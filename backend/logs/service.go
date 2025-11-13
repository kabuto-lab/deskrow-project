package logs

import (
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"deskrow/shared/logging"
	"deskrow/shared/tunnel"

	_ "modernc.org/sqlite"
)

type LogService struct {
	db        *sql.DB
	tunnel    tunnel.LogsSender
	buffer    []logging.LogMessage
	bufferMu  sync.Mutex
	stopChan  chan struct{}
	batchSize int
}

func NewLogService(dataDir string, tunnel tunnel.LogsSender) (*LogService, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}

	dbPath := filepath.Join(dataDir, "logs.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	if err := createLogsTable(db); err != nil {
		return nil, err
	}

	service := &LogService{
		db:        db,
		tunnel:    tunnel,
		buffer:    make([]logging.LogMessage, 0),
		stopChan:  make(chan struct{}),
		batchSize: 1000,
	}

	// Start batch processing
	go service.processBatches()

	// Start retention cleaner
	go service.startRetentionCleaner()

	return service, nil
}

func createLogsTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS logs (
			timestamp DATETIME NOT NULL,
			type TEXT NOT NULL,
			level TEXT NOT NULL,
			message TEXT NOT NULL,
			sent BOOLEAN DEFAULT FALSE
		);
		CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
		CREATE INDEX IF NOT EXISTS idx_logs_sent ON logs(sent);
	`)
	return err
}

// LogWriter implements io.Writer interface
type LogWriter struct {
	service *LogService
	level   logging.LogLevel
}

// NewLogWriter creates a new LogWriter instance
func NewLogWriter(service *LogService, level logging.LogLevel) *LogWriter {
	return &LogWriter{
		service: service,
		level:   level,
	}
}

func (w *LogWriter) Write(p []byte) (n int, err error) {
	msg := logging.LogMessage{
		Timestamp: time.Now(),
		Level:     w.level,
		Message:   string(p),
		Fields:    make(map[string]interface{}),
	}
	if err := w.service.Log(msg); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *LogService) Log(msg logging.LogMessage) error {
	if msg.Message == "" {
		return nil
	}
	s.bufferMu.Lock()
	defer s.bufferMu.Unlock()

	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now()
	}

	s.buffer = append(s.buffer, msg)

	// Trigger flush if buffer reaches capacity
	if len(s.buffer) >= s.batchSize {
		go func() {
			if err := s.flushBuffer(false); err != nil {
				log.Printf("Error flushing logs: %v", err)
			}
		}()
	}
	return nil
}

func (s *LogService) Flush() error {
	s.bufferMu.Lock()
	defer s.bufferMu.Unlock()

	if len(s.buffer) == 0 {
		return nil
	}

	return s.flushBuffer(false)
}

func (s *LogService) SetLevel(level logging.LogLevel) {
	// Not implemented - level filtering is handled by the caller
}

func (s *LogService) WithTunnel(tunnel tunnel.LogsSender) *LogService {
	s.tunnel = tunnel
	return s
}

func (s *LogService) processBatches() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.bufferMu.Lock()
			if len(s.buffer) > 0 {
				go func() {
					if err := s.flushBuffer(false); err != nil {
						log.Printf("Error flushing logs: %v", err)
					}
				}()
			}
			s.bufferMu.Unlock()
		case <-s.stopChan:
			return
		}
	}
}

func (s *LogService) flushBuffer(onConnect bool) error {
	if s == nil {
		return nil
	}
	s.bufferMu.Lock()
	if len(s.buffer) == 0 {
		s.bufferMu.Unlock()
		return nil
	}

	// Get batch of messages
	batchSize := len(s.buffer)
	if onConnect && batchSize > s.batchSize {
		batchSize = s.batchSize
	}
	batch := make([]logging.LogMessage, batchSize)
	copy(batch, s.buffer[:batchSize])
	s.bufferMu.Unlock()

	// Try to send via tunnel first
	if s.tunnel != nil {
		data, err := json.Marshal(batch)
		if err == nil {
			if err := s.tunnel.SendLogs(data); err == nil {
				// Successfully sent - remove from buffer
				s.bufferMu.Lock()
				s.buffer = s.buffer[batchSize:]
				s.bufferMu.Unlock()
				return nil
			}
		}
	}

	// Fallback to database storage
	if err := s.storeToDatabase(batch); err != nil {
		return err
	}
	return nil
}

func (s *LogService) storeToDatabase(batch []logging.LogMessage) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		return err
	}

	for _, msg := range batch {
		_, err = tx.Exec(
			"INSERT INTO logs (timestamp, type, level, message) VALUES (?, ?, ?, ?)",
			msg.Timestamp, "log", string(msg.Level), msg.Message,
		)
		if err != nil {
			log.Printf("Failed to store log: %v", err)
			tx.Rollback()
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit logs: %v", err)
		return err
	}
	return nil
}

func (s *LogService) OnTunnelConnect() {
	// When tunnel connects, send any stored logs
	go s.sendStoredLogs()
}

func (s *LogService) sendStoredLogs() {
	for {
		batch, err := s.getStoredLogsBatch()
		if err != nil || len(batch) == 0 {
			break
		}

		data, err := json.Marshal(batch)
		if err != nil {
			log.Printf("Failed to marshal stored logs: %v", err)
			continue
		}

		if err := s.tunnel.SendLogs(data); err != nil {
			log.Printf("Failed to send stored logs: %v", err)
			break
		}

		// Mark logs as sent
		if err := s.markLogsSent(batch); err != nil {
			log.Printf("Failed to mark logs as sent: %v", err)
		}
	}
}

func (s *LogService) getStoredLogsBatch() ([]logging.LogMessage, error) {
	rows, err := s.db.Query(`
		SELECT timestamp, type, level, message 
		FROM logs 
		WHERE sent = FALSE 
		ORDER BY timestamp ASC 
		LIMIT ?`, s.batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var batch []logging.LogMessage
	for rows.Next() {
		var msg logging.LogMessage
		var levelStr string
		var msgType string
		if err := rows.Scan(&msg.Timestamp, &msgType, &levelStr, &msg.Message); err != nil {
			return nil, err
		}
		msg.Level = logging.LogLevel(levelStr)
		batch = append(batch, msg)
	}
	return batch, nil
}

func (s *LogService) markLogsSent(batch []logging.LogMessage) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}

	for _, msg := range batch {
		_, err = tx.Exec(`
			UPDATE logs 
			SET sent = TRUE 
			WHERE timestamp = ? AND type = ? AND level = ? AND message = ?`,
			msg.Timestamp, "log", string(msg.Level), msg.Message)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

func (s *LogService) Cleanup() {
	close(s.stopChan)

	// Cleanup old logs (older than 7 days)
	s.cleanupOldLogs()

	// Cleanup sent logs
	_, err := s.db.Exec("DELETE FROM logs WHERE sent = TRUE")
	if err != nil {
		log.Printf("Error cleaning up sent logs: %v", err)
	}

	s.db.Close()
}

func (s *LogService) cleanupOldLogs() {
	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)
	_, err := s.db.Exec("DELETE FROM logs WHERE timestamp < ?", sevenDaysAgo)
	if err != nil {
		log.Printf("Error cleaning up old logs: %v", err)
	}
}

func (s *LogService) startRetentionCleaner() {
	// Run cleanup immediately
	s.cleanupOldLogs()

	// Then run daily
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanupOldLogs()
		case <-s.stopChan:
			return
		}
	}
}
