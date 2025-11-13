package db

import (
	"database/sql"
	"deskrow/shared/logging"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

type LogsDatabase struct {
	db       *sql.DB
	stopChan chan struct{}
}

func NewLogsDatabase(dbPath string) (*LogsDatabase, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	if err := createLogsTable(db); err != nil {
		return nil, err
	}

	ldb := &LogsDatabase{
		db:       db,
		stopChan: make(chan struct{}),
	}

	// Start retention cleaner
	go ldb.startRetentionCleaner()

	return ldb, nil
}

func createLogsTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS admin_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL,
			type TEXT NOT NULL,
			level TEXT NOT NULL,
			message TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON admin_logs(timestamp);
		CREATE INDEX IF NOT EXISTS idx_logs_type ON admin_logs(type);
		CREATE INDEX IF NOT EXISTS idx_logs_level ON admin_logs(level);
	`)
	return err
}

func (ldb *LogsDatabase) AddLog(logType, level, message string) error {
	_, err := ldb.db.Exec(
		"INSERT INTO admin_logs (timestamp, type, level, message) VALUES (?, ?, ?, ?)",
		time.Now().UTC(), logType, level, message,
	)
	return err
}

func (ldb *LogsDatabase) GetLogsByCriteria(start, end time.Time, logType, level string) ([]logging.LogMessage, error) {
	query := "SELECT id, timestamp, type, level, message FROM admin_logs WHERE 1=1"
	args := []interface{}{}

	if !start.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, start)
	}
	if !end.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, end)
	}
	if logType != "" {
		query += " AND type = ?"
		args = append(args, logType)
	}
	if level != "" {
		query += " AND level = ?"
		args = append(args, level)
	}

	query += " ORDER BY timestamp DESC"

	rows, err := ldb.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []logging.LogMessage
	for rows.Next() {
		var l logging.LogMessage
		if err := rows.Scan(&l.ID, &l.Timestamp, &l.Type, &l.Level, &l.Message); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}

	return logs, nil
}

func (ldb *LogsDatabase) Close() error {
	close(ldb.stopChan)
	// Cleanup old logs before closing
	ldb.cleanupOldLogs()
	return ldb.db.Close()
}

func (ldb *LogsDatabase) cleanupOldLogs() {
	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)
	_, err := ldb.db.Exec("DELETE FROM admin_logs WHERE timestamp < ?", sevenDaysAgo)
	if err != nil {
		log.Printf("Error cleaning up old admin logs: %v", err)
	}
}

func (ldb *LogsDatabase) startRetentionCleaner() {
	// Run cleanup immediately
	ldb.cleanupOldLogs()

	// Then run daily
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ldb.cleanupOldLogs()
		case <-ldb.stopChan:
			return
		}
	}
}
