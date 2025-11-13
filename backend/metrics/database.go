package metrics

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MetricsDatabase handles metrics storage and retrieval
type MetricsDatabase struct {
	db *sql.DB
}

// NewMetricsDatabase initializes the metrics database
func NewMetricsDatabase(dataDir string) (*MetricsDatabase, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create metrics directory: %w", err)
	}
	dbPath := filepath.Join(dataDir, "metrics.db")

	// Remove existing database file to ensure clean schema
	if _, err := os.Stat(dbPath); err == nil {
		if err := os.Remove(dbPath); err != nil {
			return nil, fmt.Errorf("failed to remove old database: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	if err := createMetricsTable(db); err != nil {
		return nil, err
	}

	return &MetricsDatabase{db: db}, nil
}

func createMetricsTable(db *sql.DB) error {
	// Create tables
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS system_metrics (
			timestamp DATETIME PRIMARY KEY NOT NULL,
			cpu REAL,
			memory REAL,
			goroutines INTEGER,
			api_requests INTEGER,
			api_response_time REAL,
			users_total INTEGER,
			users_active INTEGER,
			health_ok INTEGER,
			health_warning INTEGER,
			health_error INTEGER,
			health_status TEXT,
			sent BOOLEAN DEFAULT FALSE
		) WITHOUT ROWID;

		CREATE INDEX IF NOT EXISTS idx_metrics_sent ON system_metrics(sent);

		-- Initialize with timestamps for last 7 days
		INSERT OR IGNORE INTO system_metrics (timestamp)
		WITH RECURSIVE time_slots(slot) AS (
			SELECT datetime('now', '-7 days', 'start of minute')
			UNION ALL
			SELECT datetime(slot, '+30 seconds')
			FROM time_slots
			WHERE slot < datetime('now')
		)
		SELECT slot FROM time_slots
		WHERE strftime('%S', slot) IN ('00', '30');
		CREATE TABLE IF NOT EXISTS api_metrics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			metric_id INTEGER NOT NULL,
			path TEXT NOT NULL,
			count INTEGER NOT NULL,
			avg_latency_ms REAL NOT NULL,
			FOREIGN KEY(metric_id) REFERENCES system_metrics(id)
		);
		CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON system_metrics(timestamp);
		CREATE INDEX IF NOT EXISTS idx_api_metrics_metric_id ON api_metrics(metric_id);
	`)
	return err
}

// StoreMetrics saves a metrics snapshot to the database
func (d *MetricsDatabase) StoreMetrics(metrics *SystemMetrics) error {
	_, err := d.db.Exec(`
		INSERT INTO system_metrics (
			timestamp, cpu, memory, goroutines, api_requests, api_response_time,
			users_total, users_active, health_ok, health_warning, health_error, health_status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		metrics.Timestamp,
		metrics.CPU,
		metrics.Memory,
		metrics.Goroutines,
		metrics.APIRequests,
		metrics.APIResponseTime,
		metrics.Users.Total,
		metrics.Users.Active,
		metrics.SystemHealth.OK,
		metrics.SystemHealth.Warning,
		metrics.SystemHealth.Error,
		metrics.SystemHealth.Status,
	)
	return err
}

// GetMetrics retrieves metrics within a time range
func (d *MetricsDatabase) GetMetrics(query MetricsQuery) ([]SystemMetrics, error) {
	rows, err := d.db.Query(`
		SELECT 
			timestamp, cpu, memory, goroutines, api_requests, api_response_time,
			users_total, users_active, health_ok, health_warning, health_error, health_status
		FROM system_metrics
		WHERE timestamp BETWEEN ? AND ?
		ORDER BY timestamp DESC
		LIMIT ?`,
		query.Start,
		query.End,
		query.Limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []SystemMetrics
	for rows.Next() {
		var m SystemMetrics
		err := rows.Scan(
			&m.Timestamp,
			&m.CPU,
			&m.Memory,
			&m.Goroutines,
			&m.APIRequests,
			&m.APIResponseTime,
			&m.Users.Total,
			&m.Users.Active,
			&m.SystemHealth.OK,
			&m.SystemHealth.Warning,
			&m.SystemHealth.Error,
			&m.SystemHealth.Status,
		)
		if err != nil {
			return nil, err
		}
		metrics = append(metrics, m)
	}

	return metrics, nil
}

// CleanupOldMetrics removes metrics older than specified duration
func (d *MetricsDatabase) CleanupOldMetrics(retention time.Duration) error {
	_, err := d.db.Exec(
		"DELETE FROM system_metrics WHERE timestamp < ?",
		time.Now().Add(-retention),
	)
	return err
}

// GetFirstTimestamp returns the timestamp of the first metric
func (d *MetricsDatabase) GetFirstTimestamp() (time.Time, error) {
	var timestamp time.Time
	err := d.db.QueryRow(
		"SELECT timestamp FROM system_metrics ORDER BY timestamp ASC LIMIT 1",
	).Scan(&timestamp)

	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	return timestamp, err
}

// GetLastTimestamp returns the timestamp of the last metric
func (d *MetricsDatabase) GetLastTimestamp() (time.Time, error) {
	var timestamp time.Time
	err := d.db.QueryRow(
		"SELECT timestamp FROM system_metrics ORDER BY timestamp DESC LIMIT 1",
	).Scan(&timestamp)

	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	return timestamp, err
}

// StoreMetricsBatch stores multiple metrics in a single transaction
func (d *MetricsDatabase) StoreMetricsBatch(metrics []*SystemMetrics) error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Rollback if we exit with error
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	for _, m := range metrics {
		_, err = tx.Exec(`
			INSERT OR REPLACE INTO system_metrics (
				timestamp, cpu, memory, goroutines, api_requests, api_response_time,
				users_total, users_active, health_ok, health_warning, health_error, health_status, sent
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			m.Timestamp,
			m.CPU,
			m.Memory,
			m.Goroutines,
			m.APIRequests,
			m.APIResponseTime,
			m.Users.Total,
			m.Users.Active,
			m.SystemHealth.OK,
			m.SystemHealth.Warning,
			m.SystemHealth.Error,
			m.SystemHealth.Status,
			false, // Mark as not sent initially
		)
		if err != nil {
			return fmt.Errorf("failed to store metric: %w", err)
		}
	}

	return tx.Commit()
}

// MarkMetricsSent updates metrics as sent in the database
func (d *MetricsDatabase) MarkMetricsSent(timestamps []time.Time) error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Rollback if we exit with error
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	for _, ts := range timestamps {
		_, err = tx.Exec(`
			UPDATE system_metrics 
			SET sent = TRUE 
			WHERE timestamp = ?`,
			ts,
		)
		if err != nil {
			return fmt.Errorf("failed to mark metric as sent: %w", err)
		}
	}

	return tx.Commit()
}

// CleanupSentMetrics removes metrics that have been successfully sent
func (d *MetricsDatabase) CleanupSentMetrics() error {
	_, err := d.db.Exec(`
		DELETE FROM system_metrics 
		WHERE sent = TRUE`)
	return err
}

// Close closes the database connection
func (d *MetricsDatabase) Close() error {
	return d.db.Close()
}

// FillGaps identifies and fills missing metrics at :00/:30 timestamps
func (d *MetricsDatabase) FillGaps(duration time.Duration) ([]SystemMetrics, error) {
	// Default to 7 days if duration is 0
	if duration == 0 {
		duration = 7 * 24 * time.Hour
	}

	end := time.Now()
	start := end.Add(-duration)

	// Get all existing metrics in the time range
	existing, err := d.GetMetrics(MetricsQuery{
		Start: start,
		End:   end,
	})
	if err != nil {
		return nil, err
	}

	// Create map of existing timestamps for quick lookup
	existingMap := make(map[time.Time]SystemMetrics)
	for _, m := range existing {
		existingMap[m.Timestamp] = m
	}

	// Generate all expected timestamps at :00/:30 marks
	var expected []time.Time
	current := start.Truncate(time.Minute)
	if current.Before(start) {
		current = current.Add(time.Minute)
	}

	for current.Before(end) {
		// Add :00 mark
		expected = append(expected, current)
		// Add :30 mark
		expected = append(expected, current.Add(30*time.Second))
		current = current.Add(time.Minute)
	}

	// Find gaps and fill them with next non-null value
	var filled []SystemMetrics
	var lastValid *SystemMetrics

	// Iterate backwards to find next valid value efficiently
	for i := len(expected) - 1; i >= 0; i-- {
		t := expected[i]
		if m, exists := existingMap[t]; exists {
			filled = append(filled, m)
			lastValid = &m
		} else if lastValid != nil {
			// Create filled entry with last valid values
			filled = append(filled, SystemMetrics{
				Timestamp:       t,
				CPU:             lastValid.CPU,
				Memory:          lastValid.Memory,
				Goroutines:      lastValid.Goroutines,
				APIRequests:     lastValid.APIRequests,
				APIResponseTime: lastValid.APIResponseTime,
				Users:           lastValid.Users,
				SystemHealth:    lastValid.SystemHealth,
			})
		}
	}

	// Reverse to return in chronological order
	for i, j := 0, len(filled)-1; i < j; i, j = i+1, j-1 {
		filled[i], filled[j] = filled[j], filled[i]
	}

	return filled, nil
}
