package metrics

import (
	"time"
)

// SystemMetrics contains all collected system metrics
type SystemMetrics struct {
	Timestamp       time.Time `json:"timestamp"`
	CPU             float64   `json:"cpu"`               // CPU usage percentage
	Memory          float64   `json:"memory"`            // Memory usage percentage
	Goroutines      int       `json:"goroutines"`        // Number of active goroutines
	APIRequests     int       `json:"api_requests"`      // API requests in last interval
	APIResponseTime float64   `json:"api_response_time"` // Average response time in ms
	Users           struct {
		Total  int `json:"total"`  // Total users in system
		Active int `json:"active"` // Active sessions
	} `json:"users"`
	SystemHealth struct {
		OK      int    `json:"ok"`      // Number of healthy components
		Warning int    `json:"warning"` // Number of warning components
		Error   int    `json:"error"`   // Number of error components
		Status  string `json:"status"`  // Overall system status
	} `json:"system_health"`
	APIStats []APIMetric `json:"api_stats"`
}

type APIMetric struct {
	Path         string  `json:"path"`
	Count        int64   `json:"count"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

// SystemHealth represents system health status
type SystemHealth struct {
	OK      int    `json:"ok"`
	Warning int    `json:"warning"`
	Error   int    `json:"error"`
	Status  string `json:"status"`
}

// MetricsQuery defines parameters for querying historical metrics
type MetricsQuery struct {
	Start time.Time
	End   time.Time
	Limit int
}
