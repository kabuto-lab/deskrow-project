package metrics

import (
	"encoding/json"
	"log"
	"runtime"
	"sync"
	"time"

	"deskrow/db"
	"deskrow/shared/tunnel"

	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

var (
	apiStats   = make(map[string]*APIStat)
	apiStatsMu sync.Mutex
)

type APIStat struct {
	Path        string
	Count       int64
	TotalTimeMs int64
}

func getCPUUsage() float64 {
	percent, err := cpu.Percent(time.Second, false)
	if err != nil {
		log.Printf("Error getting CPU usage: %v", err)
		// Fallback to basic CPU count if detailed metrics fail
		numCPU := runtime.NumCPU()
		if numCPU > 0 {
			return float64(numCPU) * 10 // Rough estimate
		}
		return 0
	}
	if len(percent) > 0 {
		return percent[0]
	}
	return 0
}

func getSystemHealth() SystemHealth {
	// Still using placeholder but could be enhanced with real checks
	return SystemHealth{
		OK:      8,
		Warning: 1,
		Error:   0,
		Status:  "Good",
	}
}

// MetricsService handles metrics collection and distribution
type MetricsService struct {
	clients    map[*websocket.Conn]bool
	mu         sync.Mutex
	stopChan   chan struct{}
	tunnel     tunnel.MetricsSender
	metricsDB  *MetricsDatabase
	buffer     []*SystemMetrics
	bufferSize int
	bufferMu   sync.Mutex
}

// NewMetricsService creates a new metrics service
func NewMetricsService(tunnel tunnel.MetricsSender, metricsDB *MetricsDatabase) *MetricsService {
	service := &MetricsService{
		clients:    make(map[*websocket.Conn]bool),
		stopChan:   make(chan struct{}),
		tunnel:     tunnel,
		metricsDB:  metricsDB,
		buffer:     make([]*SystemMetrics, 0),
		bufferSize: 1000, // Buffer up to 1000 metrics
	}

	// Start metrics collection
	go service.startCollection()

	return service
}

func (s *MetricsService) startCollection() {
	// Calculate time until next :00 or :30 mark
	now := time.Now()
	nextMinute := now.Truncate(time.Minute).Add(time.Minute)
	nextHalf := now.Truncate(time.Minute).Add(30 * time.Second)

	var nextTick time.Time
	if now.Before(nextHalf) {
		nextTick = nextHalf
	} else {
		nextTick = nextMinute
	}

	initialDelay := nextTick.Sub(now)
	time.Sleep(initialDelay)

	// Start ticker that fires every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Immediate first collection
	metrics := s.collectMetrics()
	s.bufferAndSendMetrics(metrics)
	s.broadcastMetrics(metrics)

	for {
		select {
		case <-ticker.C:
			metrics := s.collectMetrics()
			s.bufferAndSendMetrics(metrics)
			s.broadcastMetrics(metrics)

		case <-s.stopChan:
			return
		}
	}
}

func (s *MetricsService) bufferAndSendMetrics(metrics *SystemMetrics) {
	// Log the collected metrics payload
	payload, _ := json.Marshal(metrics)
	log.Printf("Collected metrics: %s", string(payload))

	if s.tunnel != nil {
		data, err := json.Marshal(metrics)
		if err != nil {
			log.Printf("Failed to marshal metrics: %v", err)
			s.bufferMetrics(metrics)
			return
		}
		if err := s.tunnel.SendMetrics(data); err != nil {
			log.Printf("Failed to send metrics via tunnel, buffering: %v", err)
			s.bufferMetrics(metrics)
		} else {
			// If sent successfully, check if we have buffered metrics to flush
			s.flushBuffer()
		}
	} else {
		s.bufferMetrics(metrics)
	}
}

func (s *MetricsService) bufferMetrics(metrics *SystemMetrics) {
	s.bufferMu.Lock()
	defer s.bufferMu.Unlock()

	// Add new metric to buffer
	s.buffer = append(s.buffer, metrics)
	log.Printf("Buffered metrics, current buffer size: %d", len(s.buffer))

	// Check if buffer reached capacity
	if len(s.buffer) >= s.bufferSize {
		// Store entire buffer to database in one transaction
		if s.metricsDB != nil {
			err := s.metricsDB.StoreMetricsBatch(s.buffer)
			if err != nil {
				log.Printf("Failed to store metrics batch: %v", err)
				// Keep metrics in buffer if storage failed
				return
			}
			log.Printf("Stored %d metrics to database", len(s.buffer))
		}

		// Clear buffer after successful storage
		s.buffer = make([]*SystemMetrics, 0)
	}
}

func (s *MetricsService) flushBuffer() {
	s.bufferMu.Lock()
	defer s.bufferMu.Unlock()

	if s.tunnel == nil || len(s.buffer) == 0 {
		return
	}

	// Store all buffered metrics first
	if s.metricsDB != nil {
		if err := s.metricsDB.StoreMetricsBatch(s.buffer); err != nil {
			log.Printf("Failed to store metrics batch during flush: %v", err)
			return
		}
	}

	// Collect timestamps for metrics we successfully send
	var sentTimestamps []time.Time

	// Send metrics through tunnel
	for _, metrics := range s.buffer {
		data, err := json.Marshal(metrics)
		if err != nil {
			log.Printf("Failed to marshal metrics: %v", err)
			continue
		}
		if err := s.tunnel.SendMetrics(data); err != nil {
			log.Printf("Failed to flush buffered metrics: %v", err)
			continue // Skip failed metrics but try to send others
		}
		sentTimestamps = append(sentTimestamps, metrics.Timestamp)
	}

	// Mark successfully sent metrics in database
	if len(sentTimestamps) > 0 && s.metricsDB != nil {
		if err := s.metricsDB.MarkMetricsSent(sentTimestamps); err != nil {
			log.Printf("Failed to mark metrics as sent: %v", err)
		} else {
			// Cleanup metrics that were marked as sent
			if err := s.metricsDB.CleanupSentMetrics(); err != nil {
				log.Printf("Failed to cleanup sent metrics: %v", err)
			}
		}
	}

	// Remove sent metrics from buffer
	newBuffer := make([]*SystemMetrics, 0)
	for _, m := range s.buffer {
		found := false
		for _, ts := range sentTimestamps {
			if m.Timestamp.Equal(ts) {
				found = true
				break
			}
		}
		if !found {
			newBuffer = append(newBuffer, m)
		}
	}
	s.buffer = newBuffer

	log.Printf("Flushed buffer - sent %d metrics, %d remain in buffer",
		len(sentTimestamps), len(s.buffer))
}

func (s *MetricsService) collectMetrics() *SystemMetrics {
	// Round timestamp to nearest :00 or :30 mark
	now := time.Now()
	var timestamp time.Time
	if now.Second() < 30 {
		timestamp = now.Truncate(time.Minute)
	} else {
		timestamp = now.Truncate(time.Minute).Add(30 * time.Second)
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Get system memory usage
	var memPercent float64
	vmem, err := mem.VirtualMemory()
	if err == nil {
		memPercent = vmem.UsedPercent
	} else {
		log.Printf("Error getting memory stats: %v", err)
		// Fallback to basic memory stats
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		if memStats.Sys > 0 {
			memPercent = float64(memStats.Alloc) / float64(memStats.Sys) * 100
		}
	}

	metrics := &SystemMetrics{
		Timestamp:       timestamp,
		CPU:             getCPUUsage(),
		Memory:          memPercent,
		Goroutines:      runtime.NumGoroutine(),
		APIRequests:     0,
		APIResponseTime: 0,
		APIStats:        make([]APIMetric, 0), // Initialize as empty array
	}

	// Get user stats from database
	if db.DBWrapper != nil {
		totalUsers, _ := db.DBWrapper.GetUserCount()
		activeUsers, _ := db.DBWrapper.GetActiveSessionCount()
		metrics.Users.Total = totalUsers
		metrics.Users.Active = activeUsers
	} else {
		// Default values if DB wrapper is not available
		metrics.Users.Total = 0
		metrics.Users.Active = 0
	}

	// Get system health status
	metrics.SystemHealth = getSystemHealth() // Implement this based on your checks

	// Get API stats
	apiStatsMu.Lock()
	statsCopy := make(map[string]*APIStat)
	for k, v := range apiStats {
		statsCopy[k] = &APIStat{
			Path:        v.Path,
			Count:       v.Count,
			TotalTimeMs: v.TotalTimeMs,
		}
		// Reset counters
		apiStats[k].Count = 0
		apiStats[k].TotalTimeMs = 0
	}
	apiStatsMu.Unlock()

	// Calculate API metrics
	var totalRequests int
	var totalResponseTime float64
	for _, stat := range statsCopy {
		if stat.Count > 0 {
			avgLatency := float64(stat.TotalTimeMs) / float64(stat.Count)
			metrics.APIStats = append(metrics.APIStats, APIMetric{
				Path:         stat.Path,
				Count:        stat.Count,
				AvgLatencyMs: avgLatency,
			})
			totalRequests += int(stat.Count)
			totalResponseTime += avgLatency
		}
	}

	if len(metrics.APIStats) > 0 {
		metrics.APIRequests = totalRequests
		metrics.APIResponseTime = totalResponseTime / float64(len(metrics.APIStats))
	}

	return metrics
}

func (s *MetricsService) broadcastMetrics(metrics *SystemMetrics) {
	msg := map[string]interface{}{
		"type":    "metrics",
		"payload": metrics,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Error marshaling metrics: %v", err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for client := range s.clients {
		if err := client.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("Error sending metrics to client: %v", err)
			client.Close()
			delete(s.clients, client)
		}
	}
}

func (s *MetricsService) AddClient(conn *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[conn] = true
}

func (s *MetricsService) RemoveClient(conn *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, conn)
	conn.Close()
}

// CollectSystemMetrics collects and returns current system metrics
func (s *MetricsService) CollectSystemMetrics() *SystemMetrics {
	return s.collectMetrics()
}

func (s *MetricsService) Stop() {
	close(s.stopChan)
	s.mu.Lock()
	defer s.mu.Unlock()
	for client := range s.clients {
		client.Close()
		delete(s.clients, client)
	}
}
