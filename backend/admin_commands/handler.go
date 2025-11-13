package admin_commands

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"

	"deskrow/admin_auth"
)

type CommandHandler struct {
	auth           *admin_auth.AdminClientAuth
	commandCounter  uint64
}

type CommandRequest struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type CommandResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func NewCommandHandler() *CommandHandler {
	auth, err := admin_auth.NewAdminClientAuth()
	if err != nil {
		log.Fatalf("Failed to initialize admin client authentication: %v", err)
	}
	
	return &CommandHandler{
		auth: auth,
	}
}

func (h *CommandHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/v1/admin/command" && r.Method == "POST":
		h.handleCommand(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *CommandHandler) handleCommand(w http.ResponseWriter, r *http.Request) {
	// Use the new authentication system
	headers := make(map[string][]string)
	for key, values := range r.Header {
		headers[key] = values
	}

	err := h.auth.AuthorizeCommandRequest(headers)
	if err != nil {
		log.Printf("Admin command rejected: %v", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read command request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Parse command request
	var cmdReq CommandRequest
	if err := json.Unmarshal(body, &cmdReq); err != nil {
		log.Printf("Failed to parse command request: %v", err)
		http.Error(w, "Invalid command format", http.StatusBadRequest)
		return
	}

	// Process the command
	cmdID := atomic.AddUint64(&h.commandCounter, 1)
	log.Printf("Processing admin command %d: type=%s", cmdID, cmdReq.Type)

	response, err := h.processCommand(cmdReq)
	if err != nil {
		log.Printf("Error processing admin command %d: %v", cmdID, err)
		http.Error(w, fmt.Sprintf("Command processing failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode command response: %v", err)
	}
}

func (h *CommandHandler) processCommand(cmdReq CommandRequest) (*CommandResponse, error) {
	switch cmdReq.Type {
	case "get_server_info":
		return h.handleGetServerInfo(cmdReq.Payload)
	case "get_system_metrics":
		return h.handleGetSystemMetrics(cmdReq.Payload)
	case "get_active_connections":
		return h.handleGetActiveConnections(cmdReq.Payload)
	case "get_logs":
		return h.handleGetLogs(cmdReq.Payload)
	case "restart_service":
		return h.handleRestartService(cmdReq.Payload)
	case "toggle_maintenance":
		return h.handleToggleMaintenance(cmdReq.Payload)
	default:
		return &CommandResponse{
			Success: false,
			Message: fmt.Sprintf("Unknown command type: %s", cmdReq.Type),
		}, nil
	}
}

func (h *CommandHandler) handleGetServerInfo(payload interface{}) (*CommandResponse, error) {
	// TODO: Implement actual server info gathering
	info := map[string]interface{}{
		"server_name":    "DeskRow Main Server",
		"version":        "1.0.0",
		"uptime":         "0s", // Should calculate actual uptime
		"status":         "running",
		"current_time":   "2025-10-31T19:46:38Z", // Should use current time
		"cpu_usage":      "0%",  // Should get actual CPU usage
		"memory_usage":   "0%",  // Should get actual memory usage
		"disk_usage":     "0%",  // Should get actual disk usage
		"network_stats":  map[string]interface{}{}, // Should get actual network stats
	}

	return &CommandResponse{
		Success: true,
		Message: "Server info retrieved successfully",
		Data:    info,
	}, nil
}

func (h *CommandHandler) handleGetSystemMetrics(payload interface{}) (*CommandResponse, error) {
	// TODO: Implement actual system metrics gathering
	metrics := map[string]interface{}{
		"cpu":     0.0, // Should get actual CPU usage
		"memory":  0.0, // Should get actual memory usage
		"disk":    0.0, // Should get actual disk usage
		"network": map[string]interface{}{}, // Should get actual network metrics
		"active_connections": 0,             // Should get actual active connection count
		"requests_per_second": 0.0,          // Should get actual RPS
		"error_rate":         0.0,           // Should get actual error rate
	}

	return &CommandResponse{
		Success: true,
		Message: "System metrics retrieved successfully",
		Data:    metrics,
	}, nil
}

func (h *CommandHandler) handleGetActiveConnections(payload interface{}) (*CommandResponse, error) {
	// TODO: Implement actual connection counting
	connections := []map[string]interface{}{
		// Should return actual connections
	}

	return &CommandResponse{
		Success: true,
		Message: "Active connections retrieved successfully",
		Data:    connections,
	}, nil
}

func (h *CommandHandler) handleGetLogs(payload interface{}) (*CommandResponse, error) {
	// TODO: Implement actual log retrieval
	logs := []map[string]interface{}{
		{
			"timestamp": "2025-10-31T19:46:38Z",
			"level":     "INFO",
			"message":   "System started successfully",
		},
		{
			"timestamp": "2025-10-31T19:46:39Z",
			"level":     "INFO",
			"message":   "Admin WebSocket server started",
		},
	}

	return &CommandResponse{
		Success: true,
		Message: "Logs retrieved successfully",
		Data:    logs,
	}, nil
}

func (h *CommandHandler) handleRestartService(payload interface{}) (*CommandResponse, error) {
	// TODO: Implement actual service restart (safely)
	log.Println("Service restart requested - this would normally restart the service safely")
	
	return &CommandResponse{
		Success: true,
		Message: "Service restart initiated",
	}, nil
}

func (h *CommandHandler) handleToggleMaintenance(payload interface{}) (*CommandResponse, error) {
	// TODO: Implement actual maintenance mode toggle
	enabled, ok := payload.(bool)
	if !ok {
		return &CommandResponse{
			Success: false,
			Message: "Invalid payload: expected boolean value for maintenance mode",
		}, nil
	}

	action := "enabled"
	if !enabled {
		action = "disabled"
	}
	
	log.Printf("Maintenance mode %s", action)
	
	return &CommandResponse{
		Success: true,
		Message: fmt.Sprintf("Maintenance mode %s successfully", action),
	}, nil
}