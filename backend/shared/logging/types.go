package logging

import (
	"deskrow/shared/tunnel"
	"time"
)

// LogLevel represents the severity level of a log message
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
	LevelFatal LogLevel = "fatal"
)

// LogMessage represents a structured log message
type LogMessage struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      string                 `json:"type,omitempty"`
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// ChannelType defines logging-specific channel types
const (
	ChannelLogs = tunnel.ChannelLogs
)
