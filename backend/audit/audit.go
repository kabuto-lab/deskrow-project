package audit

import (
	"deskrow/shared/logging"
)

// LogSender defines the function signature for sending structured logs.
type LogSender func(logging.LogMessage)

// CryptoAuditLogger defines interface for logging crypto operations
// and potentially sending them to an admin feed.
type CryptoAuditLogger interface {
	LogOperation(operation string, keyVersion int, userID *int, status string, errorMsg string) error
	SetLogSender(sender LogSender) // Method to inject the sender function
}
