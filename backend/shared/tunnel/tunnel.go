package tunnel

import (
	"context"
	"crypto/ecdh"
	"io"
	"net"
	"time"
)

// Tunnel defines the interface for all tunnel implementations
type Tunnel interface {
	// Connect establishes a tunnel connection
	Connect(ctx context.Context) error
	// Close terminates the tunnel connection
	Close() error
	// IsConnected returns the connection status
	IsConnected() bool
	// Reconnect attempts to re-establish connection
	Reconnect(ctx context.Context) error

	// Channels returns the available tunnel channels
	Channels() map[ChannelType]Channel
	// GetChannel returns a specific channel by type
	GetChannel(channelType ChannelType) (Channel, error)

	// LocalAddr returns the local tunnel address
	LocalAddr() net.Addr
	// RemoteAddr returns the remote tunnel address
	RemoteAddr() net.Addr

	// SetAuthKeys sets the ECDH keys for authentication and session key derivation
	SetAuthKeys(publicKey *ecdh.PublicKey, privateKey *ecdh.PrivateKey)
}

// Channel represents a tunnel communication channel
type Channel interface {
	io.ReadWriteCloser
	// SetDeadline sets read/write deadlines
	SetDeadline(t time.Time) error
	// SetReadDeadline sets read deadline
	SetReadDeadline(t time.Time) error
	// SetWriteDeadline sets write deadline
	SetWriteDeadline(t time.Time) error
}

// ChannelType defines the type of tunnel channel
type ChannelType string

const (
	ChannelData    ChannelType = "data"
	ChannelLogs    ChannelType = "logs"
	ChannelMetrics ChannelType = "metrics"
	ChannelRPC     ChannelType = "rpc"
)
