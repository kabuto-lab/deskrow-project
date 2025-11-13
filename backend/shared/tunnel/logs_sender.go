package tunnel

import (
	"encoding/json"
	"errors"
	"time"
)

// LogsSender defines the interface for sending logs through a tunnel
type LogsSender interface {
	SendLogs(data []byte) error
}

// HTTP2LogsSender implements LogsSender for HTTP/2 tunnel
type HTTP2LogsSender struct {
	tunnel  Tunnel
	channel Channel
}

// NewHTTP2LogsSender creates a new HTTP2LogsSender instance
func NewHTTP2LogsSender(t Tunnel) (*HTTP2LogsSender, error) {
	channel, err := t.GetChannel(ChannelLogs)
	if err != nil {
		return nil, err
	}

	return &HTTP2LogsSender{
		tunnel:  t,
		channel: channel,
	}, nil
}

// SendLogs sends logs through the tunnel channel
func (s *HTTP2LogsSender) SendLogs(data []byte) error {
	if !s.tunnel.IsConnected() {
		return errors.New("tunnel not connected")
	}

	// Add timestamp and metadata
	payload := struct {
		Timestamp time.Time `json:"timestamp"`
		Data      []byte    `json:"data"`
	}{
		Timestamp: time.Now(),
		Data:      data,
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = s.channel.Write(encoded)
	return err
}
