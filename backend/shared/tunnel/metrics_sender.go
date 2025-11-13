package tunnel

import (
	"encoding/json"
	"errors"
	"time"
)

// MetricsSender defines the interface for sending metrics through a tunnel
type MetricsSender interface {
	SendMetrics(data []byte) error
}

// HTTP2MetricsSender implements MetricsSender for HTTP/2 tunnel
type HTTP2MetricsSender struct {
	tunnel  Tunnel
	channel Channel
}

// NewHTTP2MetricsSender creates a new HTTP2MetricsSender instance
func NewHTTP2MetricsSender(t Tunnel) (*HTTP2MetricsSender, error) {
	channel, err := t.GetChannel(ChannelMetrics)
	if err != nil {
		return nil, err
	}

	return &HTTP2MetricsSender{
		tunnel:  t,
		channel: channel,
	}, nil
}

// SendMetrics sends metrics through the tunnel channel
func (s *HTTP2MetricsSender) SendMetrics(data []byte) error {
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
