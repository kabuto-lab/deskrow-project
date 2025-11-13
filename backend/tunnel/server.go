package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"deskrow/shared/tunnel"

	"golang.org/x/crypto/curve25519"
)

type Server struct {
	config            *ServerConfig
	httpServer        *http.Server
	listener          net.Listener
	connections       map[string]*TunnelConnection
	tunnel            *tunnel.HTTP2Tunnel
	clientPublicKey   ed25519.PublicKey
	authorizedClients map[string]ed25519.PublicKey
	mu                sync.RWMutex
	connected         bool
	channels          map[tunnel.ChannelType]tunnel.Channel
	LogsSender        tunnel.LogsSender
	MetricsSender     tunnel.MetricsSender
}

type ServerConfig struct {
	Addr           string
	Port           int
	MaxConnections int
}

type TunnelConnection struct {
	ID         string
	ClientAddr string
	CreatedAt  time.Time
	LastActive time.Time
	Channels   map[tunnel.ChannelType]*tunnel.Channel
}

func NewServer() *Server {
	port, _ := strconv.Atoi(os.Getenv("TUNNEL_SERVER_PORT"))
	maxConnections, _ := strconv.Atoi(os.Getenv("TUNNEL_MAX_CONNECTIONS"))
	connectTimeout, _ := time.ParseDuration(os.Getenv("TUNNEL_CONNECT_TIMEOUT"))
	retryInterval, _ := time.ParseDuration(os.Getenv("TUNNEL_RETRY_INTERVAL"))
	maxRetries, _ := strconv.Atoi(os.Getenv("TUNNEL_MAX_RETRIES"))

	config := &ServerConfig{
		Addr:           os.Getenv("TUNNEL_SERVER_ADDR"),
		Port:           port,
		MaxConnections: maxConnections,
	}

	s := &Server{
		config:            config,
		connections:       make(map[string]*TunnelConnection),
		authorizedClients: make(map[string]ed25519.PublicKey),
		channels:          make(map[tunnel.ChannelType]tunnel.Channel),
	}

	if keys := os.Getenv("AUTHORIZED_CLIENT_KEYS"); keys != "" {
		for _, keyHex := range strings.Split(keys, ",") {
			keyHex = strings.TrimSpace(keyHex)
			if keyHex != "" {
				keyBytes, err := hex.DecodeString(keyHex)
				if err == nil {
					s.authorizedClients[keyHex] = ed25519.PublicKey(keyBytes)
				}
			}
		}
	}

	// Initialize tunnel first
	s.tunnel = tunnel.NewHTTP2Tunnel(&tunnel.Config{
		Addr:           config.Addr,
		Port:           config.Port,
		MaxRetries:     maxRetries,
		RetryInterval:  retryInterval,
		ConnectTimeout: connectTimeout,
	})

	// Get channels from tunnel
	s.channels = s.tunnel.Channels()

	// Initialize senders
	var err error
	s.LogsSender, err = tunnel.NewHTTP2LogsSender(s.tunnel)
	if err != nil {
		panic(err)
	}
	s.MetricsSender, err = tunnel.NewHTTP2MetricsSender(s.tunnel)
	if err != nil {
		panic(err)
	}

	return s
}

func (s *Server) SendLogs(data []byte) error {
	return s.LogsSender.SendLogs(data)
}

func (s *Server) SendMetrics(data []byte) error {
	return s.MetricsSender.SendMetrics(data)
}

func (s *Server) Start(ctx context.Context) error {
	s.httpServer = &http.Server{
		Addr:    net.JoinHostPort(s.config.Addr, strconv.Itoa(s.config.Port)),
		Handler: s,
	}

	var err error
	s.listener, err = net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return err
	}

	go func() {
		err := s.httpServer.Serve(s.listener)
		if err != nil && err != http.ErrServerClosed {
			s.mu.Lock()
			s.connected = false
			s.mu.Unlock()

			// Attempt reconnect if not shutting down
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(5 * time.Second)
				if err := s.Reconnect(ctx); err != nil {
					// Log reconnect failure
				}
			}
		}
	}()

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/tunnel":
		s.handleTunnel(w, r)
	case "/key-exchange":
		s.handleKeyExchange(w, r)
	case "/metrics":
		s.handleMetrics(w, r)
	case "/logs":
		s.handleLogs(w, r)
	case "/rpc":
		s.handleRPC(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify connection is authenticated
	if !s.IsConnected() {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	// Get channel type from headers
	channelType := tunnel.ChannelType(r.Header.Get("X-Channel-Type"))
	if channelType == "" {
		http.Error(w, "Channel type required", http.StatusBadRequest)
		return
	}

	// Get channel
	channel, err := s.GetChannel(channelType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Handle stream based on channel type
	switch channelType {
	case tunnel.ChannelData, tunnel.ChannelLogs, tunnel.ChannelMetrics, tunnel.ChannelRPC:
		// Upgrade to bidirectional stream
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Set headers for streaming
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		flusher.Flush()

		// Copy data between connection and channel
		go func() {
			io.Copy(channel, r.Body)
			r.Body.Close()
		}()
		io.Copy(w, channel)
	default:
		http.Error(w, "Invalid channel type", http.StatusBadRequest)
	}
}

func (s *Server) handleKeyExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// First phase - client sends public key
	if r.Header.Get("X-Key-Exchange-Phase") == "1" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		clientKeyHex := string(body)
		keyBytes, err := hex.DecodeString(clientKeyHex)
		if err != nil {
			http.Error(w, "Invalid public key encoding", http.StatusBadRequest)
			return
		}

		// Verify client is authorized
		s.mu.RLock()
		_, authorized := s.authorizedClients[clientKeyHex]
		s.mu.RUnlock()

		if !authorized {
			http.Error(w, "Unauthorized client", http.StatusUnauthorized)
			return
		}

		// Parse client's ED25519 public key
		if len(keyBytes) != ed25519.PublicKeySize {
			http.Error(w, "Invalid public key size", http.StatusBadRequest)
			return
		}
		clientPublicKey := ed25519.PublicKey(keyBytes)

		// Generate random challenge
		challenge := make([]byte, 32)
		if _, err := rand.Read(challenge); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Store challenge with client public key
		s.mu.Lock()
		s.clientPublicKey = clientPublicKey
		s.mu.Unlock()

		// Send challenge to client
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(challenge)
		return
	}

	// Second phase - client responds with signed challenge
	if r.Header.Get("X-Key-Exchange-Phase") == "2" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// Verify signed challenge
		parts := strings.SplitN(string(body), "|", 2)
		if len(parts) != 2 {
			http.Error(w, "Invalid response format", http.StatusBadRequest)
			return
		}

		signature, err := hex.DecodeString(parts[1])
		if err != nil {
			http.Error(w, "Invalid signature encoding", http.StatusBadRequest)
			return
		}

		// Verify signature using client's ED25519 public key
		if !ed25519.Verify(s.clientPublicKey, []byte(parts[0]), signature) {
			http.Error(w, "Invalid challenge signature", http.StatusUnauthorized)
			return
		}

		// Generate server's ephemeral ED25519 key pair
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			http.Error(w, "Failed to generate server key", http.StatusInternalServerError)
			return
		}

		// Initialize tunnel with config if not already done
		if s.tunnel == nil {
			s.tunnel = tunnel.NewHTTP2Tunnel(&tunnel.Config{
				Addr:           s.config.Addr,
				Port:           s.config.Port,
				MaxRetries:     3,
				RetryInterval:  time.Second * 5,
				ConnectTimeout: time.Second * 10,
			})
		}

		// Convert ED25519 private key to X25519 for ECDH
		x25519Priv := [32]byte{}
		copy(x25519Priv[:], privateKey.Seed()[:32])
		x25519Pub, err := curve25519.X25519(x25519Priv[:], curve25519.Basepoint)
		if err != nil {
			http.Error(w, "Failed to convert to X25519", http.StatusInternalServerError)
			return
		}

		// Set authentication keys
		privKey, err := ecdh.X25519().NewPrivateKey(x25519Priv[:])
		if err != nil {
			http.Error(w, "Failed to create private key", http.StatusInternalServerError)
			return
		}
		pubKey, err := ecdh.X25519().NewPublicKey(x25519Pub)
		if err != nil {
			http.Error(w, "Failed to create public key", http.StatusInternalServerError)
			return
		}
		s.tunnel.SetAuthKeys(pubKey, privKey)

		// Send success response with server public key
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(x25519Pub)
		return
	}

	http.Error(w, "Invalid key exchange phase", http.StatusBadRequest)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Implementation would go here
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	// Implementation would go here
}

func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	// Implementation would go here
}

func (s *Server) verifyECDSASignature(pubKey *ecdh.PublicKey, message, signature []byte) bool {
	// Convert ECDH public key to x25519 public key
	keyBytes := pubKey.Bytes()
	x25519PubKey, err := ecdh.X25519().NewPublicKey(keyBytes)
	if err != nil {
		return false
	}

	// Hash the message using SHA256
	hash := sha256.Sum256(message)

	// Verify the signature using x25519
	return ed25519.Verify(x25519PubKey.Bytes(), hash[:], signature)
}

// Tunnel interface implementation
func (s *Server) Connect(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.connected {
		return nil
	}

	if s.tunnel == nil {
		s.tunnel = tunnel.NewHTTP2Tunnel(&tunnel.Config{
			Addr:           s.config.Addr,
			Port:           s.config.Port,
			MaxRetries:     3,
			RetryInterval:  time.Second * 5,
			ConnectTimeout: time.Second * 10,
		})
	}

	if err := s.tunnel.Connect(ctx); err != nil {
		return err
	}

	s.connected = true
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.connected {
		return nil
	}

	if err := s.tunnel.Close(); err != nil {
		return err
	}

	s.connected = false
	return nil
}

func (s *Server) IsConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connected
}

func (s *Server) Reconnect(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tunnel == nil {
		return s.Connect(ctx)
	}

	if err := s.tunnel.Reconnect(ctx); err != nil {
		return err
	}

	s.connected = true
	return nil
}

func (s *Server) Channels() map[tunnel.ChannelType]tunnel.Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.channels
}

func (s *Server) GetChannel(channelType tunnel.ChannelType) (tunnel.Channel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	channel, ok := s.channels[channelType]
	if !ok {
		return nil, fmt.Errorf("channel type %s not found", channelType)
	}
	return channel, nil
}

func (s *Server) LocalAddr() net.Addr {
	if s.tunnel == nil {
		return nil
	}
	return s.tunnel.LocalAddr()
}

func (s *Server) RemoteAddr() net.Addr {
	if s.tunnel == nil {
		return nil
	}
	return s.tunnel.RemoteAddr()
}

func (s *Server) SetAuthKeys(publicKey *ecdh.PublicKey, privateKey *ecdh.PrivateKey) {
	if s.tunnel != nil {
		s.tunnel.SetAuthKeys(publicKey, privateKey)
	}
}
