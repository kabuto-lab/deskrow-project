package admin_ws_tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"deskrow/admin_auth"
	"deskrow/shared/tunnel"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/hkdf"
)

type AdminWSTunnelServer struct {
	upgrader         websocket.Upgrader
	connections      map[string]*WSTunnelConnection
	mu               sync.RWMutex
	auth             *admin_auth.AdminClientAuth
	privateKey       *ecdh.PrivateKey
	publicKey        *ecdh.PublicKey
	sessionKey       []byte
	sessionKeyTime   time.Time
	connected        bool
	logsChannel      chan<- []byte
	metricsChannel   chan<- []byte
}

// Ensure AdminWSTunnelServer implements tunnel.LogsSender and tunnel.MetricsSender interfaces
var _ tunnel.LogsSender = (*AdminWSTunnelServer)(nil)
var _ tunnel.MetricsSender = (*AdminWSTunnelServer)(nil)

type WSTunnelConnection struct {
	conn     *websocket.Conn
	clientID string
	addr     string
}

func NewAdminWSTunnelServer(logsChannel chan<- []byte, metricsChannel chan<- []byte) *AdminWSTunnelServer {
	auth, err := admin_auth.NewAdminClientAuth()
	if err != nil {
		log.Fatalf("Failed to initialize admin client authentication: %v", err)
	}
	
	return &AdminWSTunnelServer{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				// Allow connections from any origin for the admin tunnel
				return true
			},
		},
		connections:    make(map[string]*WSTunnelConnection),
		auth:           auth,
		logsChannel:    logsChannel,
		metricsChannel: metricsChannel,
	}
}

func (s *AdminWSTunnelServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ws/admin-feed":
		s.handleAdminFeedWebSocket(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *AdminWSTunnelServer) handleAdminFeedWebSocket(w http.ResponseWriter, r *http.Request) {
	// Use the new authentication system
	queryParams := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			queryParams[key] = values[0]
		}
	}

	headers := make(map[string][]string)
	for key, values := range r.Header {
		headers[key] = values
	}

	err := s.auth.AuthorizeWSConnection(queryParams, headers)
	if err != nil {
		log.Printf("Admin WebSocket connection rejected: %v", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// Generate a unique client ID
	clientID := generateClientID()
	addr := r.RemoteAddr

	wsConn := &WSTunnelConnection{
		conn:     conn,
		clientID: clientID,
		addr:     addr,
	}

	// Add to connections
	s.mu.Lock()
	s.connections[clientID] = wsConn
	s.connected = true
	s.mu.Unlock()

	log.Printf("Admin WebSocket connected: clientID=%s, addr=%s", clientID, addr)

	// Set up ping/pong handlers
	conn.SetPingHandler(func(appData string) error {
		err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(5*time.Second))
		if err != nil {
			log.Printf("Failed to send pong: %v", err)
		}
		return err
	})

	// Start reading loop
	s.readLoop(conn, clientID)

	// Remove from connections
	s.mu.Lock()
	delete(s.connections, clientID)
	if len(s.connections) == 0 {
		s.connected = false
	}
	s.mu.Unlock()

	log.Printf("Admin WebSocket disconnected: clientID=%s", clientID)
}

func (s *AdminWSTunnelServer) readLoop(conn *websocket.Conn, clientID string) {
	conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-heartbeatTicker.C:
			// Send ping
			if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(5*time.Second)); err != nil {
				log.Printf("Failed to send ping to client %s: %v", clientID, err)
				return
			}
		default:
			conn.SetReadDeadline(time.Now().Add(90 * time.Second))
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("WebSocket error for client %s: %v", clientID, err)
				}
				return
			}

			if messageType == websocket.TextMessage || messageType == websocket.BinaryMessage {
				// Process the message - decrypt if needed
				var msg map[string]interface{}
				if err := json.Unmarshal(message, &msg); err == nil {
					if msgType, ok := msg["type"].(string); ok {
						switch msgType {
						case "logs":
							if s.logsChannel != nil {
								payload, exists := msg["payload"]
								if exists {
									jsonPayload, _ := json.Marshal(payload)
									s.logsChannel <- jsonPayload
								}
							}
						case "metrics":
							if s.metricsChannel != nil {
								payload, exists := msg["payload"]
								if exists {
									jsonPayload, _ := json.Marshal(payload)
									s.metricsChannel <- jsonPayload
								}
							}
						case "request_historical":
							// Handle historical metrics request
							s.handleHistoricalMetricsRequest(conn, msg)
						default:
							// Forward other message types to logs channel as generic events
							if s.logsChannel != nil {
								s.logsChannel <- message
							}
						}
					}
				}
			}
		}
	}
}

func (s *AdminWSTunnelServer) handleHistoricalMetricsRequest(conn *websocket.Conn, msg map[string]interface{}) {
	// TODO: Implement historical metrics request handling
	// For now, send empty response
	response := map[string]interface{}{
		"type":    "historical_metrics",
		"payload": []interface{}{},
	}
	if err := conn.WriteJSON(response); err != nil {
		log.Printf("Error sending historical metrics response: %v", err)
	}
}

func (s *AdminWSTunnelServer) IsConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connected
}

func (s *AdminWSTunnelServer) BroadcastToAdminFeed(message interface{}) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var jsonMessage []byte
	var err error

	if msgBytes, ok := message.([]byte); ok {
		jsonMessage = msgBytes
	} else {
		jsonMessage, err = json.Marshal(message)
		if err != nil {
			return fmt.Errorf("failed to marshal message: %w", err)
		}
	}

	// Forward to all connected admin clients
	for clientID, wsConn := range s.connections {
		if err := wsConn.conn.WriteMessage(websocket.TextMessage, jsonMessage); err != nil {
			log.Printf("Failed to send message to admin client %s: %v", clientID, err)
			// Don't return error, continue with other connections
		}
	}

	return nil
}

func (s *AdminWSTunnelServer) encryptWithSessionKey(data []byte) ([]byte, error) {
	s.mu.RLock()
	sessionKey := s.sessionKey
	s.mu.RUnlock()

	if sessionKey == nil {
		return nil, fmt.Errorf("no session key established")
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (s *AdminWSTunnelServer) decryptWithSessionKey(data []byte) ([]byte, error) {
	s.mu.RLock()
	sessionKey := s.sessionKey
	s.mu.RUnlock()

	if sessionKey == nil {
		return nil, fmt.Errorf("no session key established")
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func generateClientID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp if crypto/rand fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// SendLogs implements the tunnel.LogsSender interface
func (s *AdminWSTunnelServer) SendLogs(data []byte) error {
	if !s.IsConnected() {
		return fmt.Errorf("admin WebSocket tunnel not connected")
	}

	logMessage := map[string]interface{}{
		"type":    "logs",
		"payload": json.RawMessage(data),
		"timestamp": time.Now().Unix(),
	}

	return s.BroadcastToAdminFeed(logMessage)
}

// SendMetrics implements the tunnel.MetricsSender interface
func (s *AdminWSTunnelServer) SendMetrics(data []byte) error {
	if !s.IsConnected() {
		return fmt.Errorf("admin WebSocket tunnel not connected")
	}

	metricsMessage := map[string]interface{}{
		"type":    "metrics",
		"payload": json.RawMessage(data),
		"timestamp": time.Now().Unix(),
	}

	return s.BroadcastToAdminFeed(metricsMessage)
}

// InitializeECDHKeys generates ECDH key pair for encryption
func (s *AdminWSTunnelServer) InitializeECDHKeys() error {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDH private key: %w", err)
	}

	publicKey := privateKey.PublicKey()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.privateKey = privateKey
	s.publicKey = publicKey

	return nil
}

// GetPublicKey returns the ECDH public key for key exchange
func (s *AdminWSTunnelServer) GetPublicKey() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.publicKey == nil {
		return nil
	}
	return s.publicKey.Bytes()
}

// DeriveSessionKey derives a session key using ECDH with peer public key
func (s *AdminWSTunnelServer) DeriveSessionKey(peerPublicKeyBytes []byte) error {
	peerPublicKey, err := ecdh.X25519().NewPublicKey(peerPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to create peer public key: %w", err)
	}

	sharedSecret, err := s.privateKey.ECDH(peerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive session key using HKDF
	hash := sha256.New
	hkdf := hkdf.New(hash, sharedSecret, nil, nil)
	sessionKey := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(hkdf, sessionKey); err != nil {
		return fmt.Errorf("failed to derive session key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionKey = sessionKey
	s.sessionKeyTime = time.Now()

	return nil
}