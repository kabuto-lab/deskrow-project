package tunnel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// HTTP2Tunnel implements Tunnel interface for HTTP/2
type HTTP2Tunnel struct {
	config         *Config
	client         *http.Client
	server         *http.Server
	conn           net.Conn
	channels       map[ChannelType]*HTTP2Channel
	mu             sync.RWMutex
	connected      bool
	privateKey     *ecdh.PrivateKey
	publicKey      *ecdh.PublicKey
	sessionKey     []byte
	sessionKeyTime time.Time
}

// Config holds HTTP2 tunnel configuration
type Config struct {
	Addr           string
	Port           int
	MaxRetries     int
	RetryInterval  time.Duration
	ConnectTimeout time.Duration
}

// HTTP2Channel implements Channel interface for HTTP/2
type HTTP2Channel struct {
	name      ChannelType
	stream    io.ReadWriteCloser
	readBuf   []byte
	writeBuf  []byte
	readCond  *sync.Cond
	writeCond *sync.Cond
	closed    bool
	tunnel    *HTTP2Tunnel
}

// NewHTTP2Tunnel creates a new HTTP/2 tunnel instance
func NewHTTP2Tunnel(config *Config) *HTTP2Tunnel {
	t := &HTTP2Tunnel{
		config:   config,
		channels: make(map[ChannelType]*HTTP2Channel),
	}

	// Initialize default channels
	t.channels[ChannelData] = &HTTP2Channel{
		name:      ChannelData,
		readCond:  sync.NewCond(&sync.Mutex{}),
		writeCond: sync.NewCond(&sync.Mutex{}),
	}
	t.channels[ChannelLogs] = &HTTP2Channel{
		name:      ChannelLogs,
		readCond:  sync.NewCond(&sync.Mutex{}),
		writeCond: sync.NewCond(&sync.Mutex{}),
	}
	t.channels[ChannelMetrics] = &HTTP2Channel{
		name:      ChannelMetrics,
		readCond:  sync.NewCond(&sync.Mutex{}),
		writeCond: sync.NewCond(&sync.Mutex{}),
	}
	t.channels[ChannelRPC] = &HTTP2Channel{
		name:      ChannelRPC,
		readCond:  sync.NewCond(&sync.Mutex{}),
		writeCond: sync.NewCond(&sync.Mutex{}),
	}

	return t
}

func (t *HTTP2Tunnel) Connect(ctx context.Context) error {
	// Perform key exchange and derive session key
	err := t.performKeyExchange(ctx)
	if err != nil {
		return err
	}

	// Start key rotation timer
	go t.keyRotationTimer(ctx)

	return nil
}

func (t *HTTP2Tunnel) performKeyExchange(ctx context.Context) error {
	// Generate ephemeral ECDH keys just for this session
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("ECDH key generation failed: %w", err)
	}

	// Exchange public keys with peer
	peerPublicKey, err := t.exchangePublicKeys(ctx, privateKey.PublicKey())
	if err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}

	// Compute shared secret using ephemeral ECDH keys
	sharedSecret, err := privateKey.ECDH(peerPublicKey)
	if err != nil {
		return fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive session key using HKDF
	hash := sha256.New
	hkdf := hkdf.New(hash, sharedSecret, nil, nil)
	sessionKey := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(hkdf, sessionKey); err != nil {
		return fmt.Errorf("HKDF failed: %w", err)
	}

	t.mu.Lock()
	t.sessionKey = sessionKey
	t.sessionKeyTime = time.Now()
	t.mu.Unlock()

	return nil
}

func (t *HTTP2Tunnel) exchangePublicKeys(ctx context.Context, ephemeralPubKey *ecdh.PublicKey) (*ecdh.PublicKey, error) {
	// Client sends its public key first, server responds with its public key
	if t.client != nil {
		return t.clientExchangePublicKeys(ctx, ephemeralPubKey)
	}
	return t.serverExchangePublicKeys(ctx, ephemeralPubKey)
}

func (t *HTTP2Tunnel) clientExchangePublicKeys(ctx context.Context, ephemeralPubKey *ecdh.PublicKey) (*ecdh.PublicKey, error) {
	// Send our ephemeral public key to server
	req, err := http.NewRequest("POST", "https://"+t.config.Addr+"/key-exchange", bytes.NewReader(ephemeralPubKey.Bytes()))
	if err != nil {
		return nil, err
	}

	resp, err := t.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read server's response (public key)
	peerKeyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return ecdh.P256().NewPublicKey(peerKeyBytes)
}

func (t *HTTP2Tunnel) serverExchangePublicKeys(ctx context.Context, ephemeralPubKey *ecdh.PublicKey) (*ecdh.PublicKey, error) {
	// Generate server's ephemeral key pair
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	// Store our keys
	t.mu.Lock()
	t.privateKey = privateKey
	t.publicKey = privateKey.PublicKey()
	t.mu.Unlock()

	// Compute shared secret
	sharedSecret, err := privateKey.ECDH(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive session key using HKDF
	hash := sha256.New
	hkdf := hkdf.New(hash, sharedSecret, nil, nil)
	sessionKey := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(hkdf, sessionKey); err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}

	t.mu.Lock()
	t.sessionKey = sessionKey
	t.sessionKeyTime = time.Now()
	t.connected = true
	t.mu.Unlock()

	return privateKey.PublicKey(), nil
}

func (t *HTTP2Tunnel) keyRotationTimer(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.rotateSessionKey(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (t *HTTP2Tunnel) rotateSessionKey(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Generate new ECDHE keys
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	t.privateKey = privateKey
	t.publicKey = privateKey.PublicKey()

	// Re-perform key exchange
	return t.performKeyExchange(ctx)
}

func (t *HTTP2Tunnel) Close() error {
	// Implementation would go here
	return nil
}

func (t *HTTP2Tunnel) IsConnected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connected
}

func (t *HTTP2Tunnel) Reconnect(ctx context.Context) error {
	// Implementation would go here
	return nil
}

func (t *HTTP2Tunnel) Channels() map[ChannelType]Channel {
	channels := make(map[ChannelType]Channel)
	for k, v := range t.channels {
		channels[k] = v
	}
	return channels
}

func (t *HTTP2Tunnel) GetChannel(channelType ChannelType) (Channel, error) {
	if ch, ok := t.channels[channelType]; ok {
		return ch, nil
	}
	return nil, fmt.Errorf("channel %s not found", channelType)
}

func (t *HTTP2Tunnel) LocalAddr() net.Addr {
	if t.conn != nil {
		return t.conn.LocalAddr()
	}
	return nil
}

func (t *HTTP2Tunnel) RemoteAddr() net.Addr {
	if t.conn != nil {
		return t.conn.RemoteAddr()
	}
	return nil
}

func (t *HTTP2Tunnel) SetAuthKeys(publicKey *ecdh.PublicKey, privateKey *ecdh.PrivateKey) {
	t.publicKey = publicKey
	t.privateKey = privateKey
}

// GetPublicKey returns the ECDH public key for key exchange
func (t *HTTP2Tunnel) GetPublicKey() []byte {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.publicKey == nil {
		return nil
	}
	return t.publicKey.Bytes()
}

func (t *HTTP2Tunnel) encryptWithSessionKey(data []byte) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.sessionKey == nil {
		return nil, errors.New("no session key established")
	}

	block, err := aes.NewCipher(t.sessionKey)
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

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

func (t *HTTP2Tunnel) decryptWithSessionKey(data []byte) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.sessionKey == nil {
		return nil, errors.New("no session key established")
	}

	block, err := aes.NewCipher(t.sessionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// generateECDHEKeys generates ECDHE session keys
func generateECDHEKeys() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, privateKey.PublicKey(), nil
}

// HTTP2Channel methods
func (c *HTTP2Channel) Read(p []byte) (n int, err error) {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()

	for len(c.readBuf) == 0 && !c.closed {
		c.readCond.Wait()
	}

	if c.closed {
		return 0, io.EOF
	}

	// Decrypt the data if we have a session key
	if c.tunnel != nil && c.tunnel.sessionKey != nil {
		decrypted, err := c.tunnel.decryptWithSessionKey(c.readBuf)
		if err != nil {
			return 0, fmt.Errorf("decryption failed: %w", err)
		}
		c.readBuf = decrypted
	}

	n = copy(p, c.readBuf)
	if n < len(c.readBuf) {
		c.readBuf = c.readBuf[n:]
	} else {
		c.readBuf = nil
	}
	return n, nil
}

func (c *HTTP2Channel) Write(p []byte) (n int, err error) {
	c.writeCond.L.Lock()
	defer c.writeCond.L.Unlock()

	if c.closed {
		return 0, io.ErrClosedPipe
	}

	// Encrypt the data if we have a session key
	var data []byte
	if c.tunnel != nil && c.tunnel.sessionKey != nil {
		encrypted, err := c.tunnel.encryptWithSessionKey(p)
		if err != nil {
			return 0, fmt.Errorf("encryption failed: %w", err)
		}
		data = encrypted
	} else {
		data = p
	}

	c.writeBuf = append(c.writeBuf, data...)
	c.writeCond.Signal()
	return len(p), nil
}

func (c *HTTP2Channel) Close() error {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()
	c.writeCond.L.Lock()
	defer c.writeCond.L.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	if c.stream != nil {
		c.stream.Close()
	}
	c.readCond.Broadcast()
	c.writeCond.Broadcast()
	return nil
}

func (c *HTTP2Channel) SetDeadline(t time.Time) error {
	return nil // Not implemented for HTTP2
}

func (c *HTTP2Channel) SetReadDeadline(t time.Time) error {
	return nil // Not implemented for HTTP2
}

func (c *HTTP2Channel) SetWriteDeadline(t time.Time) error {
	return nil // Not implemented for HTTP2
}
