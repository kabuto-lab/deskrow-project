package rate

import (
	"strings"
	"sync"
	"time"
)

type Limiter struct {
	store  Store
	Config Config
}

type Config struct {
	MaxAttempts         int
	WindowSize          time.Duration
	IPBanDuration       time.Duration
	UsernameBanDuration time.Duration
}

type Store interface {
	Increment(key string, window time.Duration) (int, error)
	Get(key string) (int, error)
	Block(key string, duration time.Duration) error
	IsBlocked(key string) (bool, error)
}

type MemoryStore struct {
	counters map[string]*counter
	blocks   map[string]time.Time
	mu       sync.RWMutex
	stop     chan struct{}
}

type counter struct {
	value     int
	expiresAt time.Time
}

func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		counters: make(map[string]*counter),
		blocks:   make(map[string]time.Time),
		stop:     make(chan struct{}),
	}
	go store.cleanup()
	return store
}

func (ms *MemoryStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ms.mu.Lock()
			now := time.Now()
			for k, c := range ms.counters {
				if now.After(c.expiresAt) {
					delete(ms.counters, k)
				}
			}
			for k, blockUntil := range ms.blocks {
				if now.After(blockUntil) {
					delete(ms.blocks, k)
				}
			}
			ms.mu.Unlock()
		case <-ms.stop:
			return
		}
	}
}

func (ms *MemoryStore) Close() {
	close(ms.stop)
}

func (ms *MemoryStore) Increment(key string, window time.Duration) (int, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	now := time.Now()
	c, exists := ms.counters[key]
	if !exists || now.After(c.expiresAt) {
		c = &counter{
			value:     1,
			expiresAt: now.Add(window),
		}
		ms.counters[key] = c
		return 1, nil
	}

	c.value++
	return c.value, nil
}

func (ms *MemoryStore) Get(key string) (int, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	c, exists := ms.counters[key]
	if !exists || time.Now().After(c.expiresAt) {
		return 0, nil
	}
	return c.value, nil
}

func (ms *MemoryStore) Block(key string, duration time.Duration) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.blocks[key] = time.Now().Add(duration)
	return nil
}

func (ms *MemoryStore) IsBlocked(key string) (bool, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	blockUntil, exists := ms.blocks[key]
	if !exists {
		return false, nil
	}
	return time.Now().Before(blockUntil), nil
}

func NewLimiter(config Config) *Limiter {
	return &Limiter{
		store:  NewMemoryStore(),
		Config: config,
	}
}

func (l *Limiter) IsBlocked(key string) (bool, error) {
	return l.store.IsBlocked(key)
}

func (l *Limiter) Increment(key string) (int, error) {
	count, err := l.store.Increment(key, l.Config.WindowSize)
	if err != nil {
		return 0, err
	}

	if count >= l.Config.MaxAttempts {
		err = l.Block(key)
		if err != nil {
			return count, err
		}
	}
	return count, nil
}

func (l *Limiter) Block(key string) error {
	var duration time.Duration
	if strings.HasPrefix(key, "ip:") {
		duration = l.Config.IPBanDuration
	} else {
		duration = l.Config.UsernameBanDuration
	}
	return l.store.Block(key, duration)
}
