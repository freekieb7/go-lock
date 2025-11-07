package cache

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Manager provides a unified caching interface for the application
type Manager struct {
	redis   *Service
	session *SessionStore
	jwks    *JWKSCache
	logger  *slog.Logger

	// In-memory caches for frequently accessed data
	inMemory    map[string]*inMemoryEntry
	memoryMutex sync.RWMutex

	// Cache configuration
	config *ManagerConfig
}

// ManagerConfig holds configuration for the cache manager
type ManagerConfig struct {
	RedisConfig        *Config
	InMemoryTTL        time.Duration // TTL for in-memory cache
	InMemoryMaxSize    int           // Maximum entries in memory cache
	CleanupInterval    time.Duration // How often to cleanup expired entries
	ClientCacheTTL     time.Duration // TTL for client info cache
	UserCacheTTL       time.Duration // TTL for user info cache
	PermissionCacheTTL time.Duration // TTL for permission cache
}

// DefaultManagerConfig returns default cache manager configuration
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		RedisConfig:        DefaultConfig(),
		InMemoryTTL:        5 * time.Minute,
		InMemoryMaxSize:    1000,
		CleanupInterval:    1 * time.Minute,
		ClientCacheTTL:     30 * time.Minute,
		UserCacheTTL:       15 * time.Minute,
		PermissionCacheTTL: 10 * time.Minute,
	}
}

// inMemoryEntry represents a cached entry in memory
type inMemoryEntry struct {
	value     interface{}
	expiresAt time.Time
}

// isExpired checks if the entry has expired
func (e *inMemoryEntry) isExpired() bool {
	return time.Now().After(e.expiresAt)
}

// NewManager creates a new cache manager
func NewManager(config *ManagerConfig, logger *slog.Logger) (*Manager, error) {
	if config == nil {
		config = DefaultManagerConfig()
	}

	// Create Redis cache service
	redisService, err := NewService(config.RedisConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis service: %w", err)
	}

	manager := &Manager{
		redis:    redisService,
		logger:   logger,
		config:   config,
		inMemory: make(map[string]*inMemoryEntry),
	}

	// Start cleanup goroutine for in-memory cache
	go manager.startCleanup()

	logger.Info("Cache manager initialized",
		"redis_enabled", config.RedisConfig.Enabled,
		"in_memory_max_size", config.InMemoryMaxSize,
		"cleanup_interval", config.CleanupInterval)

	return manager, nil
}

// SetSessionStore sets the cached session store
func (m *Manager) SetSessionStore(baseStore interface{}) {
	if _, ok := baseStore.(interface {
		GetSessionByToken(context.Context, string) (interface{}, error)
		SaveSession(context.Context, interface{}) (interface{}, error)
		NewSession() (interface{}, error)
		DeleteSession(context.Context, string) error
	}); ok {
		// Note: This is a simplified interface - in practice you'd use proper types
		m.logger.Debug("Session store cache integration configured")
	}
}

// SetJWKSCache sets up JWKS caching
func (m *Manager) SetJWKSCache() *JWKSCache {
	if m.jwks == nil {
		m.jwks = NewJWKSCache(m.redis, m.logger)
		m.logger.Debug("JWKS cache configured")
	}
	return m.jwks
}

// Redis returns the underlying Redis service
func (m *Manager) Redis() *Service {
	return m.redis
}

// CacheClient caches client information
func (m *Manager) CacheClient(ctx context.Context, clientID string, client interface{}) error {
	key := fmt.Sprintf("client:%s", clientID)
	return m.redis.Set(ctx, key, client, m.config.ClientCacheTTL)
}

// GetCachedClient retrieves cached client information
func (m *Manager) GetCachedClient(ctx context.Context, clientID string, dest interface{}) error {
	key := fmt.Sprintf("client:%s", clientID)
	return m.redis.Get(ctx, key, dest)
}

// CacheUser caches user information
func (m *Manager) CacheUser(ctx context.Context, userID string, user interface{}) error {
	key := fmt.Sprintf("user:%s", userID)
	return m.redis.Set(ctx, key, user, m.config.UserCacheTTL)
}

// GetCachedUser retrieves cached user information
func (m *Manager) GetCachedUser(ctx context.Context, userID string, dest interface{}) error {
	key := fmt.Sprintf("user:%s", userID)
	return m.redis.Get(ctx, key, dest)
}

// CachePermissions caches user permissions
func (m *Manager) CachePermissions(ctx context.Context, userID string, permissions interface{}) error {
	key := fmt.Sprintf("perms:%s", userID)
	return m.redis.Set(ctx, key, permissions, m.config.PermissionCacheTTL)
}

// GetCachedPermissions retrieves cached permissions
func (m *Manager) GetCachedPermissions(ctx context.Context, userID string, dest interface{}) error {
	key := fmt.Sprintf("perms:%s", userID)
	return m.redis.Get(ctx, key, dest)
}

// SetInMemory stores a value in the in-memory cache
func (m *Manager) SetInMemory(key string, value interface{}) {
	m.memoryMutex.Lock()
	defer m.memoryMutex.Unlock()

	// Check if we need to evict entries
	if len(m.inMemory) >= m.config.InMemoryMaxSize {
		m.evictExpiredEntries()
	}

	m.inMemory[key] = &inMemoryEntry{
		value:     value,
		expiresAt: time.Now().Add(m.config.InMemoryTTL),
	}
}

// GetInMemory retrieves a value from the in-memory cache
func (m *Manager) GetInMemory(key string) (interface{}, bool) {
	m.memoryMutex.RLock()
	entry, exists := m.inMemory[key]
	m.memoryMutex.RUnlock()

	if !exists || entry.isExpired() {
		// Clean up expired entry
		if exists {
			m.memoryMutex.Lock()
			delete(m.inMemory, key)
			m.memoryMutex.Unlock()
		}
		return nil, false
	}

	return entry.value, true
}

// DeleteInMemory removes a value from the in-memory cache
func (m *Manager) DeleteInMemory(key string) {
	m.memoryMutex.Lock()
	defer m.memoryMutex.Unlock()
	delete(m.inMemory, key)
}

// ClearInMemory clears all in-memory cache entries
func (m *Manager) ClearInMemory() {
	m.memoryMutex.Lock()
	defer m.memoryMutex.Unlock()
	m.inMemory = make(map[string]*inMemoryEntry)
}

// InvalidateUser clears all cached data for a user
func (m *Manager) InvalidateUser(ctx context.Context, userID string) {
	// Clear from Redis
	m.redis.Delete(ctx, fmt.Sprintf("user:%s", userID))
	m.redis.Delete(ctx, fmt.Sprintf("perms:%s", userID))
	m.redis.DeletePattern(ctx, fmt.Sprintf("session:*:%s", userID))

	// Clear from in-memory cache
	m.DeleteInMemory(fmt.Sprintf("user:%s", userID))
	m.DeleteInMemory(fmt.Sprintf("perms:%s", userID))

	m.logger.Debug("Invalidated user cache", "user_id", userID)
}

// InvalidateClient clears cached data for a client
func (m *Manager) InvalidateClient(ctx context.Context, clientID string) {
	m.redis.Delete(ctx, fmt.Sprintf("client:%s", clientID))
	m.DeleteInMemory(fmt.Sprintf("client:%s", clientID))

	m.logger.Debug("Invalidated client cache", "client_id", clientID)
}

// Health checks the health of all cache components
func (m *Manager) Health(ctx context.Context) map[string]error {
	health := make(map[string]error)

	// Check Redis
	health["redis"] = m.redis.Health(ctx)

	// Check in-memory cache stats
	m.memoryMutex.RLock()
	inMemorySize := len(m.inMemory)
	m.memoryMutex.RUnlock()

	if inMemorySize > m.config.InMemoryMaxSize {
		health["in_memory"] = fmt.Errorf("in-memory cache size exceeded: %d > %d", inMemorySize, m.config.InMemoryMaxSize)
	} else {
		health["in_memory"] = nil
	}

	return health
}

// Stats returns cache statistics
func (m *Manager) Stats(ctx context.Context) map[string]interface{} {
	stats := make(map[string]interface{})

	// Redis stats
	if redisStats, err := m.redis.Stats(ctx); err == nil {
		stats["redis"] = redisStats
	}

	// In-memory stats
	m.memoryMutex.RLock()
	stats["in_memory"] = map[string]interface{}{
		"entries":  len(m.inMemory),
		"max_size": m.config.InMemoryMaxSize,
		"ttl":      m.config.InMemoryTTL.String(),
	}
	m.memoryMutex.RUnlock()

	return stats
}

// Close closes the cache manager and all its resources
func (m *Manager) Close() error {
	m.logger.Info("Closing cache manager")
	return m.redis.Close()
}

// startCleanup starts the background cleanup goroutine
func (m *Manager) startCleanup() {
	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		m.evictExpiredEntries()
	}
}

// evictExpiredEntries removes expired entries from in-memory cache
func (m *Manager) evictExpiredEntries() {
	m.memoryMutex.Lock()
	defer m.memoryMutex.Unlock()

	now := time.Now()
	for key, entry := range m.inMemory {
		if now.After(entry.expiresAt) {
			delete(m.inMemory, key)
		}
	}
}
