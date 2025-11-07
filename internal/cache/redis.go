package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	apperrors "github.com/freekieb7/go-lock/internal/errors"
	"github.com/redis/go-redis/v9"
)

// Service provides caching functionality using Redis
type Service struct {
	client clientInterface
	logger *slog.Logger
	prefix string
}

// clientInterface abstracts Redis operations we actually use
type clientInterface interface {
	set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	get(ctx context.Context, key string) ([]byte, error)
	del(ctx context.Context, key string) error
	exists(ctx context.Context, key string) (bool, error)
	setNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	increment(ctx context.Context, key string, ttl time.Duration) (int64, error)
	deletePattern(ctx context.Context, pattern string) error
	ping(ctx context.Context) error
}

// Config holds Redis cache configuration
type Config struct {
	Addr         string        // Redis server address
	Password     string        // Redis password
	DB           int           // Redis database number
	PoolSize     int           // Connection pool size
	MinIdleConns int           // Minimum idle connections
	MaxRetries   int           // Maximum number of retries
	DialTimeout  time.Duration // Connection timeout
	ReadTimeout  time.Duration // Read timeout
	WriteTimeout time.Duration // Write timeout
	IdleTimeout  time.Duration // Idle connection timeout
	Prefix       string        // Key prefix for namespacing
	Enabled      bool          // Whether Redis caching is enabled
}

// DefaultConfig returns default Redis configuration
func DefaultConfig() *Config {
	return &Config{
		Addr:         "localhost:6379",
		Password:     "",
		DB:           0,
		PoolSize:     10,
		MinIdleConns: 3,
		MaxRetries:   3,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		IdleTimeout:  5 * time.Minute,
		Prefix:       "golock:",
		Enabled:      true,
	}
}

// NewService creates a new Redis cache service
func NewService(config *Config, logger *slog.Logger) (*Service, error) {
	if !config.Enabled {
		return &Service{
			client: &noOpClient{},
			logger: logger,
			prefix: config.Prefix,
		}, nil
	}

	// Create Redis client options
	opts := &redis.Options{
		Addr:         config.Addr,
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.MinIdleConns,
		MaxRetries:   config.MaxRetries,
		DialTimeout:  config.DialTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
	}

	redisClient := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		logger.Error("Failed to connect to Redis", "error", err, "addr", config.Addr)
		return nil, apperrors.CacheUnavailableError("failed to connect to Redis", err)
	}

	logger.Info("Connected to Redis cache", "addr", config.Addr, "db", config.DB)

	return &Service{
		client: &redisClientWrapper{client: redisClient},
		logger: logger,
		prefix: config.Prefix,
	}, nil
}

// buildKey creates a prefixed key
func (s *Service) buildKey(key string) string {
	return s.prefix + key
}

// Set stores a value in cache with expiration
func (s *Service) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal cache value: %w", err)
	}

	err = s.client.set(ctx, s.buildKey(key), data, ttl)
	if err != nil {
		s.logger.Warn("Cache set failed", "key", key, "error", err)
		return err
	}

	s.logger.Debug("Cache set", "key", key, "ttl", ttl)
	return nil
}

// Get retrieves a value from cache
func (s *Service) Get(ctx context.Context, key string, dest interface{}) error {
	val, err := s.client.get(ctx, s.buildKey(key))
	if err != nil {
		if err == ErrCacheMiss {
			return ErrCacheMiss
		}
		s.logger.Warn("Cache get failed", "key", key, "error", err)
		return err
	}

	err = json.Unmarshal(val, dest)
	if err != nil {
		s.logger.Warn("Cache unmarshal failed", "key", key, "error", err)
		return fmt.Errorf("failed to unmarshal cache value: %w", err)
	}

	s.logger.Debug("Cache hit", "key", key)
	return nil
}

// Delete removes a value from cache
func (s *Service) Delete(ctx context.Context, key string) error {
	err := s.client.del(ctx, s.buildKey(key))
	if err != nil {
		s.logger.Warn("Cache delete failed", "key", key, "error", err)
		return err
	}

	s.logger.Debug("Cache deleted", "key", key)
	return nil
}

// DeletePattern removes all keys matching a pattern
func (s *Service) DeletePattern(ctx context.Context, pattern string) error {
	fullPattern := s.buildKey(pattern)

	err := s.client.deletePattern(ctx, fullPattern)
	if err != nil {
		s.logger.Warn("Cache delete pattern failed", "pattern", pattern, "error", err)
		return err
	}

	s.logger.Debug("Cache pattern deleted", "pattern", pattern)
	return nil
}

// Exists checks if a key exists in cache
func (s *Service) Exists(ctx context.Context, key string) (bool, error) {
	result, err := s.client.exists(ctx, s.buildKey(key))
	if err != nil {
		s.logger.Warn("Cache exists check failed", "key", key, "error", err)
		return false, err
	}
	return result, nil
}

// SetNX sets a key only if it doesn't exist (atomic operation for locking)
func (s *Service) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("failed to marshal cache value: %w", err)
	}

	result, err := s.client.setNX(ctx, s.buildKey(key), data, ttl)
	if err != nil {
		s.logger.Warn("Cache setnx failed", "key", key, "error", err)
		return false, err
	}

	s.logger.Debug("Cache setnx", "key", key, "success", result, "ttl", ttl)
	return result, nil
}

// Increment atomically increments a counter
func (s *Service) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	result, err := s.client.increment(ctx, s.buildKey(key), ttl)
	if err != nil {
		s.logger.Warn("Cache increment failed", "key", key, "error", err)
		return 0, err
	}

	s.logger.Debug("Cache incremented", "key", key, "value", result)
	return result, nil
}

// GetOrSet tries to get a value, and if not found, sets it using the provided function
func (s *Service) GetOrSet(ctx context.Context, key string, dest interface{}, ttl time.Duration, fn func() (interface{}, error)) error {
	// Try to get from cache first
	err := s.Get(ctx, key, dest)
	if err == nil {
		return nil // Cache hit
	}

	if err != ErrCacheMiss {
		// Some other error, but continue to generate value
		s.logger.Warn("Cache error during get, generating fresh value", "key", key, "error", err)
	}

	// Cache miss or error, generate fresh value
	value, err := fn()
	if err != nil {
		return fmt.Errorf("failed to generate cache value: %w", err)
	}

	// Store in cache (fire and forget - don't block on cache errors)
	go func() {
		if setErr := s.Set(context.Background(), key, value, ttl); setErr != nil {
			s.logger.Warn("Failed to cache generated value", "key", key, "error", setErr)
		}
	}()

	// Convert result to destination
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal generated value: %w", err)
	}

	return json.Unmarshal(data, dest)
}

// Health checks the health of the cache service
func (s *Service) Health(ctx context.Context) error {
	return s.client.ping(ctx)
}

// Close closes the cache service
func (s *Service) Close() error {
	if wrapper, ok := s.client.(*redisClientWrapper); ok {
		return wrapper.close()
	}
	return nil
}

// Stats returns cache statistics
func (s *Service) Stats(ctx context.Context) (map[string]interface{}, error) {
	if wrapper, ok := s.client.(*redisClientWrapper); ok {
		return wrapper.stats(), nil
	}
	return map[string]interface{}{}, nil
}

// Cache errors
var (
	ErrCacheMiss = fmt.Errorf("cache miss")
)

// redisClientWrapper wraps redis.Client to implement our interface
type redisClientWrapper struct {
	client *redis.Client
}

func (r *redisClientWrapper) set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

func (r *redisClientWrapper) get(ctx context.Context, key string) ([]byte, error) {
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrCacheMiss
		}
		return nil, err
	}
	return []byte(val), nil
}

func (r *redisClientWrapper) del(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

func (r *redisClientWrapper) exists(ctx context.Context, key string) (bool, error) {
	result, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return result == 1, nil
}

func (r *redisClientWrapper) setNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return r.client.SetNX(ctx, key, value, ttl).Result()
}

func (r *redisClientWrapper) increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	pipeline := r.client.Pipeline()
	incrCmd := pipeline.Incr(ctx, key)
	pipeline.Expire(ctx, key, ttl)

	_, err := pipeline.Exec(ctx)
	if err != nil {
		return 0, err
	}

	return incrCmd.Val(), nil
}

func (r *redisClientWrapper) deletePattern(ctx context.Context, pattern string) error {
	keys, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		return nil
	}

	return r.client.Del(ctx, keys...).Err()
}

func (r *redisClientWrapper) ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

func (r *redisClientWrapper) close() error {
	return r.client.Close()
}

func (r *redisClientWrapper) stats() map[string]interface{} {
	poolStats := r.client.PoolStats()
	return map[string]interface{}{
		"hits":        poolStats.Hits,
		"misses":      poolStats.Misses,
		"timeouts":    poolStats.Timeouts,
		"total_conns": poolStats.TotalConns,
		"idle_conns":  poolStats.IdleConns,
		"stale_conns": poolStats.StaleConns,
	}
}

// noOpClient is a simplified no-op implementation
type noOpClient struct{}

func (n *noOpClient) set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return nil
}

func (n *noOpClient) get(ctx context.Context, key string) ([]byte, error) {
	return nil, ErrCacheMiss
}

func (n *noOpClient) del(ctx context.Context, key string) error {
	return nil
}

func (n *noOpClient) exists(ctx context.Context, key string) (bool, error) {
	return false, nil
}

func (n *noOpClient) setNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return false, nil
}

func (n *noOpClient) increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return 0, nil
}

func (n *noOpClient) deletePattern(ctx context.Context, pattern string) error {
	return nil
}

func (n *noOpClient) ping(ctx context.Context) error {
	return nil
}
