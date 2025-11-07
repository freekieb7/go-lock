package middleware

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RateLimiter defines the interface for rate limiting implementations
type RateLimiter interface {
	// Allow checks if a request is allowed for the given key
	// Returns true if allowed, false if rate limit exceeded
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)

	// GetRemaining returns the number of remaining requests for the key
	GetRemaining(ctx context.Context, key string, limit int, window time.Duration) (int, error)

	// Reset clears the rate limit data for the given key
	Reset(ctx context.Context, key string) error
}

// TokenBucket represents a token bucket for rate limiting
type TokenBucket struct {
	tokens   int           // Current number of tokens
	capacity int           // Maximum number of tokens
	refillAt time.Time     // Last refill time
	window   time.Duration // Refill window
	mutex    sync.RWMutex  // Protects concurrent access
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(capacity int, window time.Duration) *TokenBucket {
	return &TokenBucket{
		tokens:   capacity,
		capacity: capacity,
		refillAt: time.Now(),
		window:   window,
	}
}

// Take attempts to take a token from the bucket
func (tb *TokenBucket) Take() bool {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	now := time.Now()

	// Calculate tokens to add based on elapsed time
	if now.After(tb.refillAt.Add(tb.window)) {
		// Full refill if enough time has passed
		tb.tokens = tb.capacity
		tb.refillAt = now
	} else {
		// Partial refill based on elapsed time
		elapsed := now.Sub(tb.refillAt)
		tokensToAdd := int(elapsed.Nanoseconds() * int64(tb.capacity) / tb.window.Nanoseconds())
		tb.tokens = min(tb.capacity, tb.tokens+tokensToAdd)

		if tokensToAdd > 0 {
			tb.refillAt = now
		}
	}

	// Take a token if available
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

// Tokens returns the current number of available tokens
func (tb *TokenBucket) Tokens() int {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()

	now := time.Now()

	// Calculate current tokens without modifying state
	if now.After(tb.refillAt.Add(tb.window)) {
		return tb.capacity
	}

	elapsed := now.Sub(tb.refillAt)
	tokensToAdd := int(elapsed.Nanoseconds() * int64(tb.capacity) / tb.window.Nanoseconds())
	return min(tb.capacity, tb.tokens+tokensToAdd)
}

// InMemoryRateLimiter implements RateLimiter using in-memory token buckets
type InMemoryRateLimiter struct {
	buckets map[string]*TokenBucket
	mutex   sync.RWMutex
	janitor *janitor // Cleanup goroutine
}

// NewInMemoryRateLimiter creates a new in-memory rate limiter
func NewInMemoryRateLimiter() *InMemoryRateLimiter {
	rl := &InMemoryRateLimiter{
		buckets: make(map[string]*TokenBucket),
	}

	// Start cleanup goroutine
	rl.janitor = &janitor{
		interval: 5 * time.Minute,
		stop:     make(chan bool),
	}

	go rl.janitor.run(rl)

	return rl
}

// Allow checks if a request is allowed for the given key
func (rl *InMemoryRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	bucketKey := fmt.Sprintf("%s:%d:%s", key, limit, window.String())

	rl.mutex.Lock()
	bucket, exists := rl.buckets[bucketKey]
	if !exists {
		bucket = NewTokenBucket(limit, window)
		rl.buckets[bucketKey] = bucket
	}
	rl.mutex.Unlock()

	return bucket.Take(), nil
}

// GetRemaining returns the number of remaining requests for the key
func (rl *InMemoryRateLimiter) GetRemaining(ctx context.Context, key string, limit int, window time.Duration) (int, error) {
	bucketKey := fmt.Sprintf("%s:%d:%s", key, limit, window.String())

	rl.mutex.RLock()
	bucket, exists := rl.buckets[bucketKey]
	rl.mutex.RUnlock()

	if !exists {
		return limit, nil // No bucket means no requests made yet
	}

	return bucket.Tokens(), nil
}

// Reset clears the rate limit data for the given key
func (rl *InMemoryRateLimiter) Reset(ctx context.Context, key string) error {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	// Remove all buckets that start with the key
	for bucketKey := range rl.buckets {
		if len(bucketKey) >= len(key) && bucketKey[:len(key)] == key {
			delete(rl.buckets, bucketKey)
		}
	}

	return nil
}

// Close stops the cleanup goroutine
func (rl *InMemoryRateLimiter) Close() error {
	if rl.janitor != nil {
		rl.janitor.stop <- true
	}
	return nil
}

// janitor runs periodic cleanup of expired buckets
type janitor struct {
	interval time.Duration
	stop     chan bool
}

// run performs periodic cleanup
func (j *janitor) run(rl *InMemoryRateLimiter) {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-j.stop:
			return
		}
	}
}

// cleanup removes old unused buckets
func (rl *InMemoryRateLimiter) cleanup() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	for key, bucket := range rl.buckets {
		bucket.mutex.RLock()
		// Remove buckets that haven't been used for more than their window duration
		if now.Sub(bucket.refillAt) > bucket.window*2 {
			delete(rl.buckets, key)
		}
		bucket.mutex.RUnlock()
	}
}

// Helper function (Go 1.21+ has this built-in)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
