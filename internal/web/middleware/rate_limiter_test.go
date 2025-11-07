package middleware

import (
	"context"
	"testing"
	"time"
)

func TestInMemoryRateLimiter_Allow(t *testing.T) {
	rateLimiter := NewInMemoryRateLimiter()
	defer rateLimiter.Close()

	ctx := context.Background()
	key := "test-key"
	limit := 3
	window := time.Second

	t.Run("allows requests within limit", func(t *testing.T) {
		// First 3 requests should be allowed
		for i := 0; i < limit; i++ {
			allowed, err := rateLimiter.Allow(ctx, key, limit, window)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !allowed {
				t.Fatalf("request %d should be allowed", i+1)
			}
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		// 4th request should be blocked
		allowed, err := rateLimiter.Allow(ctx, key, limit, window)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatal("request should be blocked")
		}
	})

	t.Run("allows requests after window expires", func(t *testing.T) {
		// Wait for window to expire
		time.Sleep(window + 100*time.Millisecond)

		// Request should be allowed again
		allowed, err := rateLimiter.Allow(ctx, key, limit, window)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("request should be allowed after window expires")
		}
	})

	t.Run("different keys are independent", func(t *testing.T) {
		key2 := "test-key-2"

		// Even if first key is rate limited, second key should work
		allowed, err := rateLimiter.Allow(ctx, key2, limit, window)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("different key should be allowed")
		}
	})
}

func TestInMemoryRateLimiter_GetRemaining(t *testing.T) {
	rateLimiter := NewInMemoryRateLimiter()
	defer rateLimiter.Close()

	ctx := context.Background()
	key := "test-key"
	limit := 5
	window := time.Second

	t.Run("returns full limit for new key", func(t *testing.T) {
		remaining, err := rateLimiter.GetRemaining(ctx, "new-key", limit, window)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if remaining != limit {
			t.Fatalf("expected %d remaining, got %d", limit, remaining)
		}
	})

	t.Run("tracks remaining requests correctly", func(t *testing.T) {
		// Use 3 requests
		for i := 0; i < 3; i++ {
			_, err := rateLimiter.Allow(ctx, key, limit, window)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		}

		remaining, err := rateLimiter.GetRemaining(ctx, key, limit, window)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := limit - 3
		if remaining != expected {
			t.Fatalf("expected %d remaining, got %d", expected, remaining)
		}
	})
}

func TestInMemoryRateLimiter_Reset(t *testing.T) {
	rateLimiter := NewInMemoryRateLimiter()
	defer rateLimiter.Close()

	ctx := context.Background()
	key := "test-key"
	limit := 2
	window := time.Second

	// Use up the limit
	for i := 0; i < limit; i++ {
		rateLimiter.Allow(ctx, key, limit, window)
	}

	// Should be blocked
	allowed, err := rateLimiter.Allow(ctx, key, limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatal("request should be blocked before reset")
	}

	// Reset the key
	err = rateLimiter.Reset(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error during reset: %v", err)
	}

	// Should be allowed again
	allowed, err = rateLimiter.Allow(ctx, key, limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatal("request should be allowed after reset")
	}
}

func TestTokenBucket_Take(t *testing.T) {
	capacity := 3
	window := time.Second

	bucket := NewTokenBucket(capacity, window)

	t.Run("allows requests within capacity", func(t *testing.T) {
		for i := 0; i < capacity; i++ {
			if !bucket.Take() {
				t.Fatalf("token %d should be available", i+1)
			}
		}
	})

	t.Run("blocks requests over capacity", func(t *testing.T) {
		if bucket.Take() {
			t.Fatal("should not have tokens available")
		}
	})

	t.Run("refills after window", func(t *testing.T) {
		// Wait for partial refill
		time.Sleep(window/2 + 10*time.Millisecond)

		// Should have some tokens available
		tokens := bucket.Tokens()
		if tokens <= 0 {
			t.Fatal("bucket should have refilled some tokens")
		}
	})
}

// Benchmark tests
func BenchmarkInMemoryRateLimiter_Allow(b *testing.B) {
	rateLimiter := NewInMemoryRateLimiter()
	defer rateLimiter.Close()

	ctx := context.Background()
	limit := 1000
	window := time.Minute

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := "bench-key"
			rateLimiter.Allow(ctx, key, limit, window)
			i++
		}
	})
}

func BenchmarkTokenBucket_Take(b *testing.B) {
	bucket := NewTokenBucket(1000, time.Minute)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bucket.Take()
		}
	})
}
