package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/freekieb7/go-lock/internal/web/response"
)

func TestRateLimitMiddleware_Integration(t *testing.T) {
	// Create a simple handler that responds with OK
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response.JSONResponse(w, http.StatusOK, response.APIResponse{
			Code:    http.StatusOK,
			Message: "success",
			Status:  "SUCCESS",
		})
	})

	// Setup rate limiter
	rateLimiter := NewInMemoryRateLimiter()
	defer rateLimiter.Close()

	limit := RateLimit{
		Requests: 2,
		Window:   time.Second,
		KeyFunc:  KeyByIP,
	}

	// Wrap handler with rate limiting middleware
	rateLimitedHandler := RateLimitMiddleware(rateLimiter, limit)(handler)

	t.Run("allows requests within limit", func(t *testing.T) {
		for i := 0; i < limit.Requests; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345" // Simulate same IP

			rr := httptest.NewRecorder()
			rateLimitedHandler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("request %d: expected status %d, got %d", i+1, http.StatusOK, rr.Code)
			}

			// Check rate limiting headers
			if rr.Header().Get("X-RateLimit-Limit") != "2" {
				t.Fatalf("expected X-RateLimit-Limit header to be '2', got '%s'", rr.Header().Get("X-RateLimit-Limit"))
			}
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345" // Same IP as above

		rr := httptest.NewRecorder()
		rateLimitedHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("expected status %d, got %d", http.StatusTooManyRequests, rr.Code)
		}

		// Check that rate limiting headers are still present
		if rr.Header().Get("X-RateLimit-Remaining") != "0" {
			t.Fatalf("expected X-RateLimit-Remaining header to be '0', got '%s'", rr.Header().Get("X-RateLimit-Remaining"))
		}
	})

	t.Run("different IPs are treated independently", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.2:12345" // Different IP

		rr := httptest.NewRecorder()
		rateLimitedHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})
}

func TestRateLimitMiddleware_KeyFunctions(t *testing.T) {
	rateLimiter := NewInMemoryRateLimiter()
	defer rateLimiter.Close()

	t.Run("KeyByIP function", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.100:8080"

		key := KeyByIP(req)
		expected := "192.168.1.100"
		if key != expected {
			t.Fatalf("expected key '%s', got '%s'", expected, key)
		}
	})

	t.Run("KeyByAPIKey function", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		req.RemoteAddr = "192.168.1.100:8080"

		key := KeyByAPIKey(req)
		expected := "api_key:test-api-key"
		if key != expected {
			t.Fatalf("expected key '%s', got '%s'", expected, key)
		}
	})

	t.Run("KeyByAPIKey fallback to IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.100:8080"
		// No API key header

		key := KeyByAPIKey(req)
		expected := "192.168.1.100"
		if key != expected {
			t.Fatalf("expected fallback key '%s', got '%s'", expected, key)
		}
	})

	t.Run("KeyByUserAgent function", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("User-Agent", "TestAgent/1.0")

		key := KeyByUserAgent(req)
		expected := "TestAgent/1.0"
		if key != expected {
			t.Fatalf("expected key '%s', got '%s'", expected, key)
		}
	})
}

func TestMultiRateLimitMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimiter := NewInMemoryRateLimiter()
	defer rateLimiter.Close()

	// Create multiple rate limits - one very restrictive
	limits := []RateLimit{
		{
			Requests: 1, // Very restrictive
			Window:   time.Second,
			KeyFunc:  KeyByIP,
		},
		{
			Requests: 10, // More permissive
			Window:   time.Second,
			KeyFunc:  KeyByUserAgent,
		},
	}

	multiLimitHandler := MultiRateLimitMiddleware(rateLimiter, limits...)(handler)

	t.Run("first limit blocks when exceeded", func(t *testing.T) {
		req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
		req1.RemoteAddr = "192.168.1.1:8080"
		req1.Header.Set("User-Agent", "TestAgent/1.0")

		// First request should pass
		rr1 := httptest.NewRecorder()
		multiLimitHandler.ServeHTTP(rr1, req1)
		if rr1.Code != http.StatusOK {
			t.Fatalf("first request should pass, got status %d", rr1.Code)
		}

		// Second request should be blocked by the first (IP-based) limit
		req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
		req2.RemoteAddr = "192.168.1.1:8080" // Same IP
		req2.Header.Set("User-Agent", "TestAgent/1.0")

		rr2 := httptest.NewRecorder()
		multiLimitHandler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusTooManyRequests {
			t.Fatalf("second request should be blocked, got status %d", rr2.Code)
		}
	})
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expectedIP string
	}{
		{
			name:       "X-Forwarded-For single IP",
			remoteAddr: "10.0.0.1:8080",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1",
			},
			expectedIP: "192.168.1.1",
		},
		{
			name:       "X-Forwarded-For multiple IPs",
			remoteAddr: "10.0.0.1:8080",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1, 10.0.0.2, 172.16.0.1",
			},
			expectedIP: "192.168.1.1",
		},
		{
			name:       "X-Real-IP header",
			remoteAddr: "10.0.0.1:8080",
			headers: map[string]string{
				"X-Real-IP": "192.168.1.2",
			},
			expectedIP: "192.168.1.2",
		},
		{
			name:       "CF-Connecting-IP header",
			remoteAddr: "10.0.0.1:8080",
			headers: map[string]string{
				"CF-Connecting-IP": "192.168.1.3",
			},
			expectedIP: "192.168.1.3",
		},
		{
			name:       "fallback to RemoteAddr",
			remoteAddr: "192.168.1.4:8080",
			headers:    map[string]string{},
			expectedIP: "192.168.1.4",
		},
		{
			name:       "X-Forwarded-For takes precedence",
			remoteAddr: "10.0.0.1:8080",
			headers: map[string]string{
				"X-Forwarded-For":  "192.168.1.1",
				"X-Real-IP":        "192.168.1.2",
				"CF-Connecting-IP": "192.168.1.3",
			},
			expectedIP: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			actualIP := GetClientIP(req)
			if actualIP != tt.expectedIP {
				t.Errorf("expected IP '%s', got '%s'", tt.expectedIP, actualIP)
			}
		})
	}
}

// Benchmark the middleware performance
func BenchmarkRateLimitMiddleware(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimiter := NewInMemoryRateLimiter()
	defer rateLimiter.Close()

	limit := RateLimit{
		Requests: 1000000, // High limit so we don't hit it during benchmark
		Window:   time.Minute,
		KeyFunc:  KeyByIP,
	}

	rateLimitedHandler := RateLimitMiddleware(rateLimiter, limit)(handler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = fmt.Sprintf("192.168.1.%d:8080", b.N%255+1)

			rr := httptest.NewRecorder()
			rateLimitedHandler.ServeHTTP(rr, req)
		}
	})
}
