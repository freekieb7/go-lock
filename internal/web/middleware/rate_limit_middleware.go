package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/freekieb7/go-lock/internal/web/response"
)

// RateLimit defines rate limiting parameters for a specific endpoint or global config
type RateLimit struct {
	Requests int           // Number of requests allowed
	Window   time.Duration // Time window for the requests
	KeyFunc  KeyFunction   // Function to generate the rate limiting key
}

// KeyFunction defines how to generate the rate limiting key from the request
type KeyFunction func(r *http.Request) string

// Common key functions
var (
	// KeyByIP generates keys based on client IP address
	KeyByIP KeyFunction = func(r *http.Request) string {
		return GetClientIP(r)
	}

	// KeyByUserAgent generates keys based on User-Agent header
	KeyByUserAgent KeyFunction = func(r *http.Request) string {
		return r.Header.Get("User-Agent")
	}

	// KeyByAPIKey generates keys based on API key header
	KeyByAPIKey KeyFunction = func(r *http.Request) string {
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			return fmt.Sprintf("api_key:%s", apiKey)
		}
		return GetClientIP(r) // Fallback to IP if no API key
	}

	// KeyGlobal uses a single global key for all requests
	KeyGlobal KeyFunction = func(r *http.Request) string {
		return "global"
	}
)

// GetClientIP extracts the real client IP from the request
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (most common proxy header)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP from the comma-separated list
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			if ip := strings.TrimSpace(ips[0]); ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP header (common in nginx)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Check CF-Connecting-IP header (Cloudflare)
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return strings.TrimSpace(cfIP)
	}

	// Fallback to RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}

	return r.RemoteAddr
}

// RateLimitMiddleware creates a rate limiting middleware
func RateLimitMiddleware(rateLimiter RateLimiter, limit RateLimit) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Generate the key for rate limiting
			key := limit.KeyFunc(r)
			if key == "" {
				key = "unknown"
			}

			// Check if the request is allowed
			allowed, err := rateLimiter.Allow(r.Context(), key, limit.Requests, limit.Window)
			if err != nil {
				// Log error but don't block the request
				// TODO: Add proper logging
				next.ServeHTTP(w, r)
				return
			}

			if !allowed {
				// Rate limit exceeded
				remaining, _ := rateLimiter.GetRemaining(r.Context(), key, limit.Requests, limit.Window)

				// Set rate limiting headers
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
				w.Header().Set("X-RateLimit-Window", limit.Window.String())

				// Return rate limit exceeded response
				response.JSONResponse(w, http.StatusTooManyRequests, response.APIResponse{
					Code:    http.StatusTooManyRequests,
					Message: "Rate limit exceeded",
					Status:  "RATE_LIMITED",
				})
				return
			}

			// Add rate limiting headers to successful responses
			remaining, _ := rateLimiter.GetRemaining(r.Context(), key, limit.Requests, limit.Window)
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Window", limit.Window.String())

			next.ServeHTTP(w, r)
		})
	}
}

// MultiRateLimitMiddleware applies multiple rate limits to the same handler
func MultiRateLimitMiddleware(rateLimiter RateLimiter, limits ...RateLimit) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check all rate limits
			for i, limit := range limits {
				key := limit.KeyFunc(r)
				if key == "" {
					key = "unknown"
				}

				allowed, err := rateLimiter.Allow(r.Context(), key, limit.Requests, limit.Window)
				if err != nil {
					// Log error but continue to next limit
					continue
				}

				if !allowed {
					// Rate limit exceeded
					remaining, _ := rateLimiter.GetRemaining(r.Context(), key, limit.Requests, limit.Window)

					// Set headers for the first rate limit that failed
					w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
					w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
					w.Header().Set("X-RateLimit-Window", limit.Window.String())
					w.Header().Set("X-RateLimit-Policy", fmt.Sprintf("policy-%d", i))

					response.JSONResponse(w, http.StatusTooManyRequests, response.APIResponse{
						Code:    http.StatusTooManyRequests,
						Message: fmt.Sprintf("Rate limit exceeded: %d requests per %s", limit.Requests, limit.Window),
						Status:  "RATE_LIMITED",
					})
					return
				}
			}

			// If all rate limits pass, add headers from the most restrictive limit
			if len(limits) > 0 {
				limit := limits[0] // Use first limit for headers
				key := limit.KeyFunc(r)
				remaining, _ := rateLimiter.GetRemaining(r.Context(), key, limit.Requests, limit.Window)
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
				w.Header().Set("X-RateLimit-Window", limit.Window.String())
			}

			next.ServeHTTP(w, r)
		})
	}
}

// PathBasedRateLimitMiddleware applies different rate limits based on request path
func PathBasedRateLimitMiddleware(rateLimiter RateLimiter, pathLimits map[string]RateLimit, defaultLimit *RateLimit) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Find the appropriate rate limit for this path
			var limit RateLimit
			var found bool

			// Check for exact path matches first
			if pathLimit, exists := pathLimits[r.URL.Path]; exists {
				limit = pathLimit
				found = true
			} else {
				// Check for prefix matches
				for path, pathLimit := range pathLimits {
					if strings.HasPrefix(r.URL.Path, path) {
						limit = pathLimit
						found = true
						break
					}
				}
			}

			// Use default limit if no specific limit found
			if !found && defaultLimit != nil {
				limit = *defaultLimit
				found = true
			}

			// If no rate limit applies, pass through
			if !found {
				next.ServeHTTP(w, r)
				return
			}

			// Apply the rate limit
			RateLimitMiddleware(rateLimiter, limit)(next).ServeHTTP(w, r)
		})
	}
}

// CommonRateLimits provides predefined rate limiting configurations
type CommonRateLimits struct {
	// OAuth endpoints (stricter limits)
	OAuth RateLimit
	// API endpoints (moderate limits)
	API RateLimit
	// Public endpoints (relaxed limits)
	Public RateLimit
	// Admin endpoints (very strict limits)
	Admin RateLimit
}

// DefaultRateLimits returns sensible default rate limits for different endpoint types
func DefaultRateLimits() CommonRateLimits {
	return CommonRateLimits{
		OAuth: RateLimit{
			Requests: 10,
			Window:   time.Minute,
			KeyFunc:  KeyByIP,
		},
		API: RateLimit{
			Requests: 100,
			Window:   time.Minute,
			KeyFunc:  KeyByAPIKey,
		},
		Public: RateLimit{
			Requests: 60,
			Window:   time.Minute,
			KeyFunc:  KeyByIP,
		},
		Admin: RateLimit{
			Requests: 5,
			Window:   time.Minute,
			KeyFunc:  KeyByIP,
		},
	}
}

// StrictRateLimits returns stricter rate limits for high-security environments
func StrictRateLimits() CommonRateLimits {
	return CommonRateLimits{
		OAuth: RateLimit{
			Requests: 5,
			Window:   time.Minute,
			KeyFunc:  KeyByIP,
		},
		API: RateLimit{
			Requests: 30,
			Window:   time.Minute,
			KeyFunc:  KeyByAPIKey,
		},
		Public: RateLimit{
			Requests: 20,
			Window:   time.Minute,
			KeyFunc:  KeyByIP,
		},
		Admin: RateLimit{
			Requests: 3,
			Window:   time.Minute,
			KeyFunc:  KeyByIP,
		},
	}
}
