package middleware

import (
	"context"
	"crypto/md5"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/freekieb7/go-lock/internal/cache"
)

// RedisCacheConfig holds configuration for Redis-based caching middleware
type RedisCacheConfig struct {
	Cache           *cache.Service
	DefaultTTL      time.Duration
	VaryHeaders     []string
	CacheablePaths  []string
	ExcludePaths    []string
	CacheableStatus []int
	Logger          *slog.Logger
}

// RedisCacheMiddleware creates middleware that caches responses in Redis
func RedisCacheMiddleware(config RedisCacheConfig) func(http.Handler) http.Handler {
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 5 * time.Minute
	}

	if len(config.CacheableStatus) == 0 {
		config.CacheableStatus = []int{http.StatusOK}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only cache GET and HEAD requests
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			// Check if path should be cached
			if !shouldCachePath(r.URL.Path, config.CacheablePaths, config.ExcludePaths) {
				next.ServeHTTP(w, r)
				return
			}

			// Generate cache key
			cacheKey := generateCacheKey(r, config.VaryHeaders)

			// Try to get from cache first
			var cachedResponse CachedResponse
			err := config.Cache.Get(r.Context(), cacheKey, &cachedResponse)
			if err == nil {
				// Cache hit - serve from cache
				config.Logger.Debug("Cache hit", "key", cacheKey, "path", r.URL.Path)
				serveCachedResponse(w, &cachedResponse)
				return
			}

			if err != cache.ErrCacheMiss {
				config.Logger.Warn("Cache error", "error", err, "key", cacheKey)
			}

			// Cache miss - generate response and cache it
			wrapper := &cacheResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				headers:        make(http.Header),
			}

			next.ServeHTTP(wrapper, r)

			// Cache the response if it's cacheable
			if shouldCacheResponse(wrapper.statusCode, config.CacheableStatus) {
				cachedResp := CachedResponse{
					StatusCode: wrapper.statusCode,
					Headers:    wrapper.headers,
					Body:       wrapper.body,
					CachedAt:   time.Now(),
				}

				// Store in cache (fire and forget)
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					if setErr := config.Cache.Set(ctx, cacheKey, cachedResp, config.DefaultTTL); setErr != nil {
						config.Logger.Warn("Failed to cache response", "error", setErr, "key", cacheKey)
					} else {
						config.Logger.Debug("Response cached", "key", cacheKey, "path", r.URL.Path)
					}
				}()
			}
		})
	}
}

// CachedResponse represents a cached HTTP response
type CachedResponse struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers"`
	Body       []byte      `json:"body"`
	CachedAt   time.Time   `json:"cached_at"`
}

// cacheResponseWriter wraps http.ResponseWriter to capture response data
type cacheResponseWriter struct {
	http.ResponseWriter
	statusCode int
	headers    http.Header
	body       []byte
}

func (w *cacheResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode

	// Copy headers
	for k, v := range w.ResponseWriter.Header() {
		w.headers[k] = v
	}

	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *cacheResponseWriter) Write(data []byte) (int, error) {
	w.body = append(w.body, data...)
	return w.ResponseWriter.Write(data)
}

// generateCacheKey creates a unique cache key for the request
func generateCacheKey(r *http.Request, varyHeaders []string) string {
	var keyParts []string

	// Add method and path
	keyParts = append(keyParts, r.Method, r.URL.Path)

	// Add query parameters (sorted for consistency)
	if query := r.URL.RawQuery; query != "" {
		keyParts = append(keyParts, query)
	}

	// Add vary headers
	for _, header := range varyHeaders {
		value := r.Header.Get(header)
		keyParts = append(keyParts, fmt.Sprintf("%s:%s", header, value))
	}

	// Create hash of the key parts
	key := strings.Join(keyParts, "|")
	hash := md5.Sum([]byte(key))
	return fmt.Sprintf("response:%x", hash)
}

// shouldCachePath determines if a path should be cached
func shouldCachePath(path string, cacheablePaths, excludePaths []string) bool {
	// Check exclude paths first
	for _, exclude := range excludePaths {
		if strings.HasPrefix(path, exclude) {
			return false
		}
	}

	// If no specific cacheable paths, cache everything not excluded
	if len(cacheablePaths) == 0 {
		return true
	}

	// Check if path matches cacheable patterns
	for _, cacheable := range cacheablePaths {
		if strings.HasPrefix(path, cacheable) {
			return true
		}
	}

	return false
}

// shouldCacheResponse determines if a response should be cached based on status code
func shouldCacheResponse(statusCode int, cacheableStatus []int) bool {
	for _, status := range cacheableStatus {
		if statusCode == status {
			return true
		}
	}
	return false
}

// serveCachedResponse serves a cached response
func serveCachedResponse(w http.ResponseWriter, cached *CachedResponse) {
	// Set headers
	for k, v := range cached.Headers {
		w.Header()[k] = v
	}

	// Add cache headers
	w.Header().Set("X-Cache", "HIT")
	w.Header().Set("X-Cache-Date", cached.CachedAt.Format(http.TimeFormat))

	// Write status and body
	w.WriteHeader(cached.StatusCode)
	w.Write(cached.Body)
}

// APIResponseCacheMiddleware creates caching middleware optimized for API responses
func APIResponseCacheMiddleware(cacheService *cache.Service, logger *slog.Logger) func(http.Handler) http.Handler {
	return RedisCacheMiddleware(RedisCacheConfig{
		Cache:      cacheService,
		DefaultTTL: 5 * time.Minute,
		VaryHeaders: []string{
			"Authorization",
			"Accept",
			"Accept-Language",
		},
		CacheablePaths: []string{
			"/api/clients",
			"/api/users",
			"/oauth/jwks",
			"/api/health",
		},
		ExcludePaths: []string{
			"/oauth/authorize",
			"/oauth/token",
			"/api/sessions",
		},
		CacheableStatus: []int{
			http.StatusOK,
			http.StatusNotFound, // Cache 404s for a short time
		},
		Logger: logger,
	})
}

// StaticResourceCacheMiddleware creates caching middleware for static resources
func StaticResourceCacheMiddleware(cacheService *cache.Service, logger *slog.Logger) func(http.Handler) http.Handler {
	return RedisCacheMiddleware(RedisCacheConfig{
		Cache:      cacheService,
		DefaultTTL: 1 * time.Hour, // Longer TTL for static resources
		CacheablePaths: []string{
			"/static/",
			"/css/",
			"/js/",
			"/images/",
			"/docs/static/",
		},
		CacheableStatus: []int{
			http.StatusOK,
		},
		Logger: logger,
	})
}

// CacheInvalidationMiddleware provides middleware to invalidate cache entries
func CacheInvalidationMiddleware(cacheService *cache.Service, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Wrap response writer to capture status
			wrapper := &statusCapture{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(wrapper, r)

			// Invalidate cache on successful mutations
			if isSuccessfulMutation(r.Method, wrapper.statusCode) {
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					patterns := getCacheInvalidationPatterns(r.URL.Path)
					for _, pattern := range patterns {
						if err := cacheService.DeletePattern(ctx, pattern); err != nil {
							logger.Warn("Failed to invalidate cache", "pattern", pattern, "error", err)
						} else {
							logger.Debug("Cache invalidated", "pattern", pattern, "path", r.URL.Path)
						}
					}
				}()
			}
		})
	}
}

// isSuccessfulMutation checks if the request was a successful mutation
func isSuccessfulMutation(method string, statusCode int) bool {
	mutationMethods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, m := range mutationMethods {
		if method == m && statusCode >= 200 && statusCode < 300 {
			return true
		}
	}
	return false
}

// getCacheInvalidationPatterns returns cache patterns to invalidate for a path
func getCacheInvalidationPatterns(path string) []string {
	patterns := []string{
		fmt.Sprintf("response:*%s*", path), // Invalidate responses for this path
	}

	// Add specific invalidation rules
	switch {
	case strings.HasPrefix(path, "/api/clients"):
		patterns = append(patterns, "response:*/api/clients*", "client:*")
	case strings.HasPrefix(path, "/api/users"):
		patterns = append(patterns, "response:*/api/users*", "user:*", "perms:*")
	case strings.HasPrefix(path, "/oauth/"):
		patterns = append(patterns, "response:*/oauth/*", "session:*")
	}

	return patterns
}

// Use the statusCapture from circuit_breaker.go to avoid duplication
