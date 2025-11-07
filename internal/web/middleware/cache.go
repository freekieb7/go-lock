package middleware

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CacheConfig represents caching configuration options
type CacheConfig struct {
	MaxAge         int  // Cache duration in seconds
	Public         bool // Whether cache is public or private
	MustRevalidate bool // Whether cache must revalidate
	NoStore        bool // Whether to prevent storing
	Immutable      bool // Whether content is immutable
}

// CacheMiddleware creates a middleware that adds appropriate cache headers
func CacheMiddleware(config CacheConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Build cache control header
			var cacheControl []string

			if config.NoStore {
				cacheControl = append(cacheControl, "no-store")
			} else {
				if config.Public {
					cacheControl = append(cacheControl, "public")
				} else {
					cacheControl = append(cacheControl, "private")
				}

				if config.MaxAge > 0 {
					cacheControl = append(cacheControl, fmt.Sprintf("max-age=%d", config.MaxAge))
				}

				if config.MustRevalidate {
					cacheControl = append(cacheControl, "must-revalidate")
				}

				if config.Immutable {
					cacheControl = append(cacheControl, "immutable")
				}
			}

			if len(cacheControl) > 0 {
				w.Header().Set("Cache-Control", strings.Join(cacheControl, ", "))
			}

			next.ServeHTTP(w, r)
		})
	}
}

// StaticCacheMiddleware creates caching for static assets
func StaticCacheMiddleware() func(http.Handler) http.Handler {
	return CacheMiddleware(CacheConfig{
		MaxAge:    86400 * 7, // 7 days
		Public:    true,
		Immutable: true,
	})
}

// APICacheMiddleware creates caching for API responses
func APICacheMiddleware(maxAge int) func(http.Handler) http.Handler {
	return CacheMiddleware(CacheConfig{
		MaxAge: maxAge,
		Public: true,
	})
}

// NoCache creates middleware that prevents caching
func NoCache() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			next.ServeHTTP(w, r)
		})
	}
}

// ETagMiddleware generates and validates ETags for responses
func ETagMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only apply ETags to GET and HEAD requests
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			// Create a response wrapper to capture content
			wrapper := &responseCapture{
				ResponseWriter: w,
				body:           make([]byte, 0),
			}

			next.ServeHTTP(wrapper, r)

			// Generate ETag based on response content
			if len(wrapper.body) > 0 {
				etag := fmt.Sprintf(`"%x"`, md5.Sum(wrapper.body))

				// Check if client has matching ETag
				if match := r.Header.Get("If-None-Match"); match == etag {
					w.WriteHeader(http.StatusNotModified)
					return
				}

				// Set ETag header and write content
				w.Header().Set("ETag", etag)
				w.WriteHeader(wrapper.statusCode)
				w.Write(wrapper.body)
			}
		})
	}
}

// responseCapture captures response content for ETag generation
type responseCapture struct {
	http.ResponseWriter
	body       []byte
	statusCode int
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	rc.body = append(rc.body, b...)
	return len(b), nil
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
}

// ConditionalCacheMiddleware provides advanced conditional caching
func ConditionalCacheMiddleware(lastModified time.Time, maxAge int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set Last-Modified header
			w.Header().Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))

			// Check If-Modified-Since
			if modSince := r.Header.Get("If-Modified-Since"); modSince != "" {
				if t, err := http.ParseTime(modSince); err == nil {
					if lastModified.Before(t.Add(1 * time.Second)) {
						w.WriteHeader(http.StatusNotModified)
						return
					}
				}
			}

			// Set cache headers
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))

			next.ServeHTTP(w, r)
		})
	}
}

// VaryMiddleware adds Vary headers for proper cache keying
func VaryMiddleware(headers ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(headers) > 0 {
				w.Header().Set("Vary", strings.Join(headers, ", "))
			}
			next.ServeHTTP(w, r)
		})
	}
}
