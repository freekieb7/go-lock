package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/freekieb7/go-lock/internal/web/response"
)

// SecurityHeadersConfig allows customization of security headers
type SecurityHeadersConfig struct {
	// Enable HSTS (HTTP Strict Transport Security)
	EnableHSTS bool
	// HSTS max age in seconds (default: 1 year)
	HSTSMaxAge int
	// Include subdomains in HSTS
	HSTSIncludeSubdomains bool
	// Content Security Policy
	CSP string
	// Referrer Policy
	ReferrerPolicy string
	// Permissions Policy (formerly Feature Policy)
	PermissionsPolicy string
}

// SecurityHeadersFromConfig creates SecurityHeadersConfig from basic security settings
func SecurityHeadersFromConfig(enableHSTS bool, hstsMaxAge int, hstsIncludeSubdomains bool, csp, referrerPolicy, permissionsPolicy string) SecurityHeadersConfig {
	return SecurityHeadersConfig{
		EnableHSTS:            enableHSTS,
		HSTSMaxAge:            hstsMaxAge,
		HSTSIncludeSubdomains: hstsIncludeSubdomains,
		CSP:                   csp,
		ReferrerPolicy:        referrerPolicy,
		PermissionsPolicy:     permissionsPolicy,
	}
}

// DefaultSecurityHeaders returns a secure default configuration
func DefaultSecurityHeaders() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		EnableHSTS:            true,
		HSTSMaxAge:            31536000, // 1 year
		HSTSIncludeSubdomains: true,
		CSP:                   "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		PermissionsPolicy:     "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()",
	}
}

func SecurityHeadersMiddleware() func(http.Handler) http.Handler {
	return SecurityHeadersWithConfig(DefaultSecurityHeaders())
}

func SecurityHeadersWithConfig(config SecurityHeadersConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Prevent MIME type sniffing
			w.Header().Set("X-Content-Type-Options", "nosniff")

			// Prevent clickjacking
			w.Header().Set("X-Frame-Options", "DENY")

			// XSS protection (deprecated but still useful for older browsers)
			w.Header().Set("X-XSS-Protection", "1; mode=block")

			// HTTP Strict Transport Security
			if config.EnableHSTS {
				hstsValue := fmt.Sprintf("max-age=%d", config.HSTSMaxAge)
				if config.HSTSIncludeSubdomains {
					hstsValue += "; includeSubDomains"
				}
				w.Header().Set("Strict-Transport-Security", hstsValue)
			}

			// Content Security Policy
			if config.CSP != "" {
				w.Header().Set("Content-Security-Policy", config.CSP)
			}

			// Referrer Policy
			if config.ReferrerPolicy != "" {
				w.Header().Set("Referrer-Policy", config.ReferrerPolicy)
			}

			// Permissions Policy
			if config.PermissionsPolicy != "" {
				w.Header().Set("Permissions-Policy", config.PermissionsPolicy)
			}

			// Cross-Origin policies
			w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
			w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
			w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

			// Additional security headers
			w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
			w.Header().Set("X-Download-Options", "noopen")

			// Remove server information and version disclosure
			w.Header().Set("Server", "")
			w.Header().Del("X-Powered-By")

			// Cache control for security-sensitive responses
			if isOAuthEndpoint(r.URL.Path) {
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
				w.Header().Set("Pragma", "no-cache")
				w.Header().Set("Expires", "0")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// InputValidationMiddleware provides basic input validation and sanitization
func InputValidationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Limit request body size (10MB max)
			r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

			// Validate Content-Type for POST/PUT/PATCH requests
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
				contentType := r.Header.Get("Content-Type")
				if contentType != "" && contentType != "application/json" && contentType != "application/x-www-form-urlencoded" {
					http.Error(w, "Unsupported Content-Type", http.StatusUnsupportedMediaType)
					return
				}
			}

			// Basic header validation
			if userAgent := r.Header.Get("User-Agent"); userAgent == "" {
				// Log suspicious request without User-Agent (potential bot/script)
				// You might want to implement logging here
			}

			// Validate Host header to prevent Host header injection
			if r.Host == "" {
				http.Error(w, "Missing Host header", http.StatusBadRequest)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func APIKey(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			providedKey := r.Header.Get("X-API-Key")
			if providedKey != apiKey {
				w.Header().Set("Connection", "close")
				apiResponse := response.APIResponse{
					Code:    http.StatusUnauthorized,
					Message: "Invalid API Key",
					Status:  "UNAUTHORIZED",
				}
				response.JSONResponse(w, http.StatusUnauthorized, apiResponse)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SecureMiddleware creates a comprehensive security middleware chain
func SecureMiddleware() func(http.Handler) http.Handler {
	return Chain(
		SecurityHeadersMiddleware(),
		InputValidationMiddleware(),
	)
}

// SecureMiddlewareWithRateLimit creates a comprehensive security middleware chain with rate limiting
func SecureMiddlewareWithRateLimit(rateLimiter RateLimiter, limit RateLimit) func(http.Handler) http.Handler {
	return Chain(
		SecurityHeadersMiddleware(),
		InputValidationMiddleware(),
		RateLimitMiddleware(rateLimiter, limit),
	)
}

// SecureAPIMiddleware creates a security middleware chain specifically for API endpoints
func SecureAPIMiddleware(apiKey string) func(http.Handler) http.Handler {
	middlewares := []func(http.Handler) http.Handler{
		SecurityHeadersMiddleware(),
		InputValidationMiddleware(),
	}

	// Add API key authentication if provided
	if apiKey != "" {
		middlewares = append(middlewares, APIKey(apiKey))
	}

	return Chain(middlewares...)
}

// SecureAPIMiddlewareWithRateLimit creates a security middleware chain with rate limiting for API endpoints
func SecureAPIMiddlewareWithRateLimit(apiKey string, rateLimiter RateLimiter, limit RateLimit) func(http.Handler) http.Handler {
	middlewares := []func(http.Handler) http.Handler{
		SecurityHeadersMiddleware(),
		InputValidationMiddleware(),
		RateLimitMiddleware(rateLimiter, limit),
	}

	// Add API key authentication if provided
	if apiKey != "" {
		middlewares = append(middlewares, APIKey(apiKey))
	}

	return Chain(middlewares...)
}

// SecureAPIMiddlewareWithConfig creates a security middleware chain with custom config
func SecureAPIMiddlewareWithConfig(securityConfig SecurityHeadersConfig, apiKey string) func(http.Handler) http.Handler {
	middlewares := []func(http.Handler) http.Handler{
		SecurityHeadersWithConfig(securityConfig),
		InputValidationMiddleware(),
	}

	// Add API key authentication if provided
	if apiKey != "" {
		middlewares = append(middlewares, APIKey(apiKey))
	}

	return Chain(middlewares...)
}

// CORSConfig allows customization of CORS headers
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool
	MaxAge           int
}

// DefaultCORSConfig returns a permissive CORS configuration for public endpoints
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization"},
		AllowCredentials: false,
		MaxAge:           86400, // 24 hours
	}
}

// CORSMiddleware provides CORS support for public API endpoints
func CORSMiddleware() func(http.Handler) http.Handler {
	return CORSWithConfig(DefaultCORSConfig())
}

// CORSWithConfig provides CORS support with custom configuration
func CORSWithConfig(config CORSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowOrigin := false
			if len(config.AllowedOrigins) == 1 && config.AllowedOrigins[0] == "*" {
				allowOrigin = true
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else if origin != "" {
				for _, allowedOrigin := range config.AllowedOrigins {
					if origin == allowedOrigin {
						allowOrigin = true
						w.Header().Set("Access-Control-Allow-Origin", origin)
						break
					}
				}
			}

			if allowOrigin {
				// Set CORS headers
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))

				if config.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}

				if config.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", config.MaxAge))
				}
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// PublicAPISecurityHeaders applies minimal security headers for public API endpoints
func PublicAPISecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Basic security headers that don't interfere with CORS
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")

			// HSTS for HTTPS connections
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

			// Referrer policy
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Remove server information
			w.Header().Set("Server", "")

			// Cache control for public API endpoints (allow caching for performance)
			w.Header().Set("Cache-Control", "public, max-age=3600") // 1 hour cache

			// Note: We deliberately omit Cross-Origin-* headers here as they would interfere with CORS

			next.ServeHTTP(w, r)
		})
	}
}

// PublicAPIMiddleware creates a security middleware chain for public API endpoints (like OpenID Connect)
func PublicAPIMiddleware() func(http.Handler) http.Handler {
	return Chain(
		CORSMiddleware(),
		PublicAPISecurityHeaders(),
	)
}

// isOAuthEndpoint checks if the given path is a security-sensitive OAuth endpoint
func isOAuthEndpoint(path string) bool {
	securitySensitivePaths := []string{
		"/oauth/authorize",
		"/oauth/token",
		"/oauth/revoke",
		"/oauth/introspect",
		"/login",
		"/logout",
		"/consent",
	}

	for _, sensitivePath := range securitySensitivePaths {
		if strings.HasPrefix(path, sensitivePath) {
			return true
		}
	}
	return false
}
