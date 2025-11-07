package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// TimeoutConfig represents timeout configuration
type TimeoutConfig struct {
	Timeout time.Duration
	Message string
	Logger  *slog.Logger
}

// TimeoutMiddleware creates a middleware that enforces request timeouts
func TimeoutMiddleware(config TimeoutConfig) func(http.Handler) http.Handler {
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second // Default timeout
	}
	if config.Message == "" {
		config.Message = "Request timeout"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create context with timeout
			ctx, cancel := context.WithTimeout(r.Context(), config.Timeout)
			defer cancel()

			// Create a channel to signal completion
			done := make(chan struct{})
			var panicErr interface{}

			// Use a goroutine to handle the request
			go func() {
				defer func() {
					if p := recover(); p != nil {
						panicErr = p
					}
					close(done)
				}()

				next.ServeHTTP(w, r.WithContext(ctx))
			}()

			select {
			case <-done:
				// Request completed normally, check for panic
				if panicErr != nil {
					if config.Logger != nil {
						config.Logger.ErrorContext(ctx, "Request panic recovered",
							slog.Any("panic", panicErr),
							slog.String("path", r.URL.Path),
							slog.String("method", r.Method))
					}
					http.Error(w, "Internal server error", http.StatusInternalServerError)
				}
			case <-ctx.Done():
				// Request timed out
				if config.Logger != nil {
					config.Logger.WarnContext(ctx, "Request timeout",
						slog.Duration("timeout", config.Timeout),
						slog.String("path", r.URL.Path),
						slog.String("method", r.Method))
				}

				// Check if response was already written
				if ctx.Err() == context.DeadlineExceeded {
					http.Error(w, config.Message, http.StatusRequestTimeout)
				}
			}
		})
	}
}

// APITimeoutMiddleware creates timeout middleware optimized for API endpoints
func APITimeoutMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return TimeoutMiddleware(TimeoutConfig{
		Timeout: 15 * time.Second,
		Message: "API request timeout",
		Logger:  logger,
	})
}

// OAuthTimeoutMiddleware creates timeout middleware for OAuth endpoints
func OAuthTimeoutMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return TimeoutMiddleware(TimeoutConfig{
		Timeout: 10 * time.Second,
		Message: "OAuth request timeout",
		Logger:  logger,
	})
}

// AdminTimeoutMiddleware creates timeout middleware for admin endpoints
func AdminTimeoutMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return TimeoutMiddleware(TimeoutConfig{
		Timeout: 30 * time.Second,
		Message: "Admin request timeout",
		Logger:  logger,
	})
}
