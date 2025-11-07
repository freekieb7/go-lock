package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// MetricsCollector defines the interface for collecting performance metrics
type MetricsCollector interface {
	RecordRequest(ctx context.Context, method, path string, statusCode int, duration time.Duration)
	RecordError(ctx context.Context, method, path string, errorType string)
}

// LogMetricsCollector implements MetricsCollector using structured logging
type LogMetricsCollector struct {
	logger *slog.Logger
}

// NewLogMetricsCollector creates a new log-based metrics collector
func NewLogMetricsCollector(logger *slog.Logger) *LogMetricsCollector {
	return &LogMetricsCollector{
		logger: logger,
	}
}

// RecordRequest logs request metrics
func (c *LogMetricsCollector) RecordRequest(ctx context.Context, method, path string, statusCode int, duration time.Duration) {
	c.logger.InfoContext(ctx, "HTTP request completed",
		slog.String("method", method),
		slog.String("path", path),
		slog.Int("status_code", statusCode),
		slog.Duration("duration", duration),
		slog.Float64("duration_ms", float64(duration.Nanoseconds())/1e6))
}

// RecordError logs error metrics
func (c *LogMetricsCollector) RecordError(ctx context.Context, method, path string, errorType string) {
	c.logger.ErrorContext(ctx, "HTTP request error",
		slog.String("method", method),
		slog.String("path", path),
		slog.String("error_type", errorType))
}

// responseWriter wraps http.ResponseWriter to capture status code and size
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// MetricsMiddleware creates middleware that collects HTTP request metrics
func MetricsMiddleware(collector MetricsCollector) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap the response writer to capture status code and size
			wrapper := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK, // Default to 200
			}

			// Process the request
			next.ServeHTTP(wrapper, r)

			// Calculate duration
			duration := time.Since(start)

			// Record metrics
			collector.RecordRequest(r.Context(), r.Method, r.URL.Path, wrapper.statusCode, duration)

			// Record errors for non-2xx responses
			if wrapper.statusCode >= 400 {
				errorType := categorizeError(wrapper.statusCode)
				collector.RecordError(r.Context(), r.Method, r.URL.Path, errorType)
			}
		})
	}
}

// categorizeError categorizes HTTP status codes into error types
func categorizeError(statusCode int) string {
	switch {
	case statusCode >= 400 && statusCode < 500:
		return "client_error"
	case statusCode >= 500:
		return "server_error"
	default:
		return "unknown_error"
	}
}

// PerformanceLoggingMiddleware creates middleware for detailed performance logging
func PerformanceLoggingMiddleware(ctx context.Context, logger *slog.Logger, slowThreshold time.Duration) func(http.Handler) http.Handler {
	if slowThreshold <= 0 {
		slowThreshold = 1 * time.Second // Default slow request threshold
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			wrapper := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(wrapper, r)

			duration := time.Since(start)

			// Log detailed performance information
			logLevel := slog.LevelInfo
			if duration > slowThreshold {
				logLevel = slog.LevelWarn
			}

			logger.Log(ctx, logLevel, "Request performance",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("remote_addr", r.RemoteAddr),
				slog.String("user_agent", r.UserAgent()),
				slog.Int("status_code", wrapper.statusCode),
				slog.Int("response_size", wrapper.size),
				slog.Duration("duration", duration),
				slog.Float64("duration_ms", float64(duration.Nanoseconds())/1e6),
				slog.Bool("slow_request", duration > slowThreshold))
		})
	}
}

// HealthMetricsMiddleware creates middleware for health check metrics
func HealthMetricsMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" || r.URL.Path == "/health/" {
				start := time.Now()

				wrapper := &responseWriter{
					ResponseWriter: w,
					statusCode:     http.StatusOK,
				}

				next.ServeHTTP(wrapper, r)

				duration := time.Since(start)

				// Log health check results
				isHealthy := wrapper.statusCode >= 200 && wrapper.statusCode < 300
				logger.InfoContext(r.Context(), "Health check completed",
					slog.Bool("healthy", isHealthy),
					slog.Int("status_code", wrapper.statusCode),
					slog.Duration("duration", duration))

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequestSizeMiddleware limits request body size and logs large requests
func RequestSizeMiddleware(maxSize int64, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Limit request body size
			if r.ContentLength > maxSize {
				logger.WarnContext(r.Context(), "Request body too large",
					slog.Int64("content_length", r.ContentLength),
					slog.Int64("max_size", maxSize),
					slog.String("path", r.URL.Path))

				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}

			if r.ContentLength > 0 {
				r.Body = http.MaxBytesReader(w, r.Body, maxSize)
			}

			next.ServeHTTP(w, r)
		})
	}
}
