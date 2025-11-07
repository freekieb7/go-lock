package middleware

import (
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// CircuitState represents the current state of the circuit breaker
type CircuitState int

const (
	StateClosed CircuitState = iota
	StateHalfOpen
	StateOpen
)

// CircuitBreakerConfig holds configuration for the circuit breaker
type CircuitBreakerConfig struct {
	MaxFailures   int           // Maximum failures before opening
	ResetTimeout  time.Duration // Time to wait before attempting reset
	SuccessCount  int           // Successes needed to close from half-open
	Timeout       time.Duration // Request timeout
	Logger        *slog.Logger
	OnStateChange func(from, to CircuitState)
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config       CircuitBreakerConfig
	state        CircuitState
	failures     int
	successes    int
	lastFailTime time.Time
	mutex        sync.RWMutex
}

// NewCircuitBreaker creates a new circuit breaker with the given config
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	if config.MaxFailures <= 0 {
		config.MaxFailures = 5
	}
	if config.ResetTimeout <= 0 {
		config.ResetTimeout = 30 * time.Second
	}
	if config.SuccessCount <= 0 {
		config.SuccessCount = 2
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}

	return &CircuitBreaker{
		config: config,
		state:  StateClosed,
	}
}

// Execute runs the given function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() error) error {
	cb.mutex.RLock()
	state := cb.state
	cb.mutex.RUnlock()

	switch state {
	case StateOpen:
		// Check if we should attempt reset
		cb.mutex.RLock()
		canAttempt := time.Since(cb.lastFailTime) > cb.config.ResetTimeout
		cb.mutex.RUnlock()

		if !canAttempt {
			return ErrCircuitBreakerOpen
		}

		// Attempt to half-open
		cb.setState(StateHalfOpen)
		fallthrough

	case StateHalfOpen:
		err := fn()
		if err != nil {
			cb.recordFailure()
			return err
		}
		cb.recordSuccess()
		return nil

	case StateClosed:
		err := fn()
		if err != nil {
			cb.recordFailure()
			return err
		}
		cb.resetFailures()
		return nil
	}

	return nil
}

// recordFailure records a failure and potentially opens the circuit
func (cb *CircuitBreaker) recordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failures++
	cb.lastFailTime = time.Now()
	cb.successes = 0 // Reset success count on failure

	if cb.config.Logger != nil {
		cb.config.Logger.Warn("Circuit breaker recorded failure",
			slog.Int("failures", cb.failures),
			slog.Int("max_failures", cb.config.MaxFailures))
	}

	if cb.failures >= cb.config.MaxFailures {
		cb.setState(StateOpen)
	}
}

// recordSuccess records a success and potentially closes the circuit
func (cb *CircuitBreaker) recordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.successes++

	if cb.config.Logger != nil {
		cb.config.Logger.Info("Circuit breaker recorded success",
			slog.Int("successes", cb.successes),
			slog.Int("required_successes", cb.config.SuccessCount))
	}

	if cb.state == StateHalfOpen && cb.successes >= cb.config.SuccessCount {
		cb.setState(StateClosed)
		cb.resetFailures()
	}
}

// resetFailures resets the failure count
func (cb *CircuitBreaker) resetFailures() {
	cb.failures = 0
	cb.successes = 0
}

// setState changes the circuit breaker state and triggers callback
func (cb *CircuitBreaker) setState(newState CircuitState) {
	oldState := cb.state
	cb.state = newState

	if cb.config.Logger != nil {
		cb.config.Logger.Info("Circuit breaker state changed",
			slog.String("from", stateString(oldState)),
			slog.String("to", stateString(newState)))
	}

	if cb.config.OnStateChange != nil {
		cb.config.OnStateChange(oldState, newState)
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// ErrCircuitBreakerOpen is returned when the circuit breaker is open
var ErrCircuitBreakerOpen = &CircuitBreakerError{Message: "circuit breaker is open"}

// CircuitBreakerError represents a circuit breaker error
type CircuitBreakerError struct {
	Message string
}

func (e *CircuitBreakerError) Error() string {
	return e.Message
}

// stateString returns a string representation of the circuit state
func stateString(state CircuitState) string {
	switch state {
	case StateClosed:
		return "closed"
	case StateHalfOpen:
		return "half-open"
	case StateOpen:
		return "open"
	default:
		return "unknown"
	}
}

// CircuitBreakerMiddleware creates middleware that applies circuit breaker pattern
func CircuitBreakerMiddleware(cb *CircuitBreaker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := cb.Execute(func() error {
				// Create a custom response writer to capture status
				wrapper := &statusCapture{ResponseWriter: w, statusCode: http.StatusOK}
				next.ServeHTTP(wrapper, r)

				// Consider HTTP 5xx errors as failures
				if wrapper.statusCode >= 500 {
					return &CircuitBreakerError{Message: "server error"}
				}
				return nil
			})

			if err != nil {
				if _, isCircuitError := err.(*CircuitBreakerError); isCircuitError && cb.GetState() == StateOpen {
					http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
					return
				}
				// If it's not a circuit breaker error, the response was already written
			}
		})
	}
}

// statusCapture captures the HTTP status code
type statusCapture struct {
	http.ResponseWriter
	statusCode int
}

func (sc *statusCapture) WriteHeader(code int) {
	sc.statusCode = code
	sc.ResponseWriter.WriteHeader(code)
}

// DatabaseCircuitBreaker creates a circuit breaker optimized for database operations
func DatabaseCircuitBreaker(logger *slog.Logger) *CircuitBreaker {
	return NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  3,
		ResetTimeout: 30 * time.Second,
		SuccessCount: 2,
		Logger:       logger,
		OnStateChange: func(from, to CircuitState) {
			if logger != nil {
				logger.Warn("Database circuit breaker state changed",
					slog.String("from", stateString(from)),
					slog.String("to", stateString(to)))
			}
		},
	})
}

// ExternalServiceCircuitBreaker creates a circuit breaker for external service calls
func ExternalServiceCircuitBreaker(serviceName string, logger *slog.Logger) *CircuitBreaker {
	return NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  5,
		ResetTimeout: 60 * time.Second,
		SuccessCount: 3,
		Logger:       logger,
		OnStateChange: func(from, to CircuitState) {
			if logger != nil {
				logger.Warn("External service circuit breaker state changed",
					slog.String("service", serviceName),
					slog.String("from", stateString(from)),
					slog.String("to", stateString(to)))
			}
		},
	})
}
