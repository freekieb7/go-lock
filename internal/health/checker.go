package health

import (
	"context"
	"log/slog"
	"time"

	"github.com/freekieb7/go-lock/internal/cache"
	"github.com/freekieb7/go-lock/internal/database"
)

// Checker provides Kubernetes-ready health checks
type Checker struct {
	DB     *database.Database
	Cache  *cache.Manager
	Logger *slog.Logger
}

func NewChecker(db *database.Database, cache *cache.Manager, logger *slog.Logger) Checker {
	return Checker{
		DB:     db,
		Cache:  cache,
		Logger: logger,
	}
}

// HealthStatus represents comprehensive health information for Kubernetes
type HealthStatus struct {
	Status     string                     `json:"status"`
	Timestamp  string                     `json:"timestamp"`
	Version    string                     `json:"version,omitempty"`
	Components map[string]ComponentHealth `json:"components"`
	Details    *HealthDetails             `json:"details,omitempty"`
}

// ComponentHealth represents individual component health
type ComponentHealth struct {
	Status      string        `json:"status"`
	Message     string        `json:"message,omitempty"`
	Latency     time.Duration `json:"latency_ms"`
	LastChecked string        `json:"last_checked"`
	Critical    bool          `json:"critical"`
}

// HealthDetails provides additional diagnostic information
type HealthDetails struct {
	Uptime      time.Duration `json:"uptime_seconds"`
	Environment string        `json:"environment,omitempty"`
	NodeName    string        `json:"node_name,omitempty"`
	PodName     string        `json:"pod_name,omitempty"`
}

// CheckHealth performs comprehensive health check for Kubernetes probes
func (h *Checker) CheckHealth(ctx context.Context) HealthStatus {
	now := time.Now()
	components := make(map[string]ComponentHealth)

	// Check database (critical component)
	dbHealth := h.checkDatabase(ctx)
	components["database"] = dbHealth

	// Check Redis cache (non-critical, degraded is acceptable)
	cacheHealth := h.checkCache(ctx)
	components["cache"] = cacheHealth

	// Check application readiness
	appHealth := h.checkApplication(ctx)
	components["application"] = appHealth

	// Determine overall status based on critical components
	overallStatus := h.determineOverallStatus(components)

	return HealthStatus{
		Status:     overallStatus,
		Timestamp:  now.UTC().Format(time.RFC3339),
		Version:    "1.0.0", // Should be injected from build
		Components: components,
	}
}

// CheckLiveness provides a lightweight check for Kubernetes liveness probe
func (h *Checker) CheckLiveness(ctx context.Context) HealthStatus {
	now := time.Now()

	// Liveness should be lightweight - just verify process is responsive
	components := map[string]ComponentHealth{
		"process": {
			Status:      "healthy",
			Message:     "service is responsive",
			Latency:     time.Since(now),
			LastChecked: now.UTC().Format(time.RFC3339),
			Critical:    true,
		},
	}

	return HealthStatus{
		Status:     "healthy",
		Timestamp:  now.UTC().Format(time.RFC3339),
		Components: components,
	}
}

// CheckReadiness provides thorough check for Kubernetes readiness probe
func (h *Checker) CheckReadiness(ctx context.Context) HealthStatus {
	now := time.Now()
	components := make(map[string]ComponentHealth)

	// Only check critical dependencies for readiness
	dbHealth := h.checkDatabase(ctx)
	components["database"] = dbHealth

	// Simple application check
	components["application"] = ComponentHealth{
		Status:      "healthy",
		Message:     "application ready to serve traffic",
		Latency:     time.Millisecond,
		LastChecked: now.UTC().Format(time.RFC3339),
		Critical:    true,
	}

	overallStatus := "healthy"
	if dbHealth.Status == "unhealthy" {
		overallStatus = "unhealthy"
	}

	return HealthStatus{
		Status:     overallStatus,
		Timestamp:  now.UTC().Format(time.RFC3339),
		Components: components,
	}
}

func (h *Checker) checkDatabase(ctx context.Context) ComponentHealth {
	start := time.Now()

	if h.DB == nil {
		return ComponentHealth{
			Status:      "unhealthy",
			Message:     "database not configured",
			Latency:     time.Since(start),
			LastChecked: time.Now().UTC().Format(time.RFC3339),
			Critical:    true,
		}
	}

	// Test with a simple query that doesn't require any tables
	var result int
	err := h.DB.QueryRow(ctx, "SELECT 1").Scan(&result)

	latency := time.Since(start)

	if err != nil {
		h.Logger.Error("Database health check failed", "error", err, "latency", latency)
		return ComponentHealth{
			Status:      "unhealthy",
			Message:     "database connection failed: " + err.Error(),
			Latency:     latency,
			LastChecked: time.Now().UTC().Format(time.RFC3339),
			Critical:    true,
		}
	}

	// Check if latency is acceptable (warn if > 100ms, unhealthy if > 5s)
	status := "healthy"
	message := "database connection successful"

	if latency > 5*time.Second {
		status = "unhealthy"
		message = "database response time too slow"
	} else if latency > 100*time.Millisecond {
		status = "degraded"
		message = "database response time elevated"
	}

	return ComponentHealth{
		Status:      status,
		Message:     message,
		Latency:     latency,
		LastChecked: time.Now().UTC().Format(time.RFC3339),
		Critical:    true,
	}
}

func (h *Checker) checkCache(ctx context.Context) ComponentHealth {
	start := time.Now()

	if h.Cache == nil {
		return ComponentHealth{
			Status:      "degraded",
			Message:     "cache not configured - service will function without cache",
			Latency:     time.Since(start),
			LastChecked: time.Now().UTC().Format(time.RFC3339),
			Critical:    false,
		}
	}

	// Test Redis connectivity with a simple operation
	testKey := "health:check:ping"
	testValue := "pong"

	// Try to set and get a test value
	if err := h.Cache.Redis().Set(ctx, testKey, testValue, time.Second*10); err != nil {
		return ComponentHealth{
			Status:      "degraded",
			Message:     "redis cache unavailable - service degraded: " + err.Error(),
			Latency:     time.Since(start),
			LastChecked: time.Now().UTC().Format(time.RFC3339),
			Critical:    false,
		}
	}

	var retrieved string
	if err := h.Cache.Redis().Get(ctx, testKey, &retrieved); err != nil {
		return ComponentHealth{
			Status:      "degraded",
			Message:     "redis read failed - cache degraded: " + err.Error(),
			Latency:     time.Since(start),
			LastChecked: time.Now().UTC().Format(time.RFC3339),
			Critical:    false,
		}
	}

	return ComponentHealth{
		Status:      "healthy",
		Message:     "cache operational",
		Latency:     time.Since(start),
		LastChecked: time.Now().UTC().Format(time.RFC3339),
		Critical:    false,
	}
}

func (h *Checker) checkApplication(ctx context.Context) ComponentHealth {
	start := time.Now()

	// Simple application-level checks
	// You can extend this to check specific business logic

	return ComponentHealth{
		Status:      "healthy",
		Message:     "application services operational",
		Latency:     time.Since(start),
		LastChecked: time.Now().UTC().Format(time.RFC3339),
		Critical:    false,
	}
}

func (h *Checker) determineOverallStatus(components map[string]ComponentHealth) string {
	hasUnhealthy := false
	hasDegraded := false

	for _, component := range components {
		if component.Critical && component.Status == "unhealthy" {
			hasUnhealthy = true
		}
		if component.Status == "degraded" {
			hasDegraded = true
		}
	}

	if hasUnhealthy {
		return "unhealthy"
	}
	if hasDegraded {
		return "degraded"
	}
	return "healthy"
}
