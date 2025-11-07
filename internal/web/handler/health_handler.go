package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/freekieb7/go-lock/internal/health"
	"github.com/freekieb7/go-lock/internal/web/response"
)

type HealthHandler struct {
	HealthChecker *health.Checker
}

func NewHealthHandler(healthChecker *health.Checker) HealthHandler {
	return HealthHandler{
		HealthChecker: healthChecker,
	}
}

// RegisterRoutes sets up Kubernetes-compatible health endpoints
func (h *HealthHandler) RegisterRoutes(mux *http.ServeMux) {
	// Comprehensive health check (for monitoring/debugging)
	mux.HandleFunc("/health", h.HandleHealth)

	// Kubernetes liveness probe endpoint (lightweight)
	mux.HandleFunc("/health/live", h.HandleLiveness)

	// Kubernetes readiness probe endpoint (thorough dependency checks)
	mux.HandleFunc("/health/ready", h.HandleReadiness)

	// Startup probe endpoint (for slow-starting containers)
	mux.HandleFunc("/health/startup", h.HandleStartup)
}

// HandleHealth provides comprehensive health information
func (h *HealthHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	status := h.HealthChecker.CheckHealth(ctx)

	// Set cache headers to prevent caching of health status
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	httpStatus := http.StatusOK
	if status.Status == "unhealthy" {
		httpStatus = http.StatusServiceUnavailable
	}

	response.JSONResponse(w, httpStatus, status)
}

// HandleLiveness provides Kubernetes liveness probe
// This should be lightweight and only check if the process is alive
func (h *HealthHandler) HandleLiveness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	status := h.HealthChecker.CheckLiveness(ctx)

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	httpStatus := http.StatusOK
	if status.Status == "unhealthy" {
		httpStatus = http.StatusServiceUnavailable
	}

	response.JSONResponse(w, httpStatus, status)
}

// HandleReadiness provides Kubernetes readiness probe
// This checks if the service is ready to accept traffic
func (h *HealthHandler) HandleReadiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	status := h.HealthChecker.CheckReadiness(ctx)

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	httpStatus := http.StatusOK
	if status.Status == "unhealthy" {
		httpStatus = http.StatusServiceUnavailable
	}

	response.JSONResponse(w, httpStatus, status)
}

// HandleStartup provides Kubernetes startup probe
// This is used for containers that have a slow startup time
func (h *HealthHandler) HandleStartup(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// For startup probe, we use readiness check but with longer timeout
	status := h.HealthChecker.CheckReadiness(ctx)

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	httpStatus := http.StatusOK
	if status.Status == "unhealthy" {
		httpStatus = http.StatusServiceUnavailable
	}

	response.JSONResponse(w, httpStatus, status)
}
