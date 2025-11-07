package api

import (
	"net/http"

	"github.com/freekieb7/go-lock/internal/web/handler/api/clients"
	"github.com/freekieb7/go-lock/internal/web/handler/api/resources"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/handler/api/users"
	"github.com/freekieb7/go-lock/internal/web/middleware"
)

// Handler aggregates all API handlers and provides the main entry point
type Handler struct {
	shared.BaseHandler
	ClientsHandler   *clients.Handler
	UsersHandler     *users.Handler
	ResourcesHandler *resources.Handler
}

// NewHandler creates a new API handler with all sub-handlers
func NewHandler(base shared.BaseHandler) *Handler {
	return &Handler{
		BaseHandler:      base,
		ClientsHandler:   clients.NewHandler(base),
		UsersHandler:     users.NewHandler(base),
		ResourcesHandler: resources.NewHandler(base),
	}
}

// RegisterRoutes registers all API routes with the provided mux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Create rate limiter if enabled
	var secureAPIMiddleware func(http.Handler) http.Handler

	if h.Config.RateLimit.Enabled {
		// Initialize in-memory rate limiter
		rateLimiter := middleware.NewInMemoryRateLimiter()

		// Create API rate limit configuration
		apiLimit := middleware.RateLimit{
			Requests: h.Config.RateLimit.APIRequests,
			Window:   h.Config.RateLimit.WindowDuration,
			KeyFunc:  middleware.KeyByAPIKey,
		}

		// Apply comprehensive security middleware with rate limiting for API endpoints
		secureAPIMiddleware = middleware.SecureAPIMiddlewareWithRateLimit(h.Config.Security.APIKey, rateLimiter, apiLimit)
	} else {
		// Apply standard security middleware without rate limiting
		secureAPIMiddleware = middleware.SecureAPIMiddleware(h.Config.Security.APIKey)
	}

	// Client routes
	mux.Handle("/api/v1/clients", secureAPIMiddleware(http.HandlerFunc(h.ClientsHandler.HandleClients)))
	mux.Handle("/api/v1/clients/{client_id}", secureAPIMiddleware(http.HandlerFunc(h.ClientsHandler.HandleClient)))
	mux.Handle("/api/v1/clients/{client_id}/permissions", secureAPIMiddleware(http.HandlerFunc(h.ClientsHandler.HandleClientPermissions)))

	// User routes
	mux.Handle("/api/v1/users", secureAPIMiddleware(http.HandlerFunc(h.UsersHandler.HandleUsers)))
	mux.Handle("/api/v1/users/{user_id}", secureAPIMiddleware(http.HandlerFunc(h.UsersHandler.HandleUser)))
	mux.Handle("/api/v1/users/{user_id}/permissions", secureAPIMiddleware(http.HandlerFunc(h.UsersHandler.HandleUserPermissions)))

	// Resource server routes
	mux.Handle("/api/v1/resource-servers", secureAPIMiddleware(http.HandlerFunc(h.ResourcesHandler.HandleResourceServers)))
	mux.Handle("/api/v1/resource-servers/{resource_server_id}", secureAPIMiddleware(http.HandlerFunc(h.ResourcesHandler.HandleResourceServer)))
}
