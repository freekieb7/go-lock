package clients

import (
	"net/http"

	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
)

// Handler handles client-related HTTP requests
type Handler struct {
	shared.BaseHandler
}

// NewHandler creates a new client handler
func NewHandler(base shared.BaseHandler) *Handler {
	return &Handler{
		BaseHandler: base,
	}
}

// HandleClients routes client requests to appropriate handlers
func (h *Handler) HandleClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.HandleListClients(w, r)
	case http.MethodPost:
		h.HandleCreateClient(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandleClient routes individual client requests to appropriate handlers
func (h *Handler) HandleClient(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.HandleGetClient(w, r)
	case http.MethodPut:
		h.HandleUpdateClient(w, r)
	case http.MethodDelete:
		h.HandleDeleteClient(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandleClientPermissions routes client permission requests to appropriate handlers
func (h *Handler) HandleClientPermissions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.HandleListClientPermissions(w, r)
	case http.MethodPost:
		h.HandleAddPermissionsToClient(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
