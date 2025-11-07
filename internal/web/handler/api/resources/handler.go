package resources

import (
	"net/http"

	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
)

// Handler handles resource server-related HTTP requests
type Handler struct {
	shared.BaseHandler
}

// NewHandler creates a new resource handler
func NewHandler(base shared.BaseHandler) *Handler {
	return &Handler{
		BaseHandler: base,
	}
}

// HandleResourceServers routes resource server requests to appropriate handlers
func (h *Handler) HandleResourceServers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.HandleListResourceServers(w, r)
	case http.MethodPost:
		h.HandleCreateResourceServer(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandleResourceServer routes individual resource server requests to appropriate handlers
func (h *Handler) HandleResourceServer(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.HandleGetResourceServer(w, r)
	case http.MethodPut:
		h.HandleUpdateResourceServer(w, r)
	case http.MethodDelete:
		h.HandleDeleteResourceServer(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// Implementation methods are in separate files:
// - list.go: HandleListResourceServers
// - create.go: HandleCreateResourceServer
// - get.go: HandleGetResourceServer
// - update.go: HandleUpdateResourceServer
// - delete.go: HandleDeleteResourceServer
