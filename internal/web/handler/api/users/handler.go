package users

import (
	"net/http"

	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
)

// Handler handles user-related HTTP requests
type Handler struct {
	shared.BaseHandler
}

// NewHandler creates a new user handler
func NewHandler(base shared.BaseHandler) *Handler {
	return &Handler{
		BaseHandler: base,
	}
}

// HandleUsers routes user requests to appropriate handlers
func (h *Handler) HandleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.HandleListUsers(w, r)
	case http.MethodPost:
		h.HandleCreateUser(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandleUser routes individual user requests to appropriate handlers
func (h *Handler) HandleUser(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.HandleGetUser(w, r)
	case http.MethodPut:
		h.HandleUpdateUser(w, r)
	case http.MethodDelete:
		h.HandleDeleteUser(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandleUserPermissions routes user permission requests to appropriate handlers
func (h *Handler) HandleUserPermissions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.HandleListUserPermissions(w, r)
	case http.MethodPost:
		h.HandleAddPermissionsToUser(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// Implementation methods are in separate files:
// - list.go: HandleListUsers
// - create.go: HandleCreateUser
// - get.go: HandleGetUser
// - update.go: HandleUpdateUser
// - delete.go: HandleDeleteUser
// - permissions.go: HandleListUserPermissions, HandleAddPermissionsToUser
