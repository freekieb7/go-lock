package resources

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/freekieb7/go-lock/internal/oauth"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
)

// HandleCreateResourceServer creates a new resource server
func (h *Handler) HandleCreateResourceServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req shared.CreateResourceServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.ErrorContext(ctx, "Failed to decode create resource server request", "error", err)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidRequestBody,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	url := strings.TrimSpace(req.URL)
	description := strings.TrimSpace(req.Description)
	scopes := make(map[string]string)
	for _, scope := range req.Scopes {
		name := strings.TrimSpace(scope.Name)
		desc := strings.TrimSpace(scope.Description)
		if name == "" || desc == "" {
			h.Logger.WarnContext(ctx, "Invalid scope", "scope", scope)
			response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
				Code:    http.StatusBadRequest,
				Message: shared.ErrInvalidRequest,
				Status:  shared.StatusInvalidRequest,
			})
			return
		}
		scopes[name] = desc
	}

	if url == "" {
		h.Logger.WarnContext(ctx, "Missing resource service URL")
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrResourceServerURLRequired,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Check if resource server with the same URL already exists
	_, err := h.OAuthService.GetResourceServerByURL(ctx, url)
	if err == nil {
		h.Logger.WarnContext(ctx, "Resource server with the same URL already exists", "url", url)
		response.JSONResponse(w, http.StatusConflict, response.APIResponse{
			Code:    http.StatusConflict,
			Message: shared.ErrResourceServerExists,
			Status:  shared.StatusConflict,
		})
		return
	}
	if err != oauth.ErrResourceServerNotFound {
		h.Logger.ErrorContext(ctx, "Failed to check existing resource server", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	// Create and save new resource server
	resourceServer, err := h.OAuthService.NewResourceServer(url, description, scopes)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to create resource server", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	resourceServer, err = h.OAuthService.CreateResourceServer(ctx, resourceServer)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to create resource server", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	respScopes := make([]shared.ResourceServerScopeResponse, 0, len(scopes))
	for name, desc := range scopes {
		respScopes = append(respScopes, shared.ResourceServerScopeResponse{
			Name:        name,
			Description: desc,
		})
	}

	response.JSONResponse(w, http.StatusOK, shared.ResourceServerResponse{
		ID:          resourceServer.ID.String(),
		URL:         resourceServer.URL,
		Description: description,
		Scopes:      respScopes,
		CreatedAt:   resourceServer.CreatedAt,
	})
}
