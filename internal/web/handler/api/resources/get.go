package resources

import (
	"net/http"

	"github.com/freekieb7/go-lock/internal/oauth"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/google/uuid"
)

// HandleGetResourceServer retrieves a resource server by ID
func (h *Handler) HandleGetResourceServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	resourceServerIDStr := r.PathValue("resource_server_id")
	if resourceServerIDStr == "" {
		h.Logger.WarnContext(ctx, shared.ErrMissingIDInPath)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrMissingIDInPath,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Parse resource server UUID
	resourceServerID, err := uuid.Parse(resourceServerIDStr)
	if err != nil {
		h.Logger.WarnContext(ctx, shared.ErrInvalidIDFormat, "resource_server_id", resourceServerIDStr)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidIDFormat,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Get resource server by ID
	resourceServer, err := h.OAuthService.GetResourceServerByID(ctx, resourceServerID)
	if err != nil {
		if err == oauth.ErrResourceServerNotFound {
			h.Logger.WarnContext(ctx, shared.ErrResourceServerNotFound, "resource_server_id", resourceServerID)
			response.JSONResponse(w, http.StatusNotFound, response.APIResponse{
				Code:    http.StatusNotFound,
				Message: shared.ErrResourceServerNotFound,
				Status:  shared.StatusNotFound,
			})
			return
		}
		h.Logger.ErrorContext(ctx, "Failed to get resource server by ID", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	scopes := make([]shared.ResourceServerScopeResponse, 0, len(resourceServer.Scopes))
	for name, desc := range resourceServer.Scopes {
		scopes = append(scopes, shared.ResourceServerScopeResponse{
			Name:        name,
			Description: desc,
		})
	}

	response.JSONResponse(w, http.StatusOK, response.APIResponse{
		Code:    http.StatusOK,
		Message: shared.MsgResourceServerRetrieved,
		Status:  shared.StatusSuccess,
		Data: shared.ResourceServerResponse{
			ID:          resourceServer.ID.String(),
			URL:         resourceServer.URL,
			Description: resourceServer.Description,
			Scopes:      scopes,
			CreatedAt:   resourceServer.CreatedAt,
		},
	})
}
