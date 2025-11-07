package resources

import (
	"net/http"

	"github.com/freekieb7/go-lock/internal/oauth"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/google/uuid"
)

// HandleDeleteResourceServer deletes a resource server by ID
func (h *Handler) HandleDeleteResourceServer(w http.ResponseWriter, r *http.Request) {
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

	// Check if resource server exists
	_, err = h.OAuthService.GetResourceServerByID(ctx, resourceServerID)
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

	// Delete the resource server
	if err := h.OAuthService.DeleteResourceServerByID(ctx, resourceServerID); err != nil {
		h.Logger.ErrorContext(ctx, shared.ErrFailedResourceServerDelete, "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrFailedResourceServerDelete,
			Status:  shared.StatusError,
		})
		return
	}

	h.Logger.InfoContext(ctx, "Resource server deleted successfully", "resource_server_id", resourceServerID)

	w.WriteHeader(http.StatusNoContent)
}
