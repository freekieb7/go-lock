package resources

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/freekieb7/go-lock/internal/oauth"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/google/uuid"
)

// HandleUpdateResourceServer updates an existing resource server
func (h *Handler) HandleUpdateResourceServer(w http.ResponseWriter, r *http.Request) {
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

	// Get existing resource server
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

	// Decode patch request
	var req shared.UpdateResourceServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.WarnContext(ctx, shared.ErrInvalidRequestBody, "error", err)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidRequestBody,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Track if any changes were made
	hasChanges := false

	// Apply updates only if fields are provided
	if req.Description != "" {
		resourceServer.Description = strings.TrimSpace(req.Description)
		hasChanges = true
	}

	// If no changes were made, return early
	if !hasChanges {
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrNoUpdatesProvided,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Save updated resource server
	_, err = h.OAuthService.UpdateResourceServer(ctx, resourceServer)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to update resource server", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrFailedResourceServerUpdate,
			Status:  shared.StatusError,
		})
		return
	}

	h.Logger.InfoContext(ctx, shared.MsgResourceServerUpdated, "resource_server_id", resourceServer.ID)

	response.JSONResponse(w, http.StatusOK, response.APIResponse{
		Code:    http.StatusOK,
		Message: shared.MsgResourceServerUpdated,
		Status:  shared.StatusSuccess,
	})
}
