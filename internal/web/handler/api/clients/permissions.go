package clients

import (
	"encoding/json"
	"net/http"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/google/uuid"
)

// HandleListClientPermissions handles GET /api/v1/clients/{client_id}/permissions
func (h *Handler) HandleListClientPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clientIDStr := r.PathValue("client_id")
	if clientIDStr == "" {
		h.Logger.WarnContext(ctx, shared.ErrMissingIDInPath)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrMissingIDInPath,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Parse client UUID
	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		h.Logger.WarnContext(ctx, shared.ErrInvalidIDFormat, "client_id", clientIDStr)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidIDFormat,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Check if client exists
	client, err := h.AccountService.GetClientByID(ctx, clientID)
	if err != nil {
		if err == account.ErrClientNotFound {
			h.Logger.WarnContext(ctx, "Client not found", "client_id", clientID)
			response.JSONResponse(w, http.StatusNotFound, response.APIResponse{
				Code:    http.StatusNotFound,
				Message: shared.ErrClientNotFound,
				Status:  shared.StatusNotFound,
			})
			return
		}
		h.Logger.ErrorContext(ctx, "Failed to get client by ID", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	// Get client scopes
	scopes, err := h.OAuthService.GetScopesByAccountID(ctx, client.ID)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to get client scopes", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	response.JSONResponse(w, http.StatusOK, response.APIResponse{
		Code:    http.StatusOK,
		Message: shared.MsgClientScopesRetrieved,
		Status:  shared.StatusSuccess,
		Data: shared.ClientPermissionsResponse{
			Scopes: scopes,
		},
	})
}

// HandleAddPermissionsToClient handles POST /api/v1/clients/{client_id}/permissions
func (h *Handler) HandleAddPermissionsToClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clientIDStr := r.PathValue("client_id")
	if clientIDStr == "" {
		h.Logger.WarnContext(ctx, shared.ErrMissingIDInPath)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrMissingIDInPath,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		h.Logger.WarnContext(ctx, shared.ErrInvalidIDFormat, "client_id", clientIDStr)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidIDFormat,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Check if client exists
	client, err := h.AccountService.GetClientByID(ctx, clientID)
	if err != nil {
		if err == account.ErrClientNotFound {
			h.Logger.WarnContext(ctx, "Client not found", "client_id", clientID)
			response.JSONResponse(w, http.StatusNotFound, response.APIResponse{
				Code:    http.StatusNotFound,
				Message: shared.ErrClientNotFound,
				Status:  shared.StatusNotFound,
			})
			return
		}
		h.Logger.ErrorContext(ctx, "Failed to get client by ID", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	// Parse request body
	var req shared.CreateClientPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.WarnContext(ctx, shared.ErrInvalidRequestBody, "error", err)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidRequestBody,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	if len(req.Scopes) == 0 {
		h.Logger.WarnContext(ctx, "No scopes provided")
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidRequest,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Validate scopes exist by trying to get scope details
	if _, err := h.OAuthService.GetScopesByNames(ctx, req.Scopes); err != nil {
		h.Logger.WarnContext(ctx, "Invalid scopes provided", "error", err)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrScopeNotFound,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Add scopes to client
	if err := h.OAuthService.AssignScopesToClient(ctx, client.ID, req.Scopes); err != nil {
		h.Logger.ErrorContext(ctx, "Failed to add scopes to client", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	// Get updated scopes
	updatedScopes, err := h.OAuthService.GetScopesByAccountID(ctx, client.ID)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to get updated client scopes", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	response.JSONResponse(w, http.StatusOK, response.APIResponse{
		Code:    http.StatusOK,
		Message: shared.MsgClientScopesRetrieved,
		Status:  shared.StatusSuccess,
		Data: shared.ClientPermissionsResponse{
			Scopes: updatedScopes,
		},
	})
}
