package users

import (
	"encoding/json"
	"net/http"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/oauth"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/google/uuid"
)

// HandleListUserPermissions lists permissions/scopes for a user
func (h *Handler) HandleListUserPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := r.PathValue("user_id")
	if userIDStr == "" {
		h.Logger.WarnContext(ctx, shared.ErrMissingIDInPath)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidRequest,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Parse user UUID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.Logger.WarnContext(ctx, shared.ErrInvalidIDFormat, "user_id", userIDStr)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidIDFormat,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Check if user exists
	user, err := h.AccountService.GetUserByID(ctx, userID)
	if err != nil {
		if err == account.ErrUserNotFound {
			h.Logger.WarnContext(ctx, shared.ErrUserNotFound, "user_id", userID)
			response.JSONResponse(w, http.StatusNotFound, response.APIResponse{
				Code:    http.StatusNotFound,
				Message: shared.ErrUserNotFound,
				Status:  shared.StatusNotFound,
			})
			return
		}
		h.Logger.ErrorContext(ctx, "Failed to get user by ID", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	// Get user scopes
	scopes, err := h.OAuthService.GetScopesByAccountID(ctx, user.ID)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to get user scopes", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	response.JSONResponse(w, http.StatusOK, response.APIResponse{
		Code:    http.StatusOK,
		Message: shared.MsgUserScopesRetrieved,
		Status:  shared.StatusSuccess,
		Data: shared.UserPermissionsResponse{
			Scopes: scopes,
		},
	})
}

// HandleAddPermissionsToUser adds permissions/scopes to a user
func (h *Handler) HandleAddPermissionsToUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID := r.PathValue("user_id")
	if userID == "" {
		h.Logger.WarnContext(ctx, shared.ErrMissingIDInPath)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidRequest,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Parse and validate user UUID
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		h.Logger.WarnContext(ctx, shared.ErrInvalidIDFormat, "user_id", userID)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidIDFormat,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Check if user exists
	user, err := h.AccountService.GetUserByID(ctx, userUUID)
	if err != nil {
		if err == account.ErrUserNotFound {
			h.Logger.WarnContext(ctx, shared.ErrUserNotFound, "user_id", userID)
			response.JSONResponse(w, http.StatusNotFound, response.APIResponse{
				Code:    http.StatusNotFound,
				Message: shared.ErrUserNotFound,
				Status:  shared.StatusNotFound,
			})
			return
		}
		h.Logger.ErrorContext(ctx, "Failed to get user by ID", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	var req shared.AddUserPermissionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.ErrorContext(ctx, "Failed to decode create user permission request", "error", err)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidRequestBody,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	if err := h.OAuthService.AssignScopesToUser(ctx, user.ID, req.Scopes); err != nil {
		if err == oauth.ErrScopeNotFound {
			h.Logger.WarnContext(ctx, "One or more scopes not found", "user_id", user.ID, "scopes", req.Scopes)
			response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
				Code:    http.StatusBadRequest,
				Message: shared.ErrScopeNotFound,
				Status:  shared.StatusInvalidRequest,
			})
			return
		}

		h.Logger.ErrorContext(ctx, "Failed to assign scopes to user", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
