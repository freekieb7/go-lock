package users

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/google/uuid"
)

// HandleUpdateUser updates an existing user
func (h *Handler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := r.PathValue("user_id")
	if userIDStr == "" {
		h.Logger.WarnContext(ctx, shared.ErrMissingIDInPath)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrMissingIDInPath,
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

	// Get existing user
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

	// Decode patch request
	var req shared.UpdateUserRequest
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
	if req.Email != "" {
		email := strings.TrimSpace(req.Email)
		// Validate email format
		if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
			response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
				Code:    http.StatusBadRequest,
				Message: shared.ErrInvalidEmailFormat,
				Status:  shared.StatusInvalidRequest,
			})
			return
		}
		user.Email = email
		hasChanges = true
	}

	if req.Password != "" {
		password := strings.TrimSpace(req.Password)
		// Validate password length
		if len(password) < 8 {
			response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
				Code:    http.StatusBadRequest,
				Message: shared.ErrInvalidPasswordLength,
				Status:  shared.StatusInvalidRequest,
			})
			return
		}

		// Hash the new password
		hashedPassword, err := h.AccountService.HashPassword(password)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to hash password", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
				Code:    http.StatusInternalServerError,
				Message: shared.ErrFailedPasswordUpdate,
				Status:  shared.StatusError,
			})
			return
		}
		user.PasswordHash = hashedPassword
		hasChanges = true
	}

	if req.Type != "" {
		userType := strings.TrimSpace(req.Type)
		// Validate user type
		if userType != "user" && userType != "admin" {
			response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
				Code:    http.StatusBadRequest,
				Message: shared.ErrInvalidUserType,
				Status:  shared.StatusInvalidRequest,
			})
			return
		}

		if userType == "admin" {
			user.Type = account.UserTypeAdmin
		} else {
			user.Type = account.UserTypeUser
		}
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

	// Save updated user
	updatedUser, err := h.AccountService.UpdateUser(ctx, user)
	if err != nil {
		// Check for specific database constraint errors
		if strings.Contains(err.Error(), "email") && strings.Contains(err.Error(), "already exists") {
			response.JSONResponse(w, http.StatusConflict, response.APIResponse{
				Code:    http.StatusConflict,
				Message: shared.ErrEmailAlreadyExists,
				Status:  shared.StatusConflict,
			})
			return
		}

		h.Logger.ErrorContext(ctx, "Failed to save updated user", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrFailedUserUpdate,
			Status:  shared.StatusError,
		})
		return
	}

	h.Logger.InfoContext(ctx, shared.MsgUserUpdated, "user_id", updatedUser.ID, "email", updatedUser.Email)

	response.JSONResponse(w, http.StatusOK, response.APIResponse{
		Code:    http.StatusOK,
		Message: shared.MsgUserUpdated,
		Status:  shared.StatusSuccess,
	})
}
