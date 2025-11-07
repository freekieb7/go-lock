package users

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/freekieb7/go-lock/internal/account"
	apperrors "github.com/freekieb7/go-lock/internal/errors"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
)

// HandleCreateUser creates a new user
func (h *Handler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req shared.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.ErrorContext(ctx, "Failed to decode create user request", "error", err)
		response.ErrorResponse(w, apperrors.ValidationError("Invalid request body", err), h.Logger)
		return
	}

	// Validate required fields
	email := strings.TrimSpace(req.Email)
	password := strings.TrimSpace(req.Password)
	userType := strings.TrimSpace(req.Type)

	if email == "" {
		h.Logger.WarnContext(ctx, "Missing user email")
		response.ErrorResponse(w, apperrors.ValidationError("Email is required", nil), h.Logger)
		return
	}

	if password == "" {
		h.Logger.WarnContext(ctx, "Missing user password")
		response.ErrorResponse(w, apperrors.ValidationError("Password is required", nil), h.Logger)
		return
	}

	// Set default user type if not provided
	if userType == "" {
		userType = "user"
	}

	// Validate user type
	if userType != "user" && userType != "admin" {
		h.Logger.WarnContext(ctx, "Invalid user type", "type", userType)
		response.ErrorResponse(w, apperrors.ValidationError("Invalid user type. Must be 'user' or 'admin'", nil), h.Logger)
		return
	}

	// Validate email format (basic validation)
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		h.Logger.WarnContext(ctx, "Invalid email format", "email", email)
		response.ErrorResponse(w, apperrors.ValidationError("Invalid email format", nil), h.Logger)
		return
	}

	// Validate password length
	if len(password) < 8 {
		h.Logger.WarnContext(ctx, "Password too short")
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidPasswordLength,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Create new user
	user, err := h.AccountService.NewUser(email, password)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to create new user", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	// Set user type if admin
	if userType == "admin" {
		user.Type = account.UserTypeAdmin
	}

	// Save user to database (this will automatically assign default scopes)
	user, err = h.AccountService.CreateUser(ctx, user)
	if err != nil {
		// Check for specific database constraint errors
		if strings.Contains(err.Error(), "email") && strings.Contains(err.Error(), "already exists") {
			h.Logger.WarnContext(ctx, "User with email already exists", "email", email)
			response.JSONResponse(w, http.StatusConflict, response.APIResponse{
				Code:    http.StatusConflict,
				Message: shared.ErrEmailAlreadyExists,
				Status:  shared.StatusConflict,
			})
			return
		}

		h.Logger.ErrorContext(ctx, "Failed to save new user", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	h.Logger.InfoContext(ctx, shared.MsgUserCreated, "user_id", user.ID, "email", user.Email, "type", user.Type)

	// Return success response
	response.JSONResponse(w, http.StatusCreated, response.APIResponse{
		Code:    http.StatusCreated,
		Message: shared.MsgUserCreated,
		Status:  shared.StatusSuccess,
		Data: shared.UserResponse{
			ID:    user.ID.String(),
			Email: user.Email,
			Type:  string(user.Type),
		},
	})
}
