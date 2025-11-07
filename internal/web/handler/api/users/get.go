package users

import (
	"net/http"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/google/uuid"
)

// HandleGetUser retrieves a user by ID
func (h *Handler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
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

	// Get user by ID
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

	response.JSONResponse(w, http.StatusOK, response.APIResponse{
		Code:    http.StatusOK,
		Message: shared.MsgUserRetrieved,
		Status:  shared.StatusSuccess,
		Data: shared.UserResponse{
			ID:    user.ID.String(),
			Email: user.Email,
			Type:  string(user.Type),
		},
	})
}
