package users

import (
	"net/http"
	"strconv"

	"github.com/freekieb7/go-lock/internal/account"
	apperrors "github.com/freekieb7/go-lock/internal/errors"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
)

// HandleListUsers lists all users with pagination
func (h *Handler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters instead of JSON body for GET request
	pageSize := 20 // default
	pageToken := r.URL.Query().Get("page_token")

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 {
			pageSize = ps
		}
	}

	// Call AccountService to get users
	result, err := h.AccountService.ListUsers(ctx, account.ListUsersParams{
		PageSize: pageSize,
		Token:    pageToken,
	})
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to list users", "error", err)
		response.ErrorResponse(w, apperrors.InternalError("Failed to list users", err), h.Logger)
		return
	}

	var resp shared.ListUsersResponse
	resp.Users = make([]shared.UserResponse, len(result.Users))
	for i, user := range result.Users {
		resp.Users[i] = shared.UserResponse{
			ID:    user.ID.String(),
			Email: user.Email,
			Type:  string(user.Type),
		}
	}
	resp.NextPageToken = result.NextToken
	resp.PrevPageToken = result.PrevToken

	response.JSONResponse(w, http.StatusOK, resp)
}
