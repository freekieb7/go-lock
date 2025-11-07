package resources

import (
	"net/http"
	"strconv"

	"github.com/freekieb7/go-lock/internal/oauth"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
)

// HandleListResourceServers lists all resource servers with pagination
func (h *Handler) HandleListResourceServers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters instead of JSON body for GET request
	pageSize := 20 // default
	pageToken := r.URL.Query().Get("page_token")

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 {
			pageSize = ps
		}
	}

	// Call OAuth service to get resource servers
	result, err := h.OAuthService.ListResourceServers(ctx, oauth.ListResourceServersParams{
		PageSize: pageSize,
		Token:    pageToken,
	})
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to list resource servers", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	var resp shared.ListResourceServersResponse
	resp.ResourceServers = make([]shared.ResourceServerResponse, len(result.ResourceServers))
	for i, resourceServer := range result.ResourceServers {
		scopes := make([]shared.ResourceServerScopeResponse, 0, len(resourceServer.Scopes))
		for name, desc := range resourceServer.Scopes {
			scopes = append(scopes, shared.ResourceServerScopeResponse{
				Name:        name,
				Description: desc,
			})
		}

		resp.ResourceServers[i] = shared.ResourceServerResponse{
			ID:          resourceServer.ID.String(),
			URL:         resourceServer.URL,
			Description: resourceServer.Description,
			Scopes:      scopes,
			CreatedAt:   resourceServer.CreatedAt,
		}
	}
	resp.NextPageToken = result.NextToken
	resp.PrevPageToken = result.PrevToken

	response.JSONResponse(w, http.StatusOK, resp)
}
