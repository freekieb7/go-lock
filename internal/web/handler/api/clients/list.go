package clients

import (
	"net/http"
	"strconv"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
)

// HandleListClients handles GET /api/v1/clients
func (h *Handler) HandleListClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters instead of JSON body for GET request
	pageSize := 20 // default
	pageToken := r.URL.Query().Get("page_token")

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 {
			pageSize = ps
		}
	}

	// Call AccountService to get clients
	result, err := h.AccountService.ListClients(ctx, account.ListClientsParams{
		PageSize: pageSize,
		Token:    pageToken,
	})
	if err != nil {
		h.Logger.Error("failed to list clients", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	var resp shared.ListClientsResponse
	resp.Clients = make([]shared.ClientResponse, len(result.Clients))
	for i, client := range result.Clients {
		resp.Clients[i] = shared.ClientResponse{
			ID:             client.ID.String(),
			ClientID:       client.PublicID,
			Name:           client.Name,
			Description:    client.Description,
			RedirectURIs:   client.RedirectURIs,
			IsConfidential: client.IsConfidential,
			LogoURI:        client.LogoURI,
		}
	}
	resp.NextPageToken = result.NextToken
	resp.PrevPageToken = result.PrevToken

	response.JSONResponse(w, http.StatusOK, resp)
}
