package clients

import (
	"net/http"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/google/uuid"
)

// HandleGetClient handles GET /api/v1/clients/{client_id}
func (h *Handler) HandleGetClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clientID := r.PathValue("client_id")
	if clientID == "" {
		h.Logger.WarnContext(ctx, shared.ErrMissingIDInPath)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrMissingIDInPath,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Parse client UUID
	clientUUID, err := uuid.Parse(clientID)
	if err != nil {
		h.Logger.WarnContext(ctx, shared.ErrInvalidIDFormat, "client_id", clientID)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidIDFormat,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Check if client exists
	client, err := h.AccountService.GetClientByID(ctx, clientUUID)
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

	response.JSONResponse(w, http.StatusOK, response.APIResponse{
		Code:    http.StatusOK,
		Message: shared.MsgClientRetrieved,
		Status:  shared.StatusSuccess,
		Data: shared.ClientResponse{
			ID:             client.ID.String(),
			ClientID:       client.PublicID,
			ClientSecret:   client.Secret,
			Name:           client.Name,
			Description:    client.Description,
			RedirectURIs:   client.RedirectURIs,
			IsConfidential: client.IsConfidential,
			LogoURI:        client.LogoURI,
		},
	})
}
