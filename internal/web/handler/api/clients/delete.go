package clients

import (
	"net/http"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/google/uuid"
)

// HandleDeleteClient handles DELETE /api/v1/clients/{client_id}
func (h *Handler) HandleDeleteClient(w http.ResponseWriter, r *http.Request) {
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

	// Delete the client
	if err := h.AccountService.DeleteClientByID(ctx, client.ID); err != nil {
		h.Logger.ErrorContext(ctx, "Failed to delete client", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
