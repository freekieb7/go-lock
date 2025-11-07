package clients

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/google/uuid"
)

// HandleUpdateClient handles PUT /api/v1/clients/{client_id}
func (h *Handler) HandleUpdateClient(w http.ResponseWriter, r *http.Request) {
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

	// Decode patch request
	var req shared.UpdateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.WarnContext(ctx, shared.ErrInvalidRequestBody, "error", err)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidRequestBody,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Apply updates
	if req.Name != "" {
		client.Name = req.Name
	}

	if req.Description != "" {
		client.Description = req.Description
	}

	// Handle redirect URIs with validation if provided
	if len(req.RedirectURIs) > 0 {
		var validRedirectURIs []string
		for _, uri := range req.RedirectURIs {
			trimmedURI := strings.TrimSpace(uri)
			if trimmedURI == "" {
				continue
			}
			// Basic URL validation
			if !strings.HasPrefix(trimmedURI, "http://") && !strings.HasPrefix(trimmedURI, "https://") {
				h.Logger.WarnContext(ctx, "Invalid redirect URI format", "uri", trimmedURI)
				response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
					Code:    http.StatusBadRequest,
					Message: shared.ErrValidRedirectURI,
					Status:  shared.StatusInvalidRequest,
				})
				return
			}
			validRedirectURIs = append(validRedirectURIs, trimmedURI)
		}

		if len(validRedirectURIs) == 0 {
			response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
				Code:    http.StatusBadRequest,
				Message: shared.ErrAtLeastOneValidURI,
				Status:  shared.StatusInvalidRequest,
			})
			return
		}

		client.RedirectURIs = validRedirectURIs
	}

	// Handle IsConfidential - only update if explicitly provided
	if req.IsConfidential != nil {
		client.IsConfidential = *req.IsConfidential
	}

	if req.LogoURI != "" {
		client.LogoURI = req.LogoURI
	}

	// Save updated client
	updatedClient, err := h.AccountService.UpdateClient(ctx, client)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to update client", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	response.JSONResponse(w, http.StatusOK, response.APIResponse{
		Code:    http.StatusOK,
		Message: shared.MsgClientUpdated,
		Status:  shared.StatusSuccess,
		Data: shared.ClientResponse{
			ID:             updatedClient.ID.String(),
			ClientID:       updatedClient.PublicID,
			ClientSecret:   updatedClient.Secret,
			Name:           updatedClient.Name,
			Description:    updatedClient.Description,
			RedirectURIs:   updatedClient.RedirectURIs,
			IsConfidential: updatedClient.IsConfidential,
			LogoURI:        updatedClient.LogoURI,
		},
	})
}
