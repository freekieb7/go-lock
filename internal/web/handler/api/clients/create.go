package clients

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
	"github.com/freekieb7/go-lock/internal/web/response"
)

// HandleCreateClient handles POST /api/v1/clients
func (h *Handler) HandleCreateClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req shared.CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.ErrorContext(ctx, "Failed to decode create client request", "error", err)
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrInvalidRequestBody,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Validate and sanitize input
	clientName := strings.TrimSpace(req.Name)
	if clientName == "" {
		h.Logger.WarnContext(ctx, "Missing client name")
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrNameRequired,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	clientDescription := strings.TrimSpace(req.Description)
	clientLogoURI := strings.TrimSpace(req.LogoURI)

	// Validate redirect URIs
	if len(req.RedirectURIs) == 0 {
		h.Logger.WarnContext(ctx, "Missing redirect URIs")
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrRedirectURIRequired,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	// Validate each redirect URI
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
		h.Logger.WarnContext(ctx, "No valid redirect URIs provided")
		response.JSONResponse(w, http.StatusBadRequest, response.APIResponse{
			Code:    http.StatusBadRequest,
			Message: shared.ErrAtLeastOneValidURI,
			Status:  shared.StatusInvalidRequest,
		})
		return
	}

	client, err := h.AccountService.NewClient(clientName, clientDescription, validRedirectURIs, req.IsConfidential, clientLogoURI)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to create new client", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	client, err = h.AccountService.CreateClient(ctx, client)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to create new client", "error", err)
		response.JSONResponse(w, http.StatusInternalServerError, response.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: shared.ErrInternalServer,
			Status:  shared.StatusError,
		})
		return
	}

	response.JSONResponse(w, http.StatusCreated, response.APIResponse{
		Code:    http.StatusCreated,
		Message: shared.MsgClientCreated,
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
