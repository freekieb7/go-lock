package handler

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/config"
	"github.com/freekieb7/go-lock/internal/oauth"
	"github.com/freekieb7/go-lock/internal/session"
	"github.com/freekieb7/go-lock/internal/web/middleware"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/google/uuid"
)

const (
	errOAuthServerError            = "server_error"
	errOAuthInvalidRequest         = "invalid_request"
	errOAuthInvalidClient          = "invalid_client"
	errOAuthInvalidGrant           = "invalid_grant"
	errOAuthUnauthorizedClient     = "unauthorized_client"
	errOAuthUnsupportedGrantType   = "unsupported_grant_type"
	errOAuthTemporarilyUnavailable = "temporarily_unavailable"
)

type AuthorizationErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type AuthorizationCodeTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    uint32 `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

type ClientCredentialsTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   uint32 `json:"expires_in"`
}

type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    uint32 `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

type OAuthHandler struct {
	Config         *config.Config
	Logger         *slog.Logger
	AccountService *account.Service
	OAuthService   *oauth.Service
	SessionStore   *session.Store
	OpenIDHandler  *oauth.OpenIDHandler
}

func NewOAuthHandler(cfg *config.Config, logger *slog.Logger, accountService *account.Service, oauthService *oauth.Service, sessionStore *session.Store, openIDHandler *oauth.OpenIDHandler) OAuthHandler {
	return OAuthHandler{
		Config:         cfg,
		Logger:         logger,
		AccountService: accountService,
		OAuthService:   oauthService,
		SessionStore:   sessionStore,
		OpenIDHandler:  openIDHandler,
	}
}

func (h *OAuthHandler) RegisterRoutes(mux *http.ServeMux) {
	// Create middleware based on rate limiting configuration
	var secureMiddleware func(http.Handler) http.Handler
	var publicAPIMiddleware func(http.Handler) http.Handler

	if h.Config.RateLimit.Enabled {
		// Initialize rate limiter
		rateLimiter := middleware.NewInMemoryRateLimiter()

		// OAuth endpoints have stricter limits
		oauthLimit := middleware.RateLimit{
			Requests: h.Config.RateLimit.OAuthRequests,
			Window:   h.Config.RateLimit.WindowDuration,
			KeyFunc:  middleware.KeyByIP,
		}

		// Public endpoints have more relaxed limits
		publicLimit := middleware.RateLimit{
			Requests: h.Config.RateLimit.PublicRequests,
			Window:   h.Config.RateLimit.WindowDuration,
			KeyFunc:  middleware.KeyByIP,
		}

		// Apply security middleware with rate limiting
		secureMiddleware = middleware.SecureMiddlewareWithRateLimit(rateLimiter, oauthLimit)
		publicAPIMiddleware = middleware.Chain(
			middleware.PublicAPIMiddleware(),
			middleware.RateLimitMiddleware(rateLimiter, publicLimit),
		)
	} else {
		// Apply standard security middleware without rate limiting
		secureMiddleware = middleware.SecureMiddleware()
		publicAPIMiddleware = middleware.PublicAPIMiddleware()
	}

	sessionMiddleware := middleware.Session(h.Config, h.Logger, h.SessionStore)

	// OAuth endpoints
	mux.Handle("/oauth/authorize", secureMiddleware(sessionMiddleware(http.HandlerFunc(h.HandleAuthorize))))
	mux.Handle("/oauth/token", secureMiddleware(http.HandlerFunc(h.HandleToken)))
	mux.Handle("/oauth/revoke", secureMiddleware(sessionMiddleware(http.HandlerFunc(h.HandleRevoke))))
	// OpenID Connect endpoints (public APIs that need CORS support)
	mux.Handle("/.well-known/openid-configuration", publicAPIMiddleware(http.HandlerFunc(h.OpenIDHandler.HandleWellKnownConfiguration)))
	mux.Handle("/.well-known/jwks.json", publicAPIMiddleware(http.HandlerFunc(h.OpenIDHandler.HandleJWKS)))
}

func (h *OAuthHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	sess, ok := r.Context().Value(session.ContextKey).(session.Session)
	if !ok {
		h.Logger.ErrorContext(ctx, "Session not found in context")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Parse query parameters
	queryParams := r.URL.Query()
	clientPublicID := queryParams.Get("client_id")
	redirectURI := queryParams.Get("redirect_uri")
	responseType := queryParams.Get("response_type")
	scope := queryParams.Get("scope")
	state := queryParams.Get("state")
	codeChallenge := queryParams.Get("code_challenge")
	codeChallengeMethod := queryParams.Get("code_challenge_method")
	consentApproved := queryParams.Get("consent") == "approved"

	scopes := strings.Fields(scope)

	// Validate authorization request
	if responseType != "code" {
		h.Logger.WarnContext(ctx, "Unsupported response_type", "response_type", responseType)
		response.Redirect(w, http.StatusSeeOther, redirectURI+"?error=unsupported_response_type&state="+url.QueryEscape(state))
		return
	}

	// Check if client exists and redirect URI is valid
	client, err := h.AccountService.GetClientByPublicID(ctx, clientPublicID)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to retrieve client", "error", err)
		response.Redirect(w, http.StatusSeeOther, redirectURI+"?error=invalid_client&state="+url.QueryEscape(state))
		return
	}

	// Check if user is authenticated first
	if sess.UserID == uuid.Nil {
		// Store the authorization request in session instead of using return_to
		// This avoids URL length issues and parameter pollution with PKCE
		authRequest := oauth.AuthorizationRequest{
			ClientID:            client.ID,
			RedirectURI:         redirectURI,
			ResponseType:        responseType,
			Scopes:              scopes,
			State:               state,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			OriginalURL:         r.URL.String(),
		}

		sess.Data["pending_auth_request"] = authRequest
		_, err := h.SessionStore.SaveSession(ctx, sess)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to save session with auth request", "error", err)
			response.Redirect(w, http.StatusSeeOther, redirectURI+"?error=server_error&state="+url.QueryEscape(state))
			return
		}

		// Redirect to login without the complex OAuth parameters
		response.Redirect(w, http.StatusSeeOther, "/login")
		return
	}

	// Check if redirect URI is valid
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		h.Logger.WarnContext(ctx, "Invalid redirect URI", "redirect_uri", redirectURI)
		response.Redirect(w, http.StatusSeeOther, redirectURI+"?error=invalid_request&state="+url.QueryEscape(state))
		return
	}

	// Create and validate authorization request (includes PKCE validation)
	_, err = h.OAuthService.NewAuthorizationRequest(client.ID, redirectURI, responseType, scopes, state, codeChallenge, codeChallengeMethod, r.URL.String())
	if err != nil {
		h.Logger.ErrorContext(ctx, "Invalid authorization request", "error", err)
		response.Redirect(w, http.StatusSeeOther, redirectURI+"?error=invalid_request&state="+url.QueryEscape(state))
		return
	}

	// First: Check if user has permission for the requested scopes
	permittedScopes, err := h.OAuthService.GetUserPermittedScopes(ctx, sess.UserID, scopes)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to check user permissions", "error", err)
		response.Redirect(w, http.StatusSeeOther, redirectURI+"?error=server_error&state="+url.QueryEscape(state))
		return
	}

	// Check if user has permission for all requested scopes
	if len(permittedScopes) != len(scopes) {
		// Find which scopes are missing
		permittedSet := make(map[string]struct{})
		for _, scope := range permittedScopes {
			permittedSet[scope] = struct{}{}
		}

		var missingScopes []string
		for _, scope := range scopes {
			if _, ok := permittedSet[scope]; !ok {
				missingScopes = append(missingScopes, scope)
			}
		}

		h.Logger.WarnContext(ctx, "User lacks permission for requested scopes", "user_id", sess.UserID, "missing_scopes", missingScopes)
		response.Redirect(w, http.StatusSeeOther, redirectURI+"?error=invalid_scope&state="+url.QueryEscape(state))
		return
	}

	// Note: In authorization code flow, user permissions are the primary gate.
	// Client scope restrictions are primarily used for client credentials flow.
	// For authorization code flow, if the user has permission and grants consent,
	// that should be sufficient authorization.

	// Check if user has already granted all requested scopes to this client
	// Skip this check if consent was already approved (coming back from consent screen)
	if !consentApproved {
		ungrantedScopes, err := h.OAuthService.GetUngrantedScopes(ctx, sess.UserID, client.ID, scopes)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to check granted scopes", "error", err)
			response.Redirect(w, http.StatusSeeOther, redirectURI+"?error=server_error&state="+url.QueryEscape(state))
			return
		}

		// If there are ungranted scopes, redirect to consent screen
		if len(ungrantedScopes) > 0 {
			// Store authorization request in session for consent flow
			authRequest := oauth.AuthorizationRequest{
				ClientID:            client.ID,
				RedirectURI:         redirectURI,
				ResponseType:        responseType,
				Scopes:              ungrantedScopes, // Only show ungranted scopes
				State:               state,
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: codeChallengeMethod,
				OriginalURL:         r.URL.String(),
			}

			if sess.Data == nil {
				sess.Data = make(map[string]any)
			}
			sess.Data["authorization_request"] = authRequest
			_, err := h.SessionStore.SaveSession(ctx, sess)
			if err != nil {
				h.Logger.ErrorContext(ctx, "Failed to save session with authorization request", "error", err)
				response.Redirect(w, http.StatusSeeOther, redirectURI+"?error=server_error&state="+url.QueryEscape(state))
				return
			}

			response.Redirect(w, http.StatusSeeOther, "/consent")
			return
		}
	}

	// All scopes are already granted, generate authorization code directly
	authCode, err := h.OAuthService.NewAuthorizationCode(client.ID, sess.UserID, scopes, redirectURI, codeChallenge, codeChallengeMethod)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to create authorization code", "error", err)
		response.Redirect(w, http.StatusSeeOther, redirectURI+"?error=server_error&state="+url.QueryEscape(state))
		return
	}

	_, err = h.OAuthService.CreateAuthorizationCode(ctx, authCode)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to save authorization code", "error", err)
		response.Redirect(w, http.StatusSeeOther, redirectURI+"?error=server_error&state="+url.QueryEscape(state))
		return
	}

	// Redirect back to client with authorization code
	redirectURL := redirectURI + "?code=" + authCode.Code + "&state=" + url.QueryEscape(state)
	response.Redirect(w, http.StatusSeeOther, redirectURL)
}

// HandleToken processes OAuth token requests
func (h *OAuthHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		h.Logger.ErrorContext(ctx, "Failed to parse form", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	scope := r.FormValue("scope")
	scopes := strings.Fields(scope)

	// Check for Authorization header (Basic Auth)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Handle authorization header
		if after, ok := strings.CutPrefix(authHeader, "Basic "); ok {
			// Decode client credentials
			credentials, err := base64.StdEncoding.DecodeString(after)
			if err != nil {
				h.Logger.WarnContext(ctx, "failed to decode authorization header", "error", err)
				response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
					Error:            errOAuthInvalidRequest,
					ErrorDescription: "Failed to decode authorization header",
				})
				return
			}

			parts := strings.SplitN(string(credentials), ":", 2)
			if len(parts) != 2 {
				h.Logger.Warn("invalid authorization header format")
				response.JSONResponse(w, http.StatusUnauthorized, TokenErrorResponse{
					Error:            errOAuthInvalidClient,
					ErrorDescription: "Invalid client credentials",
				})
				return
			}

			clientID = parts[0]
			clientSecret = parts[1]
		}
	}

	if clientID == "" {
		response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
			Error:            errOAuthInvalidRequest,
			ErrorDescription: "Missing client_id",
		})
		return
	}

	switch grantType {
	case "authorization_code":
		// Handle authorization code grant (PKCE flow)
		code := r.FormValue("code")
		codeVerifier := r.FormValue("code_verifier")

		if code == "" {
			response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
				Error:            errOAuthInvalidRequest,
				ErrorDescription: "Missing code",
			})
			return
		}

		if codeVerifier == "" {
			response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
				Error:            errOAuthInvalidRequest,
				ErrorDescription: "Missing code_verifier",
			})
			return
		}

		// Get authorization code
		authCode, err := h.OAuthService.GetAuthorizationCodeByCode(ctx, code)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to retrieve authorization code", "error", err)
			response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
				Error:            errOAuthInvalidGrant,
				ErrorDescription: "Invalid authorization code",
			})
			return
		}

		// Verify client ID matches
		client, err := h.AccountService.GetClientByPublicID(ctx, clientID)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to retrieve client", "error", err)
			response.JSONResponse(w, http.StatusUnauthorized, TokenErrorResponse{
				Error:            errOAuthInvalidClient,
				ErrorDescription: "Invalid client",
			})
			return
		}

		if authCode.ClientID != client.ID {
			h.Logger.WarnContext(ctx, "Client ID mismatch", "expected", authCode.ClientID, "actual", client.ID)
			response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
				Error:            errOAuthInvalidGrant,
				ErrorDescription: "Client ID mismatch",
			})
			return
		}

		// Verify PKCE code verifier
		if err := oauth.VerifyCodeChallenge(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
			h.Logger.WarnContext(ctx, "PKCE verification failed", "error", err)
			response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
				Error:            errOAuthInvalidGrant,
				ErrorDescription: "Invalid code verifier",
			})
			return
		}

		// Generate access token
		accessToken, err := h.OAuthService.NewAccessToken(client.ID, authCode.UserID, authCode.Scopes)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to generate access token", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
				Error:            errOAuthServerError,
				ErrorDescription: "Failed to generate access token",
			})
			return
		}

		var expiresIn uint32 = 3600 // 1 hour expiry

		// Save access token
		accessToken, err = h.OAuthService.SaveAccessToken(ctx, accessToken, expiresIn)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to save access token", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
				Error:            errOAuthServerError,
				ErrorDescription: "Failed to save access token",
			})
			return
		}

		// Generate and save refresh token
		refreshToken, err := h.OAuthService.NewRefreshToken(client.ID, authCode.UserID, authCode.Scopes)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to generate refresh token", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
				Error:            errOAuthServerError,
				ErrorDescription: "Failed to generate refresh token",
			})
			return
		}

		refreshToken, err = h.OAuthService.CreateRefreshToken(ctx, refreshToken)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to save refresh token", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
				Error:            errOAuthServerError,
				ErrorDescription: "Failed to save refresh token",
			})
			return
		}

		// Delete the authorization code (one-time use)
		if err := h.OAuthService.DeleteAuthorizationCode(ctx, code); err != nil {
			h.Logger.ErrorContext(ctx, "Failed to delete authorization code", "error", err)
			// Don't fail the request, but log the error
		}

		// Generate ID token if openid scope is requested
		var idToken string
		if slices.Contains(authCode.Scopes, "openid") {
			// Get user information for ID token
			user, err := h.AccountService.GetUserByID(ctx, authCode.UserID)
			if err != nil {
				h.Logger.ErrorContext(ctx, "Failed to get user for ID token", "error", err)
				response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
					Error:            errOAuthServerError,
					ErrorDescription: "Failed to generate ID token",
				})
				return
			}

			// Get signing key from JWKS service
			signingKey, err := h.OpenIDHandler.GetSigningKey(ctx)
			if err != nil {
				h.Logger.ErrorContext(ctx, "Failed to get signing key for ID token", "error", err)
				response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
					Error:            errOAuthServerError,
					ErrorDescription: "Failed to generate ID token",
				})
				return
			}

			// Generate ID token with empty nonce for now (can be enhanced later)
			idToken, err = h.OAuthService.GenerateIDToken(ctx, user, client, authCode.Scopes, "", signingKey, h.OpenIDHandler.GetIssuer())
			if err != nil {
				h.Logger.ErrorContext(ctx, "Failed to generate ID token", "error", err)
				response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
					Error:            errOAuthServerError,
					ErrorDescription: "Failed to generate ID token",
				})
				return
			}
		}

		// Respond with token
		response.JSONResponse(w, http.StatusOK, AuthorizationCodeTokenResponse{
			AccessToken:  accessToken.Token,
			TokenType:    "Bearer",
			ExpiresIn:    expiresIn,
			RefreshToken: refreshToken.Token,
			IDToken:      idToken,
		})
	case "client_credentials":
		// Handle client credentials grant
		if clientSecret == "" {
			response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
				Error:            errOAuthInvalidRequest,
				ErrorDescription: "Missing client_secret",
			})
			return
		}

		// Validate client credentials
		client, err := h.AccountService.GetClientByPublicID(ctx, clientID)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to retrieve client", "error", err)
			response.JSONResponse(w, http.StatusUnauthorized, TokenErrorResponse{
				Error:            errOAuthInvalidClient,
				ErrorDescription: "Invalid client credentials",
			})
			return
		}

		if client.Secret != clientSecret {
			h.Logger.WarnContext(ctx, "Invalid client secret", "client_id", clientID)
			response.JSONResponse(w, http.StatusUnauthorized, TokenErrorResponse{
				Error:            errOAuthInvalidClient,
				ErrorDescription: "Invalid client credentials",
			})
			return
		}

		// Check if client is confidential
		if !client.IsConfidential {
			h.Logger.WarnContext(ctx, "Client is not confidential", "client_id", clientID)
			response.JSONResponse(w, http.StatusUnauthorized, TokenErrorResponse{
				Error:            errOAuthInvalidClient,
				ErrorDescription: "Client is not confidential",
			})
			return
		}

		// Validate requested scopes
		grantedScopes := []string{}
		if len(scopes) > 0 {
			assignedScopes, err := h.OAuthService.GetScopesByAccountID(ctx, client.ID)
			if err != nil {
				h.Logger.ErrorContext(ctx, "Failed to retrieve client scopes", "error", err)
				response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
					Error:            errOAuthServerError,
					ErrorDescription: "Failed to retrieve client scopes",
				})
				return
			}

			assignedScopeSet := make(map[string]struct{})
			for _, s := range assignedScopes {
				assignedScopeSet[s] = struct{}{}
			}

			for _, requestedScope := range scopes {
				if _, ok := assignedScopeSet[requestedScope]; !ok {
					// Register but ignore requested scope not assigned to client
					h.Logger.WarnContext(ctx, "Requested scope not assigned to client", "client_id", clientID, "scope", requestedScope)
					continue
				}
				grantedScopes = append(grantedScopes, requestedScope)
			}
		}

		// Generate token
		accessToken, err := h.OAuthService.NewAccessToken(client.ID, client.ID, grantedScopes)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to generate access token", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
				Error:            errOAuthServerError,
				ErrorDescription: "Failed to generate access token",
			})
			return
		}

		var expiresIn uint32 = 3600 // 1 hour expiry

		// Save token
		accessToken, err = h.OAuthService.SaveAccessToken(ctx, accessToken, expiresIn)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to save access token", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
				Error:            errOAuthServerError,
				ErrorDescription: "Failed to save access token",
			})
			return
		}

		// Respond with token
		response.JSONResponse(w, http.StatusOK, ClientCredentialsTokenResponse{
			AccessToken: accessToken.Token,
			TokenType:   "Bearer",
			ExpiresIn:   expiresIn,
		})

	case "refresh_token":
		// Handle refresh token grant
		refreshTokenValue := r.FormValue("refresh_token")
		if refreshTokenValue == "" {
			response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
				Error:            errOAuthInvalidRequest,
				ErrorDescription: "Missing refresh_token",
			})
			return
		}

		// Check for refresh token replay attack
		isReplay, refreshToken, err := h.OAuthService.CheckRefreshTokenReplay(ctx, refreshTokenValue)
		if err != nil {
			if err == oauth.ErrRefreshTokenNotFound {
				h.Logger.WarnContext(ctx, "Refresh token not found", "token", refreshTokenValue)
				response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
					Error:            errOAuthInvalidGrant,
					ErrorDescription: "Invalid refresh token",
				})
				return
			}
			h.Logger.ErrorContext(ctx, "Failed to check refresh token", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
				Error:            errOAuthServerError,
				ErrorDescription: "Failed to check refresh token",
			})
			return
		}

		// If token has been used before, it's a replay attack - revoke the entire chain
		if isReplay {
			h.Logger.WarnContext(ctx, "Refresh token replay attack detected", "token", refreshTokenValue, "chain_id", refreshToken.ChainID)

			// Revoke entire refresh token chain for security
			if err := h.OAuthService.RevokeRefreshTokenChain(ctx, refreshToken.ChainID); err != nil {
				h.Logger.ErrorContext(ctx, "Failed to revoke refresh token chain after replay attack", "error", err)
			}

			response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
				Error:            errOAuthInvalidGrant,
				ErrorDescription: "Refresh token has been compromised",
			})
			return
		}

		// Check if token is expired
		if time.Now().After(refreshToken.ExpiresAt) {
			h.Logger.WarnContext(ctx, "Refresh token expired", "token", refreshTokenValue)
			response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
				Error:            errOAuthInvalidGrant,
				ErrorDescription: "Refresh token expired",
			})
			return
		}

		// Verify client ID matches
		client, err := h.AccountService.GetClientByPublicID(ctx, clientID)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to retrieve client", "error", err)
			response.JSONResponse(w, http.StatusUnauthorized, TokenErrorResponse{
				Error:            errOAuthInvalidClient,
				ErrorDescription: "Invalid client",
			})
			return
		}

		if refreshToken.ClientID != client.ID {
			h.Logger.WarnContext(ctx, "Client ID mismatch for refresh token", "expected", refreshToken.ClientID, "actual", client.ID)
			response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
				Error:            errOAuthInvalidGrant,
				ErrorDescription: "Client ID mismatch",
			})
			return
		}

		// Check if client credentials are valid for confidential clients
		if client.IsConfidential {
			if clientSecret == "" {
				response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
					Error:            errOAuthInvalidRequest,
					ErrorDescription: "Missing client_secret for confidential client",
				})
				return
			}
			if client.Secret != clientSecret {
				h.Logger.WarnContext(ctx, "Invalid client secret for refresh token", "client_id", clientID)
				response.JSONResponse(w, http.StatusUnauthorized, TokenErrorResponse{
					Error:            errOAuthInvalidClient,
					ErrorDescription: "Invalid client credentials",
				})
				return
			}
		}

		// Generate new access token with the same scopes as the refresh token
		accessToken, err := h.OAuthService.NewAccessToken(client.ID, refreshToken.UserID, refreshToken.Scopes)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to generate access token from refresh token", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
				Error:            errOAuthServerError,
				ErrorDescription: "Failed to generate access token",
			})
			return
		}

		var expiresIn uint32 = 3600 // 1 hour expiry

		// Save new access token
		accessToken, err = h.OAuthService.SaveAccessToken(ctx, accessToken, expiresIn)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to save access token from refresh token", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
				Error:            errOAuthServerError,
				ErrorDescription: "Failed to save access token",
			})
			return
		}

		// Mark the current refresh token as used (for chain tracking)
		_, err = h.OAuthService.MarkRefreshTokenAsUsed(ctx, refreshTokenValue)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to mark refresh token as used", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
				Error:            errOAuthServerError,
				ErrorDescription: "Failed to process refresh token",
			})
			return
		}

		// Generate new refresh token as part of the same chain (rotation)
		newRefreshToken, err := h.OAuthService.NewRefreshTokenFromParent(refreshToken, refreshToken.Scopes)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to generate new refresh token", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
				Error:            errOAuthServerError,
				ErrorDescription: "Failed to generate refresh token",
			})
			return
		}

		newRefreshToken, err = h.OAuthService.CreateRefreshToken(ctx, newRefreshToken)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to save new refresh token", "error", err)
			response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
				Error:            errOAuthServerError,
				ErrorDescription: "Failed to save refresh token",
			})
			return
		}

		// Generate ID token if openid scope is requested
		var idToken string
		if slices.Contains(refreshToken.Scopes, "openid") {
			// Get user information for ID token
			user, err := h.AccountService.GetUserByID(ctx, refreshToken.UserID)
			if err != nil {
				h.Logger.ErrorContext(ctx, "Failed to get user for ID token in refresh", "error", err)
				response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
					Error:            errOAuthServerError,
					ErrorDescription: "Failed to generate ID token",
				})
				return
			}

			// Get client information for ID token
			client, err := h.AccountService.GetClientByID(ctx, refreshToken.ClientID)
			if err != nil {
				h.Logger.ErrorContext(ctx, "Failed to get client for ID token in refresh", "error", err)
				response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
					Error:            errOAuthServerError,
					ErrorDescription: "Failed to generate ID token",
				})
				return
			}

			// Get signing key from JWKS service
			signingKey, err := h.OpenIDHandler.GetSigningKey(ctx)
			if err != nil {
				h.Logger.ErrorContext(ctx, "Failed to get signing key for ID token in refresh", "error", err)
				response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
					Error:            errOAuthServerError,
					ErrorDescription: "Failed to generate ID token",
				})
				return
			}

			// Generate ID token
			idToken, err = h.OAuthService.GenerateIDToken(ctx, user, client, refreshToken.Scopes, "", signingKey, h.OpenIDHandler.GetIssuer())
			if err != nil {
				h.Logger.ErrorContext(ctx, "Failed to generate ID token in refresh", "error", err)
				response.JSONResponse(w, http.StatusInternalServerError, TokenErrorResponse{
					Error:            errOAuthServerError,
					ErrorDescription: "Failed to generate ID token",
				})
				return
			}
		}

		// Respond with new tokens
		response.JSONResponse(w, http.StatusOK, RefreshTokenResponse{
			AccessToken:  accessToken.Token,
			TokenType:    "Bearer",
			ExpiresIn:    expiresIn,
			RefreshToken: newRefreshToken.Token,
			IDToken:      idToken,
		})

	default:
		h.Logger.ErrorContext(r.Context(), "Unsupported grant type", "grant_type", grantType)
		response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
			Error:            errOAuthUnsupportedGrantType,
			ErrorDescription: "Unsupported grant type",
		})
	}
}

// HandleRevoke processes token revocation and session logout requests
func (h *OAuthHandler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Only accept POST requests for revocation
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.Logger.ErrorContext(ctx, "Failed to parse revoke form", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Handle logout action (session revocation)
	action := r.FormValue("action")
	if action == "logout" {
		h.handleSessionRevocation(w, r)
		return
	}

	// Handle OAuth token revocation
	if token != "" {
		h.handleTokenRevocation(w, r, token, tokenTypeHint, clientID, clientSecret)
		return
	}

	// If no token provided and no logout action, return bad request
	response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
		Error:            errOAuthInvalidRequest,
		ErrorDescription: "Missing token parameter",
	})
}

// handleSessionRevocation handles user logout by destroying the session
func (h *OAuthHandler) handleSessionRevocation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get session from context
	sess, ok := ctx.Value(session.ContextKey).(session.Session)
	if !ok {
		h.Logger.WarnContext(ctx, "No session found in context for logout")
		// Even if no session, return success for security (don't leak session state)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Logged out"))
		return
	}

	// Delete the session
	if err := h.SessionStore.DeleteSession(ctx, sess.Token); err != nil {
		h.Logger.ErrorContext(ctx, "Failed to delete session", "error", err, "session_token", sess.Token)
		// Still return success to avoid leaking internal errors
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Logged out"))
		return
	}

	// Clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     session.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.Config.Server.IsProduction(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete the cookie
	})

	h.Logger.InfoContext(ctx, "User logged out successfully", "session_token", sess.Token)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged out"))
}

// handleTokenRevocation handles OAuth token revocation (RFC 7009)
func (h *OAuthHandler) handleTokenRevocation(w http.ResponseWriter, r *http.Request, token, tokenTypeHint, clientID, clientSecret string) {
	ctx := r.Context()

	// Authenticate client if credentials provided
	if clientID != "" {
		client, err := h.AccountService.GetClientByPublicID(ctx, clientID)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Invalid client ID for token revocation", "client_id", clientID)
			response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
				Error:            errOAuthInvalidClient,
				ErrorDescription: "Invalid client credentials",
			})
			return
		}

		if clientSecret != client.Secret {
			h.Logger.WarnContext(ctx, "Invalid client secret for token revocation", "client_id", clientID)
			response.JSONResponse(w, http.StatusBadRequest, TokenErrorResponse{
				Error:            errOAuthInvalidClient,
				ErrorDescription: "Invalid client credentials",
			})
			return
		}
	}

	// Try to revoke the token based on the hint or try both types
	var err error
	revoked := false

	if tokenTypeHint == "refresh_token" || tokenTypeHint == "" {
		// Try revoking as refresh token first (if hinted or no hint)
		err = h.OAuthService.RevokeRefreshToken(ctx, token)
		if err == nil {
			revoked = true
			h.Logger.InfoContext(ctx, "Refresh token revoked", "token_hint", tokenTypeHint)
		}
	}

	if !revoked && (tokenTypeHint == "access_token" || tokenTypeHint == "") {
		// Try revoking as access token
		err = h.OAuthService.RevokeAccessToken(ctx, token)
		if err == nil {
			revoked = true
			h.Logger.InfoContext(ctx, "Access token revoked", "token_hint", tokenTypeHint)
		}
	}

	// Per RFC 7009, revocation endpoint should return 200 even if token was invalid
	// This prevents information disclosure about token validity
	if revoked {
		h.Logger.InfoContext(ctx, "Token successfully revoked")
	} else {
		h.Logger.WarnContext(ctx, "Token revocation attempted for unknown/invalid token", "error", err)
	}

	w.WriteHeader(http.StatusOK)
}
