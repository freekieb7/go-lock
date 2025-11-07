package handler

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/config"
	"github.com/freekieb7/go-lock/internal/database"
	"github.com/freekieb7/go-lock/internal/oauth"
	"github.com/freekieb7/go-lock/internal/session"
	"github.com/freekieb7/go-lock/internal/web/middleware"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/freekieb7/go-lock/web"
	"github.com/google/uuid"
)

const (
	routeLogin   = "/login"
	routeLogout  = "/logout"
	routeConsent = "/consent"

	errLoginMissingFields      = "missing_fields"
	errLoginInvalidCredentials = "invalid_credentials"
	errLoginServerError        = "server_error"
)

type UIHandler struct {
	Config         *config.Config
	Logger         *slog.Logger
	SessionStore   *session.Store
	AccountService *account.Service
	OAuthService   *oauth.Service
}

func NewUIHandler(cfg *config.Config, logger *slog.Logger, db *database.Database, sessionStore *session.Store, accountService *account.Service, oauthService *oauth.Service) UIHandler {
	return UIHandler{
		Config:         cfg,
		Logger:         logger,
		SessionStore:   sessionStore,
		AccountService: accountService,
		OAuthService:   oauthService,
	}
}

func (h *UIHandler) RegisterRoutes(mux *http.ServeMux) {
	// Create middleware chain
	securityMiddleware := middleware.SecurityHeadersMiddleware()
	sessionMiddleware := middleware.Session(h.Config, h.Logger, h.SessionStore)
	csrfMiddleware := middleware.CSRF(h.Logger, h.SessionStore)
	authenticatedMiddleware := middleware.Authenticated(h.Logger)

	// Create middleware chains for different route types
	publicChain := middleware.Chain(securityMiddleware, sessionMiddleware, csrfMiddleware)
	protectedChain := middleware.Chain(securityMiddleware, sessionMiddleware, csrfMiddleware, authenticatedMiddleware)

	// Serve static files with security headers using embedded assets
	staticHandler := web.NewStaticHandler()
	mux.Handle("/static/", securityMiddleware(http.StripPrefix("/static/", staticHandler)))

	// Register routes with appropriate middleware chains
	mux.Handle(routeLogin, publicChain(http.HandlerFunc(h.HandleLogin)))
	mux.Handle(routeLogout, publicChain(http.HandlerFunc(h.HandleLogout)))
	mux.Handle(routeConsent, protectedChain(http.HandlerFunc(h.HandleConsent)))
}

func (h *UIHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.HandleLoginGet(w, r)
	case http.MethodPost:
		h.HandleLoginPost(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *UIHandler) HandleLoginGet(w http.ResponseWriter, r *http.Request) {
	sess, ok := r.Context().Value(session.ContextKey).(session.Session)
	if !ok {
		h.Logger.ErrorContext(r.Context(), "Session not found in context")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Check if user is already logged in
	if sess.UserID != uuid.Nil {
		// Check if there's a pending OAuth request first
		if _, exists := sess.Data["pending_auth_request"]; exists {
			// User is logged in and has pending OAuth request, redirect to consent
			http.Redirect(w, r, routeConsent, http.StatusSeeOther)
			return
		}
		// User already logged in, show success message
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Already logged in"))
		return
	}

	errMsg := r.URL.Query().Get("error")
	if errMsg != "" {
		switch errMsg {
		case errLoginMissingFields:
			errMsg = "Please fill in all required fields."
		case errLoginInvalidCredentials:
			errMsg = "Invalid email or password."
		case errLoginServerError:
			errMsg = "Internal server error. Please try again later."
		default:
			errMsg = "An unknown error occurred."
		}
	}

	csrfToken, ok := sess.Data["csrf_token"].(string)
	if !ok {
		h.Logger.ErrorContext(r.Context(), "Missing CSRF token in session")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("web/templates/base.html", "web/templates/login.html")
	if err != nil {
		h.Logger.ErrorContext(r.Context(), "Failed to parse login template", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, map[string]any{
		"CSRFToken": csrfToken,
		"Error":     errMsg,
	})
}

func (h *UIHandler) HandleLoginPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sess, ok := r.Context().Value(session.ContextKey).(session.Session)
	if !ok {
		h.Logger.ErrorContext(ctx, "Session not found in context")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		h.Logger.WarnContext(ctx, "Missing login form fields")
		response.Redirect(w, http.StatusSeeOther, routeLogin+"?error="+errLoginMissingFields)
		return
	}

	// CSRF token validation is handled by CSRFMiddleware, no need to validate again here
	h.Logger.InfoContext(ctx, "Login attempt", "email", email, "session_token", sess.Token)

	user, err := h.AccountService.AuthenticateUser(ctx, email, password)
	if err != nil {
		if err == account.ErrInvalidCredentials {
			h.Logger.WarnContext(ctx, "Invalid login credentials", "email", email)
			response.Redirect(w, http.StatusSeeOther, routeLogin+"?error="+errLoginInvalidCredentials)
			return
		}

		h.Logger.ErrorContext(ctx, "Failed to authenticate user", "error", err)
		response.Redirect(w, http.StatusSeeOther, routeLogin+"?error="+errLoginServerError)
		return
	}

	// Update session with user ID
	sess.UserID = user.ID
	sess, err = h.SessionStore.SaveSession(ctx, sess)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to save session", "error", err)
		response.Redirect(w, http.StatusSeeOther, routeLogin+"?error="+errLoginServerError)
		return
	}

	// Regenerate session token to prevent fixation
	sess, err = h.SessionStore.RegenerateSession(ctx, sess)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to regenerate session", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set new session token in response
	http.SetCookie(w, &http.Cookie{
		Name:     session.CookieName,
		Value:    sess.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.Config.Server.IsProduction(),
		SameSite: http.SameSiteLaxMode,
	})

	h.Logger.InfoContext(ctx, "User logged in successfully", "email", user.Email)

	// Check if there's a pending authorization request in session
	if _, exists := sess.Data["pending_auth_request"]; exists {
		h.Logger.InfoContext(ctx, "Found pending authorization request, redirecting to consent")
		response.Redirect(w, http.StatusSeeOther, routeConsent)
		return
	}

	// No pending OAuth request, login successful
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful"))
}

func (h *UIHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get session from context (may not exist if already logged out)
	sess, ok := ctx.Value(session.ContextKey).(session.Session)
	if ok && sess.Token != "" {
		// Delete the session from the database
		if err := h.SessionStore.DeleteSession(ctx, sess.Token); err != nil {
			h.Logger.ErrorContext(ctx, "Failed to delete session during logout", "error", err)
			// Continue anyway, we'll clear the cookie
		}
		h.Logger.InfoContext(ctx, "Session deleted during logout", "session_token", sess.Token)
	}

	// Clear the session cookie regardless of session state
	http.SetCookie(w, &http.Cookie{
		Name:     session.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.Config.Server.IsProduction(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete the cookie
	})

	// Return success response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged out successfully"))
}

func (h *UIHandler) HandleConsent(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.HandleConsentGet(w, r)
	case http.MethodPost:
		h.HandleConsentPost(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *UIHandler) HandleConsentGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	h.Logger.InfoContext(ctx, "HandleConsentGet started")

	sess, ok := r.Context().Value(session.ContextKey).(session.Session)
	if !ok {
		h.Logger.ErrorContext(ctx, "Session not found in context")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h.Logger.InfoContext(ctx, "Session found", "session_id", sess.Token)
	errMsg := r.URL.Query().Get("error")

	var authorizationRequest oauth.AuthorizationRequest

	h.Logger.InfoContext(ctx, "Looking for authorization request in session")

	// Handle both direct struct and JSON-unmarshaled map types
	if authReq, ok := sess.Data["pending_auth_request"].(oauth.AuthorizationRequest); ok {
		// Direct struct type (unlikely after JSON round-trip)
		h.Logger.InfoContext(ctx, "Found direct authorization request struct")
		authorizationRequest = authReq
	} else if authReqData, exists := sess.Data["pending_auth_request"]; exists {
		h.Logger.InfoContext(ctx, "Found authorization request data, attempting to unmarshal", "data_type", fmt.Sprintf("%T", authReqData))
		// Convert via JSON marshaling/unmarshaling to handle map[string]interface{} -> struct
		authReqJSON, err := json.Marshal(authReqData)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to marshal authorization request data", "error", err, "data_type", fmt.Sprintf("%T", authReqData))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if err := json.Unmarshal(authReqJSON, &authorizationRequest); err != nil {
			h.Logger.ErrorContext(ctx, "Failed to unmarshal authorization request", "error", err, "json", string(authReqJSON))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

	} else {
		h.Logger.WarnContext(ctx, "No pending authorization request found in session")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	csrfToken, ok := sess.Data["csrf_token"].(string)
	if !ok {
		h.Logger.ErrorContext(ctx, "Missing CSRF token in session")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Get client information
	h.Logger.InfoContext(ctx, "Fetching client information", "client_id", authorizationRequest.ClientID)
	client, err := h.AccountService.GetClientByID(ctx, authorizationRequest.ClientID)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to get client information", "error", err, "client_id", authorizationRequest.ClientID)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	h.Logger.InfoContext(ctx, "Client information retrieved successfully", "client_name", client.Name)

	// Fetch scope names and descriptions
	h.Logger.InfoContext(ctx, "Fetching scope information", "scopes", authorizationRequest.Scopes)
	scopes, err := h.OAuthService.GetScopesByNames(ctx, authorizationRequest.Scopes)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to fetch scope names and descriptions", "error", err, "scopes", authorizationRequest.Scopes)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	h.Logger.InfoContext(ctx, "Scope information retrieved successfully", "scope_count", len(scopes))

	switch errMsg {
	case "":
		// No error message, proceed with consent
	default:
		errMsg = "Internal server error. Please try again later."
	}

	h.Logger.InfoContext(ctx, "Parsing consent template")
	tmpl, err := template.ParseFiles("web/templates/base.html", "web/templates/consent.html")
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to parse authorize template", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h.Logger.InfoContext(ctx, "Executing consent template")
	err = tmpl.Execute(w, map[string]any{
		"Error":     errMsg,
		"Scopes":    scopes,
		"CSRFToken": csrfToken,
		"Client":    client,
	})
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to execute consent template", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	h.Logger.InfoContext(ctx, "Consent template executed successfully")
}

func (h *UIHandler) HandleConsentPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
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

	action := r.FormValue("action")

	var authRequest oauth.AuthorizationRequest

	// Handle both direct struct and JSON-unmarshaled map types
	if authReq, ok := sess.Data["pending_auth_request"].(oauth.AuthorizationRequest); ok {
		// Direct struct type (unlikely after JSON round-trip)
		authRequest = authReq
	} else if authReqData, exists := sess.Data["pending_auth_request"]; exists {
		// Convert via JSON marshaling/unmarshaling to handle map[string]interface{} -> struct
		authReqJSON, err := json.Marshal(authReqData)
		if err != nil {
			h.Logger.ErrorContext(ctx, "Failed to marshal authorization request data", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := json.Unmarshal(authReqJSON, &authRequest); err != nil {
			h.Logger.ErrorContext(ctx, "Failed to unmarshal authorization request", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		h.Logger.ErrorContext(ctx, "Missing pending authorization request in session")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if action != "authorize" {
		if authRequest.RedirectURI != "" {
			response.Redirect(w, http.StatusSeeOther, authRequest.RedirectURI+"?error=access_denied&state="+url.QueryEscape(authRequest.State))
			return
		}

		w.WriteHeader(http.StatusForbidden)
		return
	}

	h.Logger.InfoContext(ctx, "User authorized OAuth client", "user_id", sess.UserID, "scopes", authRequest.Scopes)

	// Grant the newly consented scopes
	if err := h.OAuthService.GrantScopes(ctx, sess.UserID, authRequest.ClientID, authRequest.Scopes); err != nil {
		h.Logger.ErrorContext(ctx, "Failed to grant scopes", "error", err)
		if authRequest.RedirectURI != "" {
			response.Redirect(w, http.StatusSeeOther, authRequest.RedirectURI+"?error=server_error&state="+url.QueryEscape(authRequest.State))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Clear the authorization request from session since it's been processed
	delete(sess.Data, "pending_auth_request")
	sess, err := h.SessionStore.SaveSession(ctx, sess)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to save session", "error", err)
		// Continue anyway, this is not critical
	}

	// Now continue with the original authorization request by redirecting back to authorize endpoint
	// Parse the original URL to get all the original scopes (not just the ungranted ones)
	originalURL, err := url.Parse(authRequest.OriginalURL)
	if err != nil {
		h.Logger.ErrorContext(ctx, "Failed to parse original URL", "error", err)
		response.Redirect(w, http.StatusSeeOther, authRequest.RedirectURI+"?error=server_error&state="+url.QueryEscape(authRequest.State))
		return
	}

	// Add a parameter to indicate consent was approved to avoid infinite redirect
	query := originalURL.Query()
	query.Set("consent", "approved")
	originalURL.RawQuery = query.Encode()

	response.Redirect(w, http.StatusSeeOther, originalURL.String())
}
