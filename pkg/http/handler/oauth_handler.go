package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/local/model"
	"github.com/freekieb7/go-lock/pkg/data/local/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/jwt"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/freekieb7/go-lock/pkg/settings"
)

const (
	ErrCodeInvalidRequest = "invalid_request"
)

type OAuth2Handler struct {
	settings               *settings.Settings
	logging                *slog.Logger
	clientStore            *store.ClientStore
	apiStore               *store.ApiStore
	authorizationCodeStore *store.AuthorizationCodeStore
	redirectUriStore       *store.RedirectUriStore
	jwksStore              *store.JwksStore
}

func NewOAuth2Handler(
	settings *settings.Settings,
	logger *slog.Logger,
	clientStore *store.ClientStore,
	apiStore *store.ApiStore,
	authorizationCodeStore *store.AuthorizationCodeStore,
	redirectUriStore *store.RedirectUriStore,
	jwksStore *store.JwksStore,
) *OAuth2Handler {
	return &OAuth2Handler{
		settings,
		logger,
		clientStore,
		apiStore,
		authorizationCodeStore,
		redirectUriStore,
		jwksStore,
	}
}

func (handler *OAuth2Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if !r.URL.Query().Has("response_type") {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : response_type")
		return
	}
	responseTypeRaw := r.URL.Query().Get("response_type")

	// response_type "token" is also viable
	// https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/call-your-api-using-the-authorization-code-flow
	switch responseTypeRaw {
	case "code":
		{
			handler.authorizeByCode(w, r)
			return
		}
	case "token":
		{
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
	default:
		{
			encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid response type : %s", responseTypeRaw))
			return
		}
	}
}

func (handler *OAuth2Handler) authorizeByCode(w http.ResponseWriter, r *http.Request) {
	/// Step 1: Prepare
	// Get Client ID
	if !r.URL.Query().Has("client_id") {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : client_id")
		return
	}
	clientIdRaw := r.URL.Query().Get("client_id")

	// Get Audience
	if !r.URL.Query().Has("audience") {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : audience")
		return
	}
	audienceRaw := r.URL.Query().Get("audience")

	// Get Scope
	if !r.URL.Query().Has("scope") {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : scope")
		return
	}
	scopeRaw := r.URL.Query().Get("scope")

	// Get Redirect URI (optional, when 1 redirect uri exists)
	redirectUriRaw := r.URL.Query().Get("redirect_uri")

	// Get State (optional)
	stateRaw := r.URL.Query().Get("state")

	// Get Code Challenge
	codeChallengeRaw := r.URL.Query().Get("code_challenge")
	codeChallengeMethodRaw := r.URL.Query().Get("code_challenge_method")

	/// Step 2: Validate
	// Check client
	client, err := handler.clientStore.GetById(r.Context(), clientIdRaw)
	if err != nil {
		if errors.Is(err, store.ErrClientNotExists) {
			encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid client id : %s", clientIdRaw))
			return
		}

		panic(err)
	}

	// Check redirect uri
	knownUris, err := handler.redirectUriStore.AllByClientId(r.Context(), client.Id)
	if err != nil {
		panic(err)
	}

	if redirectUriRaw == "" {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : redirect_uri")
		return
	}

	// Search for a matching uri
	var redirectUri string
	for _, knownUri := range knownUris {
		if redirectUriRaw == knownUri.Uri {
			redirectUri = knownUri.Uri
			break
		}
	}

	// No matching uri's
	if redirectUri == "" {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid redirection uri %s", redirectUriRaw))
		return
	}

	// (optional) validate code challenge
	if codeChallengeRaw != "" || codeChallengeMethodRaw != "" {
		if codeChallengeMethodRaw != "S256" {
			encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Invalid code challenge method : S256")
			return
		}

		if codeChallengeRaw == "" {
			encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid code challenge method : %s", codeChallengeRaw))
			return
		}
	}

	/// STEP 3 : Create Auth Code
	authorizationCode := model.AuthorizationCode{
		ClientId:      client.Id,
		Code:          random.NewString(32),
		Audience:      audienceRaw,
		Scope:         scopeRaw,
		CodeChallenge: codeChallengeRaw,
	}
	if err := handler.authorizationCodeStore.Create(r.Context(), authorizationCode); err != nil {
		panic(err)
	}

	location := fmt.Sprintf("%s?code=%s", redirectUri, authorizationCode.Code)
	if stateRaw != "" {
		location += fmt.Sprintf("&state=%s", stateRaw)
	}

	w.Header().Add("Location", location)
	w.WriteHeader(http.StatusFound)
}

type TokenResponse struct {
	AccessToken string  `json:"access_token"`
	TokenType   string  `json:"token_type"`
	ExpiresIn   float64 `json:"expires_in"`
}

func (handler *OAuth2Handler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()

	if !r.Form.Has("grant_type") {
		encoding.EncodeError(w, r, http.StatusNotImplemented, ErrCodeInvalidRequest, "Required param : grant_type")
		return
	}
	grantTypeRaw := r.Form.Get("grant_type")

	switch grantTypeRaw {
	case "client_credentials":
		{
			handler.tokenByClientCredentials(w, r)
		}
	case "authorization_code":
		{
			handler.tokenByAuthorizationCode(w, r)
		}
	default:
		{
			encoding.EncodeError(w, r, http.StatusNotImplemented, ErrCodeInvalidRequest, fmt.Sprintf("Unsupported grant type : %s", grantTypeRaw))
		}
	}
}

func (handler *OAuth2Handler) tokenByClientCredentials(w http.ResponseWriter, r *http.Request) {
	if !r.Form.Has("client_id") {
		encoding.EncodeError(w, r, http.StatusNotImplemented, ErrCodeInvalidRequest, "Required param : client_id")
		return
	}
	clientIdRaw := r.Form.Get("client_id")

	if !r.Form.Has("client_secret") {
		encoding.EncodeError(w, r, http.StatusNotImplemented, ErrCodeInvalidRequest, "Required param : client_secret")
		return
	}
	clientSecretRaw := r.Form.Get("client_secret")

	if !r.Form.Has("audience") {
		encoding.EncodeError(w, r, http.StatusNotImplemented, ErrCodeInvalidRequest, "Required param : audience")
		return
	}
	audienceRaw := r.Form.Get("audience")

	client, err := handler.clientStore.GetById(r.Context(), clientIdRaw)

	if err != nil {
		if errors.Is(err, store.ErrClientNotExists) {
			encoding.EncodeError(w, r, http.StatusNotImplemented, ErrCodeInvalidRequest, fmt.Sprintf("Invalid client credentials : %s <secret>", clientIdRaw))
			return
		}

		panic(err)
	}

	if base64.RawURLEncoding.EncodeToString(client.Secret) != clientSecretRaw {
		encoding.EncodeError(w, r, http.StatusNotImplemented, ErrCodeInvalidRequest, fmt.Sprintf("Invalid client credentials : %s <secret>", clientIdRaw))
		return
	}

	_, err = handler.apiStore.GetByUri(r.Context(), audienceRaw)
	if err != nil {
		if errors.Is(err, store.ErrApiNotExists) {
			encoding.EncodeError(w, r, http.StatusNotImplemented, ErrCodeInvalidRequest, fmt.Sprintf("Invalid audience : %s", audienceRaw))
			return
		}

		panic(err)
	}

	// Step 3 : Create tokens
	jwkSets, err := handler.jwksStore.All(r.Context())
	if err != nil {
		panic(err)
	}

	if len(jwkSets) < 1 {
		panic(err)
	}

	jwks := jwkSets[len(jwkSets)-1] // Take last

	privateKey, err := jwt.ParseRsaPrivateKey(jwks.PrivateKey)
	if err != nil {
		panic(err)
	}

	now := time.Now().UTC()
	expiresIn := time.Hour

	signedToken, err := jwt.Encode(jwt.Token{
		Header: map[string]any{
			"typ": "JWT",
			"alg": "RS256",
			"kid": jwks.Id,
		},
		Payload: map[string]any{
			"iss": handler.settings.Host,
			"sub": "TODO some user",
			"exp": now.Add(expiresIn).Unix(),
			"iat": now.Unix(),
			"nbf": now.Unix(),
		},
	}, privateKey)
	if err != nil {
		panic(err)
	}

	encoding.Encode(w, r, http.StatusOK, TokenResponse{
		AccessToken: signedToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn.Seconds(),
	})
}

func (handler *OAuth2Handler) tokenByAuthorizationCode(w http.ResponseWriter, r *http.Request) {

	panic(errors.New("test"))

	var (
		clientIdRaw     string
		clientSecretRaw string
	)

	if !r.Form.Has("code") {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : code")
		return
	}
	codeRaw := r.Form.Get("code")

	if !r.Form.Has("redirect_uri") {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : redirect_uri")
		return
	}
	redirectUriRaw := r.Form.Get("redirect_uri")

	if !r.Form.Has("audience") {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : audience")
		return
	}
	audienceRaw := r.Form.Get("audience")

	if !r.Form.Has("scope") {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : scope")
		return
	}
	scopeRaw := r.Form.Get("scope")

	// Authorization Code
	if r.Form.Has("client_id") {
		// Credentials are in form
		clientIdRaw = r.Form.Get("client_id")
		clientSecretRaw = r.Form.Get("client_secret")
	} else if r.Header.Get("Authorization") != "" {
		// Credentials are in header
		authorizationHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorizationHeader, "Basic ") {
			encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Invalid authorization header")
			return
		}

		authorizationHeaderParts := strings.Split(authorizationHeader, " ")
		if len(authorizationHeaderParts) != 2 {
			encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Invalid authorization header")
			return
		}

		base64ClientCredentials := authorizationHeaderParts[1]
		clientCredentials, err := base64.StdEncoding.DecodeString(base64ClientCredentials)
		if err != nil {
			panic(err)
		}

		clientCredentialParts := strings.Split(string(clientCredentials), ":")
		if len(clientCredentialParts) != 2 {
			encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Invalid authorization header")
			return
		}

		clientIdRaw = clientCredentialParts[0]
		clientSecretRaw = clientCredentialParts[1]
	} else {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : client_id")
		return
	}

	// Get client based on credentials or code
	var client *model.Client
	if r.Form.Has("code_verifier") {
		// Get client by secret
		codeVerifierRaw := r.Form.Get("code_verifier")

		authorizationCode, err := handler.authorizationCodeStore.Get(r.Context(), clientIdRaw, codeRaw)
		if err != nil {
			if errors.Is(err, store.ErrAuthorizationCodeNotExists) {
				encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid code : %s", codeRaw))
				return
			}

			panic(err)
		}

		// Validate Code verifier
		hasher := sha256.New()
		hasher.Write([]byte(codeVerifierRaw))
		codeChallengeGenerated := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
		if codeChallengeGenerated != authorizationCode.CodeChallenge {
			encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid code verifier : %s", codeVerifierRaw))
			return
		}

		// After code validation, get client
		client, err = handler.clientStore.GetById(r.Context(), clientIdRaw)
		if err != nil {
			if errors.Is(err, store.ErrClientNotExists) {
				encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid client credentials : %s", client.Id))
				return
			}

			panic(err)
		}
	} else {
		// Get client by secret
		if clientSecretRaw == "" {
			encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : client_secret")
			return
		}

		var err error
		client, err = handler.clientStore.GetById(r.Context(), clientIdRaw)
		if err != nil {
			if errors.Is(err, store.ErrClientNotExists) {
				encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid client credentials : %s", client.Id))
				return
			}

			panic(err)
		}

		if base64.RawURLEncoding.EncodeToString(client.Secret) != clientSecretRaw {
			encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid client credentials : %s", client.Id))
			return
		}
	}

	// Validate redirect uri
	redirectUris, err := handler.redirectUriStore.AllByClientId(r.Context(), client.Id)
	if err != nil {
		panic(err)
	}

	if redirectUriRaw == "" {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : redirect uri")
		return
	}

	found := false
	for _, redirectUri := range redirectUris {
		if redirectUriRaw == redirectUri.Uri {
			found = true
			break
		}
	}

	if !found {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid redirect uri : %s", redirectUriRaw))
		return
	}

	// Validate audience
	scope := scopeRaw

	// Validate scopes
	audience := audienceRaw

	// Step 3 : Create tokens
	jwkSets, err := handler.jwksStore.All(r.Context())
	if err != nil {
		panic(err)
	}

	if len(jwkSets) < 1 {
		panic(err)
	}

	jwks := jwkSets[len(jwkSets)-1] // Take last

	privateKey, err := jwt.ParseRsaPrivateKey(jwks.PrivateKey)
	if err != nil {
		panic(err)
	}

	now := time.Now().UTC()
	expiresIn := time.Hour
	token := jwt.Token{
		Header: map[string]any{
			"kid": jwks.Id,
		},
		Payload: map[string]any{
			"iss":   handler.settings.Host,
			"sub":   "TODO some user",
			"exp":   now.Add(expiresIn).Unix(),
			"iat":   now.Unix(),
			"nbf":   now.Unix(),
			"scope": scope,
			"aud":   audience,
		},
	}

	signedToken, err := jwt.Encode(token, privateKey)
	if err != nil {
		panic(err)
	}

	encoding.Encode(w, r, http.StatusOK, TokenResponse{
		AccessToken: signedToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn.Seconds(),
	})
}
