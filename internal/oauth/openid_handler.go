package oauth

import (
	"context"
	"encoding/json"
	"net/http"

	apperrors "github.com/freekieb7/go-lock/internal/errors"
	"github.com/freekieb7/go-lock/internal/jwks"
	"github.com/freekieb7/go-lock/internal/web/response"
	"github.com/freekieb7/go-lock/pkg/jwt"
)

// OpenIDConfiguration represents the OpenID Connect Discovery configuration
type OpenIDConfiguration struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	JWKSUri                       string   `json:"jwks_uri"`
	UserinfoEndpoint              string   `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint            string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint         string   `json:"introspection_endpoint,omitempty"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	SubjectTypesSupported         []string `json:"subject_types_supported"`
	IDTokenSigningAlgValues       []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported               []string `json:"scopes_supported"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported               []string `json:"claims_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	ResponseModesSupported        []string `json:"response_modes_supported"`
}

// OpenIDHandler handles OpenID Connect specific endpoints
type OpenIDHandler struct {
	jwksService *jwks.JWKSService
	baseURL     string
}

// NewOpenIDHandler creates a new OpenID Connect handler
func NewOpenIDHandler(jwksService *jwks.JWKSService, baseURL string) *OpenIDHandler {
	return &OpenIDHandler{
		jwksService: jwksService,
		baseURL:     baseURL,
	}
}

// HandleWellKnownConfiguration serves the OpenID Connect discovery document
func (h *OpenIDHandler) HandleWellKnownConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		response.ErrorResponse(w, apperrors.InvalidRequestError("Method not allowed", nil), nil)
		return
	}

	config := OpenIDConfiguration{
		Issuer:                h.baseURL,
		AuthorizationEndpoint: h.baseURL + "/oauth/authorize",
		TokenEndpoint:         h.baseURL + "/oauth/token",
		JWKSUri:               h.baseURL + "/.well-known/jwks.json",
		UserinfoEndpoint:      h.baseURL + "/oauth/userinfo",
		RevocationEndpoint:    h.baseURL + "/oauth/revoke",
		IntrospectionEndpoint: h.baseURL + "/oauth/introspect",

		ResponseTypesSupported: []string{
			"code",
			"id_token",
			"token id_token",
			"code id_token",
			"code token",
			"code token id_token",
		},

		SubjectTypesSupported: []string{
			"public",
		},

		IDTokenSigningAlgValues: []string{
			"RS256",
			"RS384",
			"RS512",
		},

		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
			"offline_access",
		},

		TokenEndpointAuthMethods: []string{
			"client_secret_basic",
			"client_secret_post",
		},

		ClaimsSupported: []string{
			"iss",
			"sub",
			"aud",
			"exp",
			"iat",
			"auth_time",
			"nonce",
			"email",
			"email_verified",
			"name",
			"given_name",
			"family_name",
		},

		CodeChallengeMethodsSupported: []string{
			"S256",
		},

		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
		},

		ResponseModesSupported: []string{
			"query",
			"fragment",
			"form_post",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	if err := json.NewEncoder(w).Encode(config); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// HandleJWKS serves the JSON Web Key Set for token verification
func (h *OpenIDHandler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	jwkSet, err := h.jwksService.GetPublicJWKS(ctx)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=600") // Cache for 10 minutes

	if err := json.NewEncoder(w).Encode(jwkSet); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// GetSigningKey returns the current active signing key for ID token generation
func (h *OpenIDHandler) GetSigningKey(ctx context.Context) (*jwt.KeySet, error) {
	return h.jwksService.GetSigningKey(ctx)
}

// GetIssuer returns the issuer URL for ID tokens
func (h *OpenIDHandler) GetIssuer() string {
	return h.baseURL
}
