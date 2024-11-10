package handler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/data/local/model"
	"github.com/freekieb7/go-lock/pkg/data/local/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/freekieb7/go-lock/pkg/settings"
)

type OidcHandler struct {
	settings         *settings.Settings
	clientStore      *store.ClientStore
	redirectUriStore *store.RedirectUriStore
	jwksStore        *store.JwksStore
}

func NewOidcHandler(
	settings *settings.Settings,
	clientStore *store.ClientStore,
	redirectUriStore *store.RedirectUriStore,
	jwksStore *store.JwksStore,
) *OidcHandler {
	return &OidcHandler{
		settings,
		clientStore,
		redirectUriStore,
		jwksStore,
	}
}

func (handler *OidcHandler) Configurations(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Add("Access-Control-Allow-Origin", "*")

	wellKnownOpenIdConfiguration := map[string]any{
		"issuer":                 handler.settings.Host,
		"authorization_endpoint": fmt.Sprintf("%s/oauth2/authorize", handler.settings.Host),
		"token_endpoint":         fmt.Sprintf("%s/oauth2/token", handler.settings.Host),
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			// "private_key_jwt",
		},
		"token_endpoint_auth_signing_alg_values_supported": []string{
			"RS256",
			// "ES256",
		},
		// "userinfo_endpoint":                           "http://localhost:8080/oauth2/userinfo",
		// "check_session_iframe":                        "http://localhost:8080/oauth2/check_session",
		// "end_session_endpoint":                        "http://localhost:8080/oauth2/end_session",
		"jwks_uri":              fmt.Sprintf("%s/oidc/jwks", handler.settings.Host),
		"registration_endpoint": fmt.Sprintf("%s/oidc/register", handler.settings.Host),
		// "scopes_supported":                            []string{"openid", "profile", "email", "address", "phone", "offline_access"},
		"response_types_supported": []string{
			"code",
			// "token",
			// "code id_token", "id_token", "id_token token",
		},
		// "acr_values_supported":                        []string{"urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"},
		"subject_types_supported": []string{
			"public",
			// "pairwise",
		},
		"userinfo_signing_alg_values_supported": []string{
			"RS256",
			// "ES256",
			// "HS256",
		},
		// "userinfo_encryption_alg_values_supported":    []string{"RSA-OAEP-256", "A128KW"},
		// "userinfo_encryption_enc_values_supported":    []string{"A128CBC-HS256", "A128GCM"},
		// "id_token_signing_alg_values_supported":       []string{"RS256", "ES256", "HS256"},
		// "id_token_encryption_alg_values_supported":    []string{"RSA-OAEP-256", "A128KW"},
		// "id_token_encryption_enc_values_supported":    []string{"A128CBC-HS256", "A128GCM"},
		// "request_object_signing_alg_values_supported": []string{"none", "RS256", "ES256"},
		// "display_values_supported":                    []string{"page", "popup"},
		// "claim_types_supported":                       []string{"normal", "distributed"},
		// "claims_supported":                            []string{"sub", "iss", "auth_time", "acr", "name", "given_name", "family_name", "nickname", "profile", "picture", "website", "email", "email_verified", "locale", "zoneinfo", "http://example.info/claims/groups"},
		// "claims_parameter_supported":                  true,
		// "service_documentation":                       "http://server.example.com/connect/service_documentation.html",
		// "ui_locales_supported":                        []string{"en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"},
	}

	encoding.Encode(w, r, http.StatusOK, wellKnownOpenIdConfiguration)
}

type RegisterClientRequestBody struct {
	
}

type RegisterClientResponseBody struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func (handler *OidcHandler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		encoding.EncodeError(w, r, http.StatusMethodNotAllowed, ErrCodeInvalidRequest, "Invalid method")
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		w.Header().Set("Accept", "application/json")
		encoding.EncodeError(w, r, http.StatusUnsupportedMediaType, ErrCodeInvalidRequest, "Invalid content type")
		return
	}

	requestBody, err := encoding.Decode[clientRegistrationBody](r.Body)
	if err != nil {
		panic(err)
	}

	if len(requestBody.RedirectUris) < 1 {
		encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "No redirect uri found")
		return
	}

	var errClientCreation error
	var client model.Client
	for range 3 {
		client.Id = random.NewString(32)
		client.Secret = random.NewBytes(32)

		if err := handler.clientStore.Create(r.Context(), client); err != nil {
			if errors.Is(err, store.ErrClientDuplicate) {
				errClientCreation = err
				continue
			}

			errClientCreation = err
		}

		break
	}

	if errClientCreation != nil {
		panic(errClientCreation)
	}

	for _, uri := range requestBody.RedirectUris {
		redirectUri := model.RedirectUri{
			ClientId: client.Id,
			Uri:      uri,
		}

		// TODO add transaction
		if err := handler.redirectUriStore.Create(r.Context(), redirectUri); err != nil {
			panic(err)
		}
	}

	encoding.Encode(w, r, http.StatusCreated, RegisterClientResponse{
		ClientId:     client.Id,
		ClientSecret: base64.RawURLEncoding.EncodeToString(client.Secret),
	})
}

type KeysResponseBody struct {
	Keys []KeysReponseBodyKey `json:"keys"`
}

type KeysReponseBodyKey struct {
	Kty      string   `json:"kty"`
	Use      string   `json:"use"`
	Kid      string   `json:"kid"`
	Alg      string   `json:"alg"`
	KeyOps   []string `json:"key_ops"`
	X5t      string   `json:"x5t,omitempty"`
	X5c      [][]byte `json:"x5c,omitempty"`
	Modules  string   `json:"n"`
	Exponent string   `json:"e"`
}

func (handler *OidcHandler) Keys(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Add("Access-Control-Allow-Origin", "*")

	jwkSets, err := handler.jwksStore.All(r.Context())
	if err != nil {
		panic(err)
	}

	var responseBody KeysResponseBody
	responseBody.Keys = make([]KeysReponseBodyKey, 0, len(jwkSets))

	for _, jwkSet := range jwkSets {
		// publicKeyBlock, _ := pem.Decode(jwkSet.PublicKey)

		responseBody.Keys = append(responseBody.Keys, KeysReponseBodyKey{
			Kty: "RSA",
			Use: "sig",
			Kid: jwkSet.Id,
			Alg: "RS256",
			KeyOps: []string{
				"verify",
			},
			Modules:  base64.RawURLEncoding.EncodeToString(jwkSet.PublicKeyModules),
			Exponent: base64.RawURLEncoding.EncodeToString(jwkSet.PublicKeyExponent),
		})
	}

	encoding.Encode(w, r, http.StatusOK, responseBody)
}
