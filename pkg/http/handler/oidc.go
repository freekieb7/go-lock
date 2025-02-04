package handler

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/freekieb7/go-lock/pkg/settings"
	"github.com/google/uuid"
)

func OpenIdConfigurations(
	settings *settings.Settings,
) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Access-Control-Allow-Origin", "*")

			if r.Method == http.MethodOptions {
				return
			}

			if r.Method == http.MethodGet {
				w.Header().Add("Access-Control-Allow-Origin", "*")

				wellKnownOpenIdConfiguration := map[string]any{
					"issuer":                 settings.Host,
					"authorization_endpoint": fmt.Sprintf("%s/auth/oauth/authorize", settings.Host),
					"token_endpoint":         fmt.Sprintf("%s/auth/oauth/token", settings.Host),
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
					"jwks_uri":              fmt.Sprintf("%s/auth/oidc/jwks", settings.Host),
					"registration_endpoint": fmt.Sprintf("%s/auth/oidc/register", settings.Host),
					// "scopes_supported":                            []string{"openid", "profile", "email", "address", "phone", "offline_access"},
					"response_types_supported": []string{
						"code",
						"token",
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

				encoding.Encode(w, http.StatusOK, wellKnownOpenIdConfiguration)
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}

// https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationRequest
func RegisterClient(
	clientStore *store.ClientStore,
) http.Handler {
	type RequestBody struct {
		RedirectUris                 []string `json:"redirect_uris"` // Required
		ResponseTypes                []string `json:"response_types"`
		GrantTypes                   []string `json:"grant_types"`
		ApplicationType              string   `json:"application_type"`
		Contacts                     []string `json:"contacts"`
		ClientName                   string   `json:"client_name"`
		LogoUri                      string   `json:"logo_uri"`
		ClientUri                    string   `json:"client_uri"`
		PolicyUri                    string   `json:"policy_uri"`
		TosUri                       string   `json:"tos_uri"`
		JwksUri                      string   `json:"jwks_uri"`
		Jwks                         string   `json:"jwks"`
		SectorIdentifierUri          string   `json:"sector_identifier_uri"`
		SubjectType                  string   `json:"subject_type"`
		IdTokenEncrypedResponseAlg   string   `json:"id_token_encrypted_response_alg"`
		IdTokenSignedResponseAlg     string   `json:"id_token_signed_response_alg"`
		IdTokenEncryptedResponseEnc  string   `json:"id_token_encrypted_response_enc"`
		UserinfoSignedResponseAlg    string   `json:"userinfo_signed_response_alg"`
		UserinfoEncryptedResponseAlg string   `json:"userinfo_encrypted_response_alg"`
		UserinfoEncryptedResponseEnc string   `json:"userinfo_encrypted_response_enc"`
		RequestObjectSigningAlg      string   `json:"request_object_signing_alg"`
		RequestObjectEncryptionAlg   string   `json:"request_object_encryption_alg"`
		RequestObjectEncryptionEnc   string   `json:"request_object_encryption_enc"`
		TokenEndpointAuthMethod      string   `json:"token_endpoint_auth_method"`
		TokenEndpointAuthSigningAlg  string   `json:"token_endpoint_auth_signing_alg"`
		DefaultMaxAge                int      `json:"default_max_age"`
		RequireAuthTime              bool     `json:"require_auth_time"`
		DefaultAcrValues             []string `json:"default_acr_values"`
		InitiateLoginUri             string   `json:"initiate_login_uri"`
		RequestUris                  []string `json:"request_uris"`
	}

	type responseBody struct {
		ClientId                uuid.UUID `json:"client_id"`
		ClientSecret            string    `json:"client_secret"`
		RegistrationAccessToken string    `json:"registration_access_token,omitempty"`
		RegistrationClientUri   string    `json:"registration_client_uri,omitempty"`
		ClientIdIssuedAt        int64     `json:"client_id_issued_at"`
		ClientSecretExpiresAt   int64     `json:"client_secret_expires_at"`
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				requestBody, err := encoding.Decode[RequestBody](r.Body)
				if err != nil {
					encoding.Encode(w, http.StatusBadRequest, "Bad request body")
					return
				}

				if len(requestBody.RedirectUris) < 1 {
					encoding.Encode(w, http.StatusBadRequest, "Required redirect uri")
					return
				}

				rexp := regexp.MustCompile(`(https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z0-9]{2,}(\.[a-zA-Z0-9]{2,})(\.[a-zA-Z0-9]{2,})?\/[a-zA-Z0-9]{2,}`)
				for _, uri := range requestBody.RedirectUris {
					if !rexp.MatchString(uri) {
						encoding.Encode(w, http.StatusBadRequest, fmt.Sprintf("Invalid redirect uri : %s", uri))
						return
					}
				}

				now := time.Now().Unix()
				client := model.Client{
					Id:             uuid.New(),
					Secret:         random.NewString(20),
					Name:           random.NewString(10),
					IsSystem:       false,
					IsConfidential: false,
					RedirectUrls:   strings.Join(requestBody.RedirectUris, " "),
					CreatedAt:      now,
					UpdatedAt:      now,
				}
				if requestBody.ClientName != "" {
					client.Name = requestBody.ClientName
				}
				client.IsConfidential = false

				if err := clientStore.Create(r.Context(), client); err != nil {
					encoding.Encode(w, http.StatusInternalServerError, "Internal server error, please try again")
					return
				}

				encoding.Encode(w, http.StatusCreated, responseBody{
					ClientId:         client.Id,
					ClientSecret:     client.Secret,
					ClientIdIssuedAt: time.Now().UTC().Unix(),
				})
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}

func Keys(
	JwksStore *store.JwksStore,
) http.Handler {
	type keysReponseBodyKey struct {
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

	type keysResponseBody struct {
		Keys []keysReponseBodyKey `json:"keys"`
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Access-Control-Allow-Origin", "*")

			if r.Method == http.MethodOptions {
				return
			}

			if r.Method == http.MethodGet {
				jwkSets, err := JwksStore.All(r.Context())
				if err != nil {
					panic(err)
				}

				var responseBody keysResponseBody
				responseBody.Keys = make([]keysReponseBodyKey, len(jwkSets))

				for idx, jwkSet := range jwkSets {
					responseBody.Keys[idx] = keysReponseBodyKey{
						Kty: "RSA",
						Use: "sig",
						Kid: jwkSet.Id,
						Alg: "RS256",
						KeyOps: []string{
							"verify",
						},
						Modules:  base64.RawURLEncoding.EncodeToString(jwkSet.PublicKeyModules),
						Exponent: base64.RawURLEncoding.EncodeToString(jwkSet.PublicKeyExponent),
					}
				}

				encoding.Encode(w, http.StatusOK, responseBody)
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}
