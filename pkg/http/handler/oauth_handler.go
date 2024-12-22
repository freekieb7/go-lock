package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/http/session"
	"github.com/freekieb7/go-lock/pkg/jwt"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/freekieb7/go-lock/pkg/settings"
	"github.com/freekieb7/go-lock/pkg/uuid"
)

const (
	ErrCodeInvalidRequest = "invalid_request"
)

type Display int

const (
	DisplayPage Display = iota
	DisplayPopup
	DisplayTouch
	DisplayWap
)

type Prompt int

const (
	PromptNone Prompt = iota
	PromptLogin
	PromptConsent
	PromptSelectAccount
)

type AuthRequest struct {
	UrlValues  string    `json:"url_values"`
	UserId     uuid.UUID `json:"user_id"`
	Authorized bool      `json:"authorized"`
}

// see https://openid.net/specs/openid-connect-core-1_0.html
func OAuthAuthorize(
	ClientStore *store.ClientStore,
	AuthorizationCodeStore *store.AuthorizationCodeStore,
	ResourceServerStore *store.ResourceServerStore,
) http.Handler {
	gob.Register(AuthRequest{})

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// type requestBody struct {
			// 	Scope        string // Required
			// 	ResponseType string // Required
			// 	ClientId     string // Required
			// 	RedirectUri  string // Required
			// 	State        string // Recommended
			// 	// ResponseMode string  // Optional
			// 	// Nonce        string  // Optional
			// 	// Display      Display // Optional
			// 	// Prompt       Prompt  // Optional
			// 	// MaxAge       int     // Optional
			// 	// UiLocales    string  // Optional
			// 	// IdTokenHint  string  // Optional
			// 	// LoginHint    string  // Optional
			// 	// AcrValues    string  // Optional
			// }

			if r.Method != "GET" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			session := session.FromRequest(r)
			if session.Has("auth_request") {
				if r.URL.RawQuery == "" {
					authRequest := session.Get("auth_request").(AuthRequest)
					r.URL.RawQuery = authRequest.UrlValues
				} else {
					session.Delete("auth_request")
				}
			}

			if !r.URL.Query().Has("response_type") {
				encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : response_type")
				return
			}
			responseTypeRaw := r.URL.Query().Get("response_type")

			if !r.URL.Query().Has("client_id") {
				encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : client_id")
				return
			}
			clientIdRaw := r.URL.Query().Get("client_id")

			if !r.URL.Query().Has("redirect_uri") {
				encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : redirect_uri")
				return
			}
			redirectUriRaw := r.URL.Query().Get("redirect_uri")

			if !r.URL.Query().Has("audience") {
				encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : audience")
				return
			}
			audienceRaw := r.URL.Query().Get("audience")

			stateRaw := r.URL.Query().Get("state")
			scopeRaw := r.URL.Query().Get("scope")

			client, err := ClientStore.GetById(r.Context(), clientIdRaw)
			if err != nil {
				if errors.Is(err, store.ErrClientNotExists) {
					encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid client id : %s", clientIdRaw))
					return
				}

				panic(err)
			}

			var redirectUri string
			for _, uri := range client.RedirectUris {
				if redirectUriRaw == uri {
					redirectUri = uri
					break
				}
			}
			if redirectUri == "" {
				encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid redirection uri %s", redirectUriRaw))
				return
			}

			resourceServer, err := ResourceServerStore.GetByUri(r.Context(), audienceRaw)
			if err != nil {
				if errors.Is(err, store.ErrResourceServerNotExists) {
					encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid audience : %s", audienceRaw))
					return
				}

				encoding.EncodeError(w, r, http.StatusInternalServerError, "server_error", "Internal server error")
				return
			}

			for _, scope := range strings.Split(scopeRaw, " ") {
				if !slices.Contains(resourceServer.Scopes, scope) {
					encoding.EncodeError(w, r, http.StatusInternalServerError, "server_error", fmt.Sprintf("Invalid scope : %s", scope))
					return
				}
			}

			// response_type "token" is also viable
			// https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/call-your-api-using-the-authorization-code-flow
			switch responseTypeRaw {
			case "code":
				{
					if r.URL.Query().Has("code_challenge") {
						// Auth code with PKCE flow
						codeChallengeRaw := r.URL.Query().Get("code_challenge")

						if !r.URL.Query().Has("code_challenge_method") {
							encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : code_challenge_method")
							return
						}
						codeChallengeMethodRaw := r.URL.Query().Get("code_challenge_method")

						if codeChallengeMethodRaw != "S256" && codeChallengeMethodRaw != "plain" {
							encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid code_challenge_method : %s", codeChallengeMethodRaw))
							return
						}

						if !session.Has("auth_request") {
							var authRequest AuthRequest
							authRequest.UrlValues = r.URL.Query().Encode()
							if session.Has("user_id") {
								authRequest.UserId = session.Get("user_id").(uuid.UUID)
							}
							session.Set("auth_request", authRequest)

							w.Header().Add("Location", "/authorize")
							w.WriteHeader(http.StatusFound)
							return
						}

						authRequest := session.Get("auth_request").(AuthRequest)
						if !authRequest.Authorized {
							location := fmt.Sprintf("%s?error=access_denied", redirectUri)
							if stateRaw != "" {
								location += fmt.Sprintf("&state=%s", stateRaw)
							}

							w.Header().Add("Location", location)
							w.WriteHeader(http.StatusFound)
						}
						session.Delete("auth_request")

						authorizationCode := model.AuthorizationCode{
							ClientId:            client.Id,
							Code:                random.NewString(32),
							Audience:            audienceRaw,
							Scope:               scopeRaw,
							CodeChallenge:       codeChallengeRaw,
							CodeChallengeMethod: codeChallengeMethodRaw,
						}
						if err := AuthorizationCodeStore.Create(r.Context(), authorizationCode); err != nil {
							panic(err)
						}

						location := fmt.Sprintf("%s?code=%s", redirectUri, authorizationCode.Code)
						if stateRaw != "" {
							location += fmt.Sprintf("&state=%s", stateRaw)
						}

						w.Header().Add("Location", location)
						w.WriteHeader(http.StatusFound)
					} else {
						// Auth code flow
						//todo
						w.WriteHeader(http.StatusNotImplemented)
						return
					}
				}
			case "token":
				{
					w.WriteHeader(http.StatusNotImplemented)
				}
			default:
				{
					encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid response type : %s", responseTypeRaw))
				}
			}
		},
	)
}

type TokenResponse struct {
	AccessToken string  `json:"access_token"`
	TokenType   string  `json:"token_type"`
	ExpiresIn   float64 `json:"expires_in"`
}

func OAuthToken(
	Settings *settings.Settings,
	ClientStore *store.ClientStore,
	AuthorizationCodeStore *store.AuthorizationCodeStore,
	JwksStore *store.JwksStore,
	ResourceServerStore *store.ResourceServerStore,
) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
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

					client, err := ClientStore.GetById(r.Context(), clientIdRaw)
					if err != nil {
						if errors.Is(err, store.ErrClientNotExists) {
							encoding.EncodeError(w, r, http.StatusNotImplemented, ErrCodeInvalidRequest, fmt.Sprintf("Invalid client credentials : %s <secret>", clientIdRaw))
							return
						}

						panic(err)
					}

					if client.Secret != clientSecretRaw {
						encoding.EncodeError(w, r, http.StatusNotImplemented, ErrCodeInvalidRequest, fmt.Sprintf("Invalid client credentials : %s <secret>", clientIdRaw))
						return
					}

					_, err = ResourceServerStore.GetByUri(r.Context(), audienceRaw)
					if err != nil {
						if errors.Is(err, store.ErrResourceServerNotExists) {
							encoding.EncodeError(w, r, http.StatusNotImplemented, ErrCodeInvalidRequest, fmt.Sprintf("Invalid audience : %s", audienceRaw))
							return
						}

						panic(err)
					}

					// Step 3 : Create tokens
					jwkSets, err := JwksStore.All(r.Context())
					if err != nil {
						panic(err)
					}

					if len(jwkSets) < 1 {
						panic("no jwk sets available")
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
							"iss": Settings.Host,
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
			case "authorization_code":
				{
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

						authorizationCode, err := AuthorizationCodeStore.Get(r.Context(), clientIdRaw, codeRaw)
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
						client, err = ClientStore.GetById(r.Context(), clientIdRaw)
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
						client, err = ClientStore.GetById(r.Context(), clientIdRaw)
						if err != nil {
							if errors.Is(err, store.ErrClientNotExists) {
								encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid client credentials : %s", client.Id))
								return
							}

							panic(err)
						}

						if client.Secret != clientSecretRaw {
							encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, fmt.Sprintf("Invalid client credentials : %s", client.Id))
							return
						}
					}

					if redirectUriRaw == "" {
						encoding.EncodeError(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "Required param : redirect uri")
						return
					}

					found := false
					for _, redirectUri := range client.RedirectUris {
						if redirectUriRaw == redirectUri {
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
					jwkSets, err := JwksStore.All(r.Context())
					if err != nil {
						panic(err)
					}

					if len(jwkSets) < 1 {
						panic(errors.New("no jwk sets available"))
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
							"iss":   Settings.Host,
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
			default:
				{
					encoding.EncodeError(w, r, http.StatusNotImplemented, ErrCodeInvalidRequest, fmt.Sprintf("Unsupported grant type : %s", grantTypeRaw))
				}
			}
		},
	)
}
