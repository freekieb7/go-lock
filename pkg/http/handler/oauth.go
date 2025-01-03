package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
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
	"github.com/google/uuid"
)

type OAuthError string

const (
	ErrOAuthAccessDenied            OAuthError = "access_denied"
	ErrOAuthInvalidRequest          OAuthError = "invalid_request"
	ErrOAuthUnauthorizedClient      OAuthError = "unauthorized_client"
	ErrOAuthUnsupportedResponseType OAuthError = "unsupported_response_type"
	ErrOAuthInvalidScope            OAuthError = "invalid_scope"
	ErrOAuthServerError             OAuthError = "server_error"
	ErrOAuthTemporarilyUnavailable  OAuthError = "temporarily_unavailable"
)

type OAuthErrorResponse struct {
	Error            OAuthError `json:"error"`
	ErrorDescription string     `json:"error_description"`
}

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
	UrlValues  string
	UserId     uuid.UUID
	Authorized bool
}

func init() {
	gob.Register(AuthRequest{})
}

// see https://openid.net/specs/openid-connect-core-1_0.html
func OAuthAuthorize(
	ClientStore *store.ClientStore,
	AuthorizationCodeStore *store.AuthorizationCodeStore,
	ResourceServerStore *store.ResourceServerStore,
) http.Handler {
	gob.Register(AuthRequest{})

	// type requestBody struct {
	// 	Scope        string // Required
	// 	ResponseType string // Required
	// 	ClientId     string // Required
	// 	RedirectUri  string // Required
	// 	State        string // Recommended
	// ResponseMode string  // Optional
	// Nonce        string  // Optional
	// Display      Display // Optional
	// Prompt       Prompt  // Optional
	// MaxAge       int     // Optional
	// UiLocales    string  // Optional
	// IdTokenHint  string  // Optional
	// LoginHint    string  // Optional
	// AcrValues    string  // Optional
	// }

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
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

			if !r.URL.Query().Has("redirect_uri") {
				encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
					ErrOAuthInvalidRequest,
					"Required param : redirect_uri",
				})
				return
			}
			redirectUriRaw := r.URL.Query().Get("redirect_uri")
			if _, err := url.ParseRequestURI(redirectUriRaw); err != nil {
				encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
					ErrOAuthInvalidRequest,
					fmt.Sprintf("Invalid redirect_uri : %s", redirectUriRaw),
				})
				return
			}

			if !r.URL.Query().Has("response_type") {
				encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
					ErrOAuthInvalidRequest,
					"Required param : response_type",
				})
				return
			}
			responseTypeRaw := r.URL.Query().Get("response_type")

			if !r.URL.Query().Has("client_id") {
				encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
					ErrOAuthInvalidRequest,
					"Required param : client_id",
				})
				return
			}
			clientIdRaw := r.URL.Query().Get("client_id")

			if !r.URL.Query().Has("audience") {
				encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
					ErrOAuthInvalidRequest,
					"Required param : audience",
				})
				return
			}
			audienceRaw := r.URL.Query().Get("audience")

			stateRaw := r.URL.Query().Get("state")
			scopeRaw := r.URL.Query().Get("scope")

			client, err := ClientStore.GetById(r.Context(), clientIdRaw)
			if err != nil {
				if errors.Is(err, store.ErrClientNotFound) {
					encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
						ErrOAuthInvalidRequest,
						fmt.Sprintf("Invalid client : %s", clientIdRaw),
					})
					return
				}

				log.Println(err)

				encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
					ErrOAuthServerError,
					"Something went wrong, please try again",
				})
				return
			}

			found := false
			for _, uri := range client.RedirectUris {
				if redirectUriRaw == uri {
					found = true
					break
				}
			}
			if !found {
				encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
					ErrOAuthInvalidRequest,
					fmt.Sprintf("Invalid redirect_uri : %s", redirectUriRaw),
				})
				return
			}

			resourceServer, err := ResourceServerStore.GetByUri(r.Context(), audienceRaw)
			if err != nil {
				if errors.Is(err, store.ErrResourceServerNotFound) {
					encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
						ErrOAuthInvalidRequest,
						fmt.Sprintf("Invalid audience : %s", audienceRaw),
					})
					return
				}

				log.Println(err)

				encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
					ErrOAuthServerError,
					"Something went wrong, please try again",
				})
				return
			}

			supportedScopes := append(resourceServer.Scopes, "offline_access")
			for _, scope := range strings.Split(scopeRaw, " ") {
				if !slices.Contains(supportedScopes, scope) {
					encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
						ErrOAuthInvalidRequest,
						fmt.Sprintf("Invalid scope : %s", scope),
					})
					return
				}
			}

			// response_type "token" is also viable
			// https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/call-your-api-using-the-authorization-code-flow
			switch responseTypeRaw {
			case "code":
				{
					var codeChallengeRaw, codeChallengeMethodRaw string
					if r.URL.Query().Has("code_challenge") {
						// Auth code with PKCE flow
						codeChallengeRaw = r.URL.Query().Get("code_challenge")

						if !r.URL.Query().Has("code_challenge_method") {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								"Required param : code_challenge_method",
							})
							return
						}
						codeChallengeMethodRaw = r.URL.Query().Get("code_challenge_method")

						if codeChallengeMethodRaw != "S256" && codeChallengeMethodRaw != "plain" {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								fmt.Sprintf("Invalid code_challenge_method : %s", codeChallengeMethodRaw),
							})
							return
						}
					} else {
						// Auth code flow
						if !client.IsConfidential {
							location := fmt.Sprintf("%s?error=unauthorized_client", redirectUriRaw)
							if stateRaw != "" {
								location += fmt.Sprintf("&state=%s", stateRaw)
							}
						}
					}

					if !session.Has("auth_request") {
						var authRequest AuthRequest
						authRequest.UrlValues = r.URL.Query().Encode()
						if session.Has("user_id") {
							authRequest.UserId = session.Get("user_id").(uuid.UUID)
						}
						session.Set("auth_request", authRequest)

						w.Header().Add("Location", "/auth/authorize")
						w.WriteHeader(http.StatusFound)
						return
					}
					authRequest := session.Get("auth_request").(AuthRequest)

					if !authRequest.Authorized {

						location := fmt.Sprintf("%s?error=access_denied", redirectUriRaw)
						if stateRaw != "" {
							location += fmt.Sprintf("&state=%s", stateRaw)
						}

						w.Header().Add("Location", location)
						w.WriteHeader(http.StatusFound)
					}
					session.Delete("auth_request")

					authorizationCode := model.AuthorizationCode{
						ClientId:            client.Id,
						UserId:              authRequest.UserId,
						Code:                random.NewString(32),
						Audience:            audienceRaw,
						Scope:               scopeRaw,
						CodeChallenge:       codeChallengeRaw,
						CodeChallengeMethod: codeChallengeMethodRaw,
					}
					if err := AuthorizationCodeStore.Create(r.Context(), authorizationCode); err != nil {
						panic(err)
					}

					location := fmt.Sprintf("%s?code=%s", redirectUriRaw, authorizationCode.Code)
					if stateRaw != "" {
						location += fmt.Sprintf("&state=%s", stateRaw)
					}

					w.Header().Add("Location", location)
					w.WriteHeader(http.StatusFound)
				}
			case "token":
				{
					encoding.Encode(w, http.StatusNotImplemented, OAuthErrorResponse{
						ErrOAuthUnsupportedResponseType,
						fmt.Sprintf("Unsupported response_type : %s", responseTypeRaw),
					})
				}
			default:
				{
					encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
						ErrOAuthInvalidRequest,
						fmt.Sprintf("Invalid response_type : %s", responseTypeRaw),
					})
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
	settings *settings.Settings,
	clientStore *store.ClientStore,
	authorizationCodeStore *store.AuthorizationCodeStore,
	jwksStore *store.JwksStore,
	resourceServerStore *store.ResourceServerStore,
	userStore *store.UserStore,
) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			r.ParseForm()

			if !r.Form.Has("grant_type") {
				encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
					ErrOAuthInvalidRequest,
					"Required param : grant_type",
				})
				return
			}
			grantTypeRaw := r.Form.Get("grant_type")

			switch grantTypeRaw {
			case "client_credentials":
				{
					if !r.Form.Has("client_id") {
						encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
							ErrOAuthInvalidRequest,
							"Required param : client_id",
						})
						return
					}
					clientIdRaw := r.Form.Get("client_id")

					if !r.Form.Has("client_secret") {
						encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
							ErrOAuthInvalidRequest,
							"Required param : client_secret",
						})
						return
					}
					clientSecretRaw := r.Form.Get("client_secret")

					if !r.Form.Has("audience") {
						encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
							ErrOAuthInvalidRequest,
							"Required param : audience",
						})
						return
					}
					audienceRaw := r.Form.Get("audience")

					client, err := clientStore.GetById(r.Context(), clientIdRaw)
					if err != nil {
						if errors.Is(err, store.ErrClientNotFound) {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								fmt.Sprintf("Invalid client : %s", clientIdRaw),
							})
							return
						}

						encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
							ErrOAuthServerError,
							"Internal server error, please try again",
						})
						return
					}

					if client.Secret != clientSecretRaw {
						encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
							ErrOAuthInvalidRequest,
							fmt.Sprintf("Invalid client : %s", clientIdRaw),
						})
						return
					}

					_, err = resourceServerStore.GetByUri(r.Context(), audienceRaw)
					if err != nil {
						if errors.Is(err, store.ErrResourceServerNotFound) {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								fmt.Sprintf("Invalid audience : %s", audienceRaw),
							})
							return
						}

						encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
							ErrOAuthServerError,
							"Internal server error, please try again",
						})
						return
					}

					jwkSets, err := jwksStore.All(r.Context())
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
							"iss": settings.Host,
							"sub": "TODO some user",
							"exp": now.Add(expiresIn).Unix(),
							"iat": now.Unix(),
							"nbf": now.Unix(),
						},
					}, privateKey)
					if err != nil {
						panic(err)
					}

					encoding.Encode(w, http.StatusOK, TokenResponse{
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
						encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
							ErrOAuthInvalidRequest,
							"Required param : code",
						})
						return
					}
					codeRaw := r.Form.Get("code")

					if !r.Form.Has("redirect_uri") {
						encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
							ErrOAuthInvalidRequest,
							"Required param : redirect_uri",
						})
						return
					}
					redirectUriRaw := r.Form.Get("redirect_uri")

					if !r.Form.Has("audience") {
						encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
							ErrOAuthInvalidRequest,
							"Required param : audience",
						})
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
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								"Invalid Authorization header",
							})
							return
						}

						authorizationHeaderParts := strings.Split(authorizationHeader, " ")
						if len(authorizationHeaderParts) != 2 {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								"Invalid Authorization header",
							})
							return
						}

						base64ClientCredentials := authorizationHeaderParts[1]
						clientCredentials, err := base64.StdEncoding.DecodeString(base64ClientCredentials)
						if err != nil {
							panic(err)
						}

						clientCredentialParts := strings.Split(string(clientCredentials), ":")
						if len(clientCredentialParts) != 2 {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								"Invalid Authorization header",
							})
							return
						}

						clientIdRaw = clientCredentialParts[0]
						clientSecretRaw = clientCredentialParts[1]
					} else {
						encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
							ErrOAuthInvalidRequest,
							"Required param : client_id",
						})
						return
					}

					authorizationCode, err := authorizationCodeStore.GetByCode(r.Context(), codeRaw, clientIdRaw)
					if err != nil {
						if errors.Is(err, store.ErrAuthorizationCodeNotFound) {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								fmt.Sprintf("Invalid code : %s", codeRaw),
							})
							return
						}

						encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
							ErrOAuthServerError,
							"Internal server error, please try again",
						})
						return
					}

					// Get client based on credentials or code
					client, err := clientStore.GetById(r.Context(), clientIdRaw)
					if err != nil {
						encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
							ErrOAuthServerError,
							fmt.Sprintf("Invalid client id : %s", clientIdRaw),
						})
						return
					}

					if r.Form.Has("code_verifier") {
						// Validate by verifier
						codeVerifierRaw := r.Form.Get("code_verifier")

						hasher := sha256.New()
						hasher.Write([]byte(codeVerifierRaw))
						codeChallengeGenerated := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
						if codeChallengeGenerated != authorizationCode.CodeChallenge {
							encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
								ErrOAuthServerError,
								fmt.Sprintf("Invalid code verifier : %s", codeVerifierRaw),
							})
							return
						}
					} else {
						if !client.IsConfidential {
							encoding.Encode(w, http.StatusForbidden, OAuthErrorResponse{
								ErrOAuthUnauthorizedClient,
								"Unauthorized client",
							})
							return
						}

						if client.Secret != clientSecretRaw {
							encoding.Encode(w, http.StatusForbidden, OAuthErrorResponse{
								ErrOAuthAccessDenied,
								"Access denied",
							})
							return
						}
					}

					found := false
					for _, redirectUri := range client.RedirectUris {
						if redirectUriRaw == redirectUri {
							found = true
							break
						}
					}

					if !found {
						encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
							ErrOAuthAccessDenied,
							fmt.Sprintf("Invalid redirect uri : %s", redirectUriRaw),
						})
						return
					}

					resourceServer, err := resourceServerStore.GetByUri(r.Context(), audienceRaw)
					if err != nil {
						if errors.Is(err, store.ErrResourceServerNotFound) {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								fmt.Sprintf("Invalid audience : %s", audienceRaw),
							})
							return
						}
					}

					supportedScopes := append(resourceServer.Scopes, "offline_access")
					for _, scope := range strings.Split(scopeRaw, " ") {
						if !slices.Contains(supportedScopes, scope) {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidScope,
								fmt.Sprintf("Invalid scope : %s", scope),
							})
							return
						}
					}

					user, err := userStore.GetById(r.Context(), authorizationCode.UserId)
					if err != nil {
						encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
							ErrOAuthServerError,
							"Internal server error, please try again",
						})
						return
					}

					jwkSets, err := jwksStore.All(r.Context())
					if err != nil {
						encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
							ErrOAuthServerError,
							"Internal server error, please try again",
						})
						return
					}

					if len(jwkSets) < 1 {
						encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
							ErrOAuthServerError,
							"Internal server error, please try again",
						})
						return
					}

					jwks := jwkSets[len(jwkSets)-1] // Take last

					privateKey, err := jwt.ParseRsaPrivateKey(jwks.PrivateKey)
					if err != nil {
						encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
							ErrOAuthServerError,
							"Internal server error, please try again",
						})
						return
					}

					now := time.Now().UTC()
					expiresIn := time.Hour
					token := jwt.Token{
						Header: map[string]any{
							"kid": jwks.Id,
						},
						Payload: map[string]any{
							"iss":   settings.Host,
							"sub":   user.Id.String(),
							"exp":   now.Add(expiresIn).Unix(),
							"iat":   now.Unix(),
							"nbf":   now.Unix(),
							"scope": scopeRaw,
							"aud":   audienceRaw,
						},
					}

					signedToken, err := jwt.Encode(token, privateKey)
					if err != nil {
						encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
							ErrOAuthServerError,
							"Internal server error, please try again",
						})
						return
					}

					encoding.Encode(w, http.StatusOK, TokenResponse{
						AccessToken: signedToken,
						TokenType:   "Bearer",
						ExpiresIn:   expiresIn.Seconds(),
					})
				}
			default:
				{
					encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
						ErrOAuthInvalidRequest,
						fmt.Sprintf("Invalid grant_type : %s", grantTypeRaw),
					})
				}
			}
		},
	)
}
