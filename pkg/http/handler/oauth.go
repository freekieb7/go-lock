package handler

import (
	"context"
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
	"github.com/freekieb7/go-lock/pkg/jwt"
	"github.com/freekieb7/go-lock/pkg/jwt/helper"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/freekieb7/go-lock/pkg/session"
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
	Scopes     []string
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

			clientId, err := uuid.Parse(clientIdRaw)
			if err != nil {
				encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
					ErrOAuthInvalidRequest,
					fmt.Sprintf("Invalid client id : %s", clientIdRaw),
				})
				return
			}

			client, err := ClientStore.GetById(r.Context(), clientId)
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
			for _, uri := range client.RedirectUriList() {
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

			resourceServer, err := ResourceServerStore.GetByUrl(r.Context(), audienceRaw)
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

			supportedScopes := strings.Split(resourceServer.Scopes+" offline_access openid profile email", " ")
			scopes := strings.Split(scopeRaw, " ")
			for _, scope := range scopes {
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
						authRequest.Scopes = scopes
						authRequest.UrlValues = r.URL.Query().Encode()

						if session.Has("user_id") {
							authRequest.UserId = session.Get("user_id").(uuid.UUID)
						}
						if resourceServer.AllowSkippingUserConsent {
							authRequest.Authorized = true
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

func OAuthToken(
	settings *settings.Settings,
	clientStore *store.ClientStore,
	authorizationCodeStore *store.AuthorizationCodeStore,
	jwksStore *store.JwksStore,
	resourceServerStore *store.ResourceServerStore,
	userStore *store.UserStore,
	refreshTokenStore *store.RefreshTokenStore,
) http.Handler {
	type tokenResponseBody struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    uint32 `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"`
		IdToken      string `json:"id_token,omitempty"`
	}

	generateUserTokensResponseBody := func(ctx context.Context, scopes []string, user model.User, client model.Client, resourceServer model.ResourceServer) (tokenResponseBody, error) {
		var responseBody tokenResponseBody
		responseBody.TokenType = "Bearer"

		jwks, err := jwksStore.FirstActive(ctx)
		if err != nil {
			panic(err)
		}

		jwtBuilder := helper.NewJwtBuilder()

		now := time.Now()
		var expiresInSeconds uint32 = 3600

		accessToken := jwtBuilder.
			SetIssuer(settings.Host).
			SetAudience(resourceServer.Url).
			SetInitiatedAt(now.Unix()).
			SetNotBefore(now.Unix()).
			SetExpiresAt(now.Add(time.Second * time.Duration(expiresInSeconds)).Unix()).
			Build()

		signedAccessToken, err := jwt.Encode(accessToken, jwks)
		if err != nil {
			return responseBody, err
		}
		responseBody.AccessToken = signedAccessToken
		responseBody.ExpiresIn = expiresInSeconds

		if slices.Contains(scopes, "offline_access") {
			refreshToken := model.RefreshToken{
				Id:               uuid.New(),
				ClientId:         client.Id,
				UserId:           user.Id,
				Scope:            strings.Join(scopes, " "),
				ResourceServerId: resourceServer.Id,
				CreatedAt:        time.Now().Unix(),
				ExpiresAt:        time.Now().Add(model.RefreshTokenExpiresIn).Unix(),
			}
			if err := refreshTokenStore.Create(ctx, refreshToken); err != nil {
				return responseBody, err
			}

			responseBody.RefreshToken = refreshToken.Id.String()
		}

		if slices.Contains(scopes, "openid") {
			idToken := jwtBuilder.
				Reset().
				SetIssuer(settings.Host).
				SetAudience(client.Id.String()).
				SetSubject(user.Id.String()).
				SetInitiatedAt(now.Unix()).
				SetExpiresAt(now.Add(time.Second * time.Duration(expiresInSeconds)).Unix()).
				Build()

			signedIdToken, err := jwt.Encode(idToken, jwks)
			if err != nil {
				return responseBody, err
			}

			responseBody.IdToken = signedIdToken
		}

		return responseBody, nil
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
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

						clientId, err := uuid.Parse(clientIdRaw)
						if err != nil {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								fmt.Sprintf("Invalid client id : %s", clientIdRaw),
							})
							return
						}

						client, err := clientStore.GetById(r.Context(), clientId)
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

						_, err = resourceServerStore.GetByUrl(r.Context(), audienceRaw)
						if err != nil {
							if errors.Is(err, store.ErrResourceServerNotFound) {
								encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
									ErrOAuthInvalidRequest,
									fmt.Sprintf("Invalid audience : %s", audienceRaw),
								})
								return
							}

							log.Println(err)

							encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
								ErrOAuthServerError,
								"Internal server error, please try again",
							})
							return
						}

						jwks, err := jwksStore.FirstActive(r.Context())
						if err != nil {
							panic(err)
						}

						now := time.Now()
						var expiresInSeconds uint32 = 3600

						accessToken := helper.NewJwtBuilder().
							SetIssuer(settings.Host).
							SetAudience(client.Id.String()).
							SetInitiatedAt(now.Unix()).
							SetExpiresAt(now.Add(time.Second * time.Duration(expiresInSeconds)).Unix()).
							Build()

						signedAccessToken, err := jwt.Encode(accessToken, jwks)
						if err != nil {
							panic(err)
						}

						encoding.Encode(w, http.StatusOK, tokenResponseBody{
							AccessToken: signedAccessToken,
							TokenType:   "Bearer",
							ExpiresIn:   expiresInSeconds,
						})
						return
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
							if len(clientCredentialParts) > 1 {
								encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
									ErrOAuthInvalidRequest,
									"Invalid Authorization header",
								})
								return
							}

							clientIdRaw = clientCredentialParts[0]

							if len(clientCredentialParts) == 2 {
								clientSecretRaw = clientCredentialParts[1]
							}
						} else {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								"Required param : client_id",
							})
							return
						}

						clientId, err := uuid.Parse(clientIdRaw)
						if err != nil {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								fmt.Sprintf("Invalid client id : %s", clientIdRaw),
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

							log.Println(err)

							encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
								ErrOAuthServerError,
								"Internal server error, please try again",
							})
							return
						}

						// Get client based on credentials or code
						client, err := clientStore.GetById(r.Context(), clientId)
						if err != nil {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthServerError,
								fmt.Sprintf("Invalid client id : %s", clientIdRaw),
							})
							return
						}

						if client.IsConfidential && client.Secret != clientSecretRaw {
							encoding.Encode(w, http.StatusForbidden, OAuthErrorResponse{
								ErrOAuthUnauthorizedClient,
								fmt.Sprintf("Invalid client : %s", clientId),
							})
							return
						}

						if authorizationCode.CodeChallenge != "" {
							if !r.Form.Has("code_verifier") {
								encoding.Encode(w, http.StatusForbidden, OAuthErrorResponse{
									ErrOAuthInvalidRequest,
									"Required param : code_verifier",
								})
								return
							}
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
						}

						found := false
						for _, redirectUri := range client.RedirectUriList() {
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

						resourceServer, err := resourceServerStore.GetByUrl(r.Context(), audienceRaw)
						if err != nil {
							if errors.Is(err, store.ErrResourceServerNotFound) {
								encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
									ErrOAuthInvalidRequest,
									fmt.Sprintf("Invalid audience : %s", audienceRaw),
								})
								return
							}
						}

						supportedScopes := strings.Split(resourceServer.Scopes+" offline_access openid profile email", " ")
						scopes := strings.Split(authorizationCode.Scope, " ")
						for _, scope := range scopes {
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
							log.Println(err)
							encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
								ErrOAuthServerError,
								"Internal server error, please try again",
							})
							return
						}

						generatedReponseBody, err := generateUserTokensResponseBody(r.Context(), scopes, user, client, resourceServer)
						if err != nil {
							log.Println(err)
							encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
								ErrOAuthServerError,
								"Internal server error, please try again",
							})
							return
						}
						encoding.Encode(w, http.StatusOK, generatedReponseBody)
						return
					}
				case "refresh_token":
					{
						var (
							clientIdRaw     string
							clientSecretRaw string
						)
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
							if len(clientCredentialParts) > 1 {
								encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
									ErrOAuthInvalidRequest,
									"Invalid Authorization header",
								})
								return
							}

							clientIdRaw = clientCredentialParts[0]

							if len(clientCredentialParts) == 2 {
								clientSecretRaw = clientCredentialParts[1]
							}
						} else {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								"Required param : client_id",
							})
							return
						}

						if !r.Form.Has("refresh_token") {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								"Required param : refresh_token",
							})
							return
						}
						refreshTokenRaw := r.Form.Get("refresh_token")

						// todo scope subset
						if !r.Form.Has("scope") {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								"Unsupported param : scope",
							})
							return
						}

						clientId, err := uuid.Parse(clientIdRaw)
						if err != nil {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								fmt.Sprintf("Invalid client id : %s", clientId),
							})
							return
						}

						client, err := clientStore.GetById(r.Context(), clientId)
						if err != nil {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								fmt.Sprintf("Invalid client : %s", clientIdRaw),
							})
							return
						}

						if client.IsConfidential && client.Secret != clientSecretRaw {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthAccessDenied,
								fmt.Sprintf("Invalid client : %s", clientIdRaw),
							})
							return
						}

						refreshTokenId, err := uuid.Parse(refreshTokenRaw)
						if err != nil {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								fmt.Sprintf("Invalid refresh token : %s", refreshTokenRaw),
							})
							return
						}

						refreshToken, err := refreshTokenStore.GetById(r.Context(), refreshTokenId, clientId)
						if err != nil {
							panic(err)
						}

						if time.Now().Unix() > refreshToken.ExpiresAt {
							encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
								ErrOAuthInvalidRequest,
								fmt.Sprintf("Expired refresh token : %s", refreshTokenRaw),
							})
							return
						}

						user, err := userStore.GetById(r.Context(), refreshToken.UserId)
						if err != nil {
							if errors.Is(err, store.ErrUserNotFound) {
								encoding.Encode(w, http.StatusForbidden, OAuthErrorResponse{
									ErrOAuthAccessDenied,
									fmt.Sprintf("User not found : %s", user.Id),
								})
								return
							}

							log.Println(err)
							encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
								ErrOAuthServerError,
								"Internal server error",
							})
							return
						}

						resourceServer, err := resourceServerStore.GetById(r.Context(), refreshToken.ResourceServerId)
						if err != nil {
							if errors.Is(err, store.ErrUserNotFound) {
								encoding.Encode(w, http.StatusForbidden, OAuthErrorResponse{
									ErrOAuthAccessDenied,
									fmt.Sprintf("Invalid audience"),
								})
								return
							}

							log.Println(err)
							encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
								ErrOAuthServerError,
								"Internal server error",
							})
							return
						}

						generatedReponseBody, err := generateUserTokensResponseBody(r.Context(), strings.Split(refreshToken.Scope, " "), user, client, resourceServer)
						if err != nil {
							log.Println(err)
							encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
								ErrOAuthServerError,
								"Internal server error, please try again",
							})
							return
						}

						if err := refreshTokenStore.DeleteById(r.Context(), refreshToken.Id, refreshToken.ClientId); err != nil {
							log.Println(err)
							encoding.Encode(w, http.StatusInternalServerError, OAuthErrorResponse{
								ErrOAuthServerError,
								"Internal server error, please try again",
							})
							return
						}

						encoding.Encode(w, http.StatusOK, generatedReponseBody)
						return
					}
				default:
					{
						encoding.Encode(w, http.StatusBadRequest, OAuthErrorResponse{
							ErrOAuthInvalidRequest,
							fmt.Sprintf("Invalid grant_type : %s", grantTypeRaw),
						})
						return
					}
				}
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}
