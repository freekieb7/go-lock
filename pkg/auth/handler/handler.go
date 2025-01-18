package handler

import (
	"net/http"

	"github.com/freekieb7/go-lock/pkg/auth/generator"
	"github.com/freekieb7/go-lock/pkg/core/data/store"
	"github.com/freekieb7/go-lock/pkg/core/settings"
)

func AddRoutes(
	mux *http.ServeMux,
	settings *settings.Settings,
	sessionStore *store.SessionStore,
	clientStore *store.ClientStore,
	jwksStore *store.JwksStore,
	authorizationCodeStore *store.AuthorizationCodeStore,
	resourceServerStore *store.ResourceServerStore,
	userStore *store.UserStore,
	refreshTokenStore *store.RefreshTokenStore,
	tokenGenerator *generator.TokenGenerator,
) {
	mux.Handle("/.well-known/openid-configuration", OpenIdConfigurations(settings))

	mux.Handle("/auth/oidc/register", RegisterClient(clientStore))
	mux.Handle("/auth/oidc/jwks", Keys(jwksStore))

	mux.Handle("/auth/oauth/authorize", sessionMiddleware(sessionStore, OAuthAuthorize(clientStore, authorizationCodeStore, resourceServerStore)))
	mux.Handle("/auth/oauth/token", OAuthToken(settings, clientStore, authorizationCodeStore, jwksStore, resourceServerStore, userStore, refreshTokenStore, tokenGenerator))

	mux.Handle("/auth/signin", sessionMiddleware(sessionStore, Signin(sessionStore, userStore)))
	mux.Handle("/auth/authorize", sessionMiddleware(sessionStore, Authorize()))
}
