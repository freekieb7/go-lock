package handler

import (
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/middleware"
	"github.com/freekieb7/go-lock/pkg/settings"
)

func New(
	settings *settings.Settings,
	logger *slog.Logger,
	database *sql.DB,
	sessionStore *store.SessionStore,
	clientStore *store.ClientStore,
	jwksStore *store.JwksStore,
	authorizationCodeStore *store.AuthorizationCodeStore,
	resourceServerStore *store.ResourceServerStore,
) http.Handler {
	mux := http.NewServeMux()

	sessionMiddleware := func(next http.Handler) http.Handler {
		return middleware.EnforceCookieMiddleware(middleware.SessionMiddleware(sessionStore, next))
	}

	mux.Handle("/health", Health(logger, database))

	mux.Handle("/.well-known/openid-configuration", OpenIdConfigurations(settings))

	mux.Handle("/oidc/register", RegisterClient(clientStore))
	mux.Handle("/oidc/jwks", Keys(jwksStore))

	mux.Handle("/oauth/authorize", sessionMiddleware(OAuthAuthorize(clientStore, authorizationCodeStore, resourceServerStore)))
	mux.Handle("/oauth/token", OAuthToken(settings, clientStore, authorizationCodeStore, jwksStore, resourceServerStore))

	mux.Handle("/signin", sessionMiddleware(Signin()))
	mux.Handle("/authorize", sessionMiddleware(Authorize()))

	var handler http.Handler = mux
	handler = middleware.LogRoutes(logger, handler)
	// handler = middleware.HandlePanic(handler)

	return handler
}
