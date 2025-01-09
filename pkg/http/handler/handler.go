package handler

import (
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/generator"
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
	userStore *store.UserStore,
	refreshTokenStore *store.RefreshTokenStore,
	tokenGenerator *generator.TokenGenerator,
) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("./public"))))

	mux.Handle("/health", Health(logger, database))

	mux.Handle("/.well-known/openid-configuration", OpenIdConfigurations(settings))

	mux.Handle("/app", appMiddleware(sessionStore, clientStore, settings, Home()))
	mux.Handle("/app/callback", appUnprotectedMiddleware(sessionStore, Callback(settings, clientStore)))

	mux.Handle("/auth/oidc/register", RegisterClient(clientStore))
	mux.Handle("/auth/oidc/jwks", Keys(jwksStore))

	mux.Handle("/auth/oauth/authorize", authenticatorMiddleware(sessionStore, OAuthAuthorize(clientStore, authorizationCodeStore, resourceServerStore)))
	mux.Handle("/auth/oauth/token", OAuthToken(settings, clientStore, authorizationCodeStore, jwksStore, resourceServerStore, userStore, refreshTokenStore, tokenGenerator))

	mux.Handle("/auth/signin", authenticatorMiddleware(sessionStore, Signin(sessionStore, userStore)))
	mux.Handle("/auth/authorize", authenticatorMiddleware(sessionStore, Authorize()))

	mux.Handle("/api/users", Users(userStore))

	var handler http.Handler = mux
	handler = middleware.LogRoutes(logger, handler)
	handler = middleware.HandlePanic(handler)

	return handler
}
