package handler

import (
	"log/slog"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/http/middleware"
)

func New(
	logger *slog.Logger,
	healthHandler *HealthHandler,
	oidcHandler *OidcHandler,
	oAuth2Handler *OAuth2Handler,
) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", healthHandler.HealthCheck)

	mux.HandleFunc("/.well-known/openid-configuration", oidcHandler.Configurations)

	mux.HandleFunc("/oidc/register", oidcHandler.RegisterClient)
	mux.HandleFunc("/oidc/jwks", oidcHandler.Keys)

	mux.HandleFunc("/oauth/authorize", oAuth2Handler.Authorize)
	mux.HandleFunc("/oauth/token", oAuth2Handler.Token)

	var handler http.Handler = mux
	handler = middleware.LogRoutes(logger, handler)
	handler = middleware.HandlePanic(handler)

	return handler
}
