package handler

import (
	"net/http"

	api_handler "github.com/freekieb7/go-lock/pkg/api/handler"
	app_handler "github.com/freekieb7/go-lock/pkg/app/handler"
	auth_handler "github.com/freekieb7/go-lock/pkg/auth/handler"
	"github.com/freekieb7/go-lock/pkg/core/container"
)

func New(
	container *container.Container,
) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("./public"))))
	mux.Handle("/health", Health(container.Logger, container.Database))

	api_handler.AddRoutes(mux, container.UserStore, container.ClientStore)
	app_handler.AddRoutes(mux, container.Settings, container.SessionStore, container.ClientStore, container.ResourceServerStore, container.OAuthProvider, container.LockApi)
	auth_handler.AddRoutes(mux, container.Settings, container.SessionStore, container.ClientStore, container.JwksStore, container.AuthorizationCodeStore, container.ResourceServerStore, container.UserStore, container.RefreshTokenStore, container.TokenGenerator)

	var handler http.Handler = mux
	handler = LogMiddleware(container.Logger, handler)
	// handler = PanicMiddleware(handler)

	return handler
}
