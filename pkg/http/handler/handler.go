package handler

import (
	"net/http"

	"github.com/freekieb7/go-lock/pkg/container"
	"github.com/freekieb7/go-lock/pkg/data/store"
)

type RouteManager struct {
	userStore *store.UserStore
}

func NewRouteManager(
	userStore *store.UserStore,
) *RouteManager {
	return &RouteManager{
		userStore,
	}
}

func New(
	container *container.Container,
) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("./public"))))
	mux.Handle("/health", Health(container.Logger, container.Database))

	mux.Handle("/.well-known/openid-configuration", OpenIdConfigurations(container.Settings))

	mux.Handle("/", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, HomePage()))
	mux.Handle("/callback", sessionMiddleware(container.SessionStore, Callback(container.OAuthProvider, container.Settings, container.ClientStore)))

	mux.Handle("/clients", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, ClientsPage(container.ClientStore)))
	mux.Handle("/clients/create", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, ClientCreatePage(container.ClientStore)))
	mux.Handle("/clients/{client_id}", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, ClientPage(container.ClientStore)))
	mux.Handle("/clients/{client_id}/delete", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, ClientPageDelete(container.ClientStore)))

	mux.Handle("/resourceServers", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, ResourceServersPage(container.ResourceServerStore)))
	mux.Handle("/resourceServers/create", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, ResourceServerCreatePage(container.ResourceServerStore)))
	mux.Handle("/resourceServers/{resource_server_id}", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, ResourceServerPage(container.ResourceServerStore)))
	mux.Handle("/resourceServers/{resource_server_id}/delete", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, ResourceServerPageDelete(container.ResourceServerStore)))

	mux.Handle("/users", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, UsersPage(container.UserStore)))
	mux.Handle("/users/create", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, UserCreatePage(container.UserStore)))
	mux.Handle("/users/{user_id}", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, UserPage(container.UserStore)))
	mux.Handle("/users/{user_id}/delete", authenticatedMiddleware(container.Settings, container.OAuthProvider, container.SessionStore, UserPageDelete(container.UserStore)))

	mux.Handle("/auth/oidc/register", RegisterClient(container.ClientStore))
	mux.Handle("/auth/oidc/jwks", Keys(container.JwksStore))

	mux.Handle("/auth/oauth/authorize", sessionMiddleware(container.SessionStore, OAuthAuthorize(container.ClientStore, container.AuthorizationCodeStore, container.ResourceServerStore)))
	mux.Handle("/auth/oauth/token", OAuthToken(container.Settings, container.ClientStore, container.AuthorizationCodeStore, container.JwksStore, container.ResourceServerStore, container.UserStore, container.RefreshTokenStore))

	mux.Handle("/auth/signin", sessionMiddleware(container.SessionStore, SigninPage(container.SessionStore, container.UserStore)))
	mux.Handle("/auth/authorize", sessionMiddleware(container.SessionStore, AuthorizePage()))

	var handler http.Handler = mux
	handler = logMiddleware(container.Logger, handler)
	handler = panicMiddleware(handler)

	return handler
}

func AddRoutes(
	mux *http.ServeMux,
	userStore *store.UserStore,
	clientStore *store.ClientStore,
) {
	mux.Handle("/api/users", Users(userStore))
	mux.Handle("/api/clients", Clients(clientStore))
}
