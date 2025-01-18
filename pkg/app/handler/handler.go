package handler

import (
	"net/http"

	"github.com/freekieb7/go-lock/pkg/app/oauth"
	"github.com/freekieb7/go-lock/pkg/core/data/data_source/api"
	"github.com/freekieb7/go-lock/pkg/core/data/store"
	"github.com/freekieb7/go-lock/pkg/core/settings"
)

func AddRoutes(
	mux *http.ServeMux,
	settings *settings.Settings,
	sessionStore *store.SessionStore,
	clientStore *store.ClientStore,
	resourceServerStore *store.ResourceServerStore,
	oauthProvider *oauth.OAuthProvider,
	lockApi *api.LockApi,
) {
	mux.Handle("/", authenticatedMiddleware(oauthProvider, sessionStore, Home()))
	mux.Handle("/callback", sessionMiddleware(sessionStore, Callback(oauthProvider, settings, clientStore)))

	mux.Handle("/clients", authenticatedMiddleware(oauthProvider, sessionStore, Clients(lockApi)))
	mux.Handle("/clients/{client_id}", authenticatedMiddleware(oauthProvider, sessionStore, Client(clientStore)))

	mux.Handle("/resourceServers", authenticatedMiddleware(oauthProvider, sessionStore, ResourceServer(settings, resourceServerStore)))
}
