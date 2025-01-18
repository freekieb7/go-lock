package handler

import (
	"net/http"

	"github.com/freekieb7/go-lock/pkg/core/data/store"
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

func AddRoutes(
	mux *http.ServeMux,
	userStore *store.UserStore,
	clientStore *store.ClientStore,
) {
	mux.Handle("/api/users", Users(userStore))
	mux.Handle("/api/clients", Clients(clientStore))
}
