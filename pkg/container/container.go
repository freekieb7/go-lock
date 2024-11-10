package container

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	database "github.com/freekieb7/go-lock/pkg/data/local/data_source"
	"github.com/freekieb7/go-lock/pkg/data/local/store"
	"github.com/freekieb7/go-lock/pkg/http/handler"
	"github.com/freekieb7/go-lock/pkg/http/server"
	"github.com/freekieb7/go-lock/pkg/settings"
)

type Container struct {
	Settings               *settings.Settings
	Logger                 *slog.Logger
	Database               *sql.DB
	ApiStore               *store.ApiStore
	ClientStore            *store.ClientStore
	RedirectUriStore       *store.RedirectUriStore
	AuthorizationCodeStore *store.AuthorizationCodeStore
	HttpServer             *http.Server
}

func New(ctx context.Context) *Container {
	settings := settings.New(ctx)

	// Logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Data sources
	database, err := database.New(filepath.Join(settings.DataDir, "go-lock.db"))
	if err != nil {
		log.Fatal(err)
	}

	// Stores
	apiStore := store.NewApiStore(database)
	authorizationCodeStore := store.NewAuthorizationCodeStore(database)
	clientStore := store.NewClientStore(database)
	jwksStore := store.NewJwksStore(database)
	redirectUriStore := store.NewRedirectUriStore(database)

	// HTTP Handlers
	healthHandler := handler.NewHealthHandler(logger, database)
	oidcHandler := handler.NewOidcHandler(settings, clientStore, redirectUriStore, jwksStore)
	oauth2Handler := handler.NewOAuth2Handler(settings, clientStore, apiStore, authorizationCodeStore, redirectUriStore, jwksStore)
	// Listeners
	httpHandler := handler.New(logger, healthHandler, oidcHandler, oauth2Handler)
	httpServer := server.New(fmt.Sprintf(":%d", settings.Port), httpHandler)

	return &Container{
		Settings:               settings,
		Logger:                 logger,
		Database:               database,
		ApiStore:               apiStore,
		ClientStore:            clientStore,
		RedirectUriStore:       redirectUriStore,
		AuthorizationCodeStore: authorizationCodeStore,
		HttpServer:             httpServer,
	}
}
