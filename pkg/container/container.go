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

	database "github.com/freekieb7/go-lock/pkg/data/data_source"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/handler"
	"github.com/freekieb7/go-lock/pkg/http/server"
	"github.com/freekieb7/go-lock/pkg/settings"

	_ "github.com/freekieb7/go-lock/pkg/data/migration/versions"
)

type Container struct {
	Settings               *settings.Settings
	Logger                 *slog.Logger
	Database               *sql.DB
	ResourceServerStore    *store.ResourceServerStore
	ClientStore            *store.ClientStore
	AuthorizationCodeStore *store.AuthorizationCodeStore
	HttpServer             *http.Server
}

func New(ctx context.Context) *Container {
	settings := settings.New(ctx)

	// Logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Data sources
	database, err := database.New(filepath.Join(settings.DataDir, "go-lock.db"), settings.Environment)
	if err != nil {
		log.Fatal(err)
	}

	// Stores
	sessionStore := store.NewSessionStore(database)
	resourceServerStore := store.NewResourceServerStore(database)
	authorizationCodeStore := store.NewAuthorizationCodeStore(database)
	clientStore := store.NewClientStore(database)
	jwksStore := store.NewJwksStore(database)

	// Listeners
	httpHandler := handler.New(settings, logger, database, sessionStore, clientStore, jwksStore, authorizationCodeStore, resourceServerStore)
	httpServer := server.New(fmt.Sprintf(":%d", settings.Port), httpHandler)

	return &Container{
		Settings:               settings,
		Logger:                 logger,
		Database:               database,
		ResourceServerStore:    resourceServerStore,
		ClientStore:            clientStore,
		AuthorizationCodeStore: authorizationCodeStore,
		HttpServer:             httpServer,
	}
}
