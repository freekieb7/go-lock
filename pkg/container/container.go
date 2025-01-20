package container

import (
	"context"
	"database/sql"
	"log"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/freekieb7/go-lock/pkg/data/data_source/database"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/oauth"
	"github.com/freekieb7/go-lock/pkg/settings"
)

type Container struct {
	Settings               *settings.Settings
	Logger                 *slog.Logger
	Database               *sql.DB
	SessionStore           *store.SessionStore
	ResourceServerStore    *store.ResourceServerStore
	ClientStore            *store.ClientStore
	AuthorizationCodeStore *store.AuthorizationCodeStore
	UserStore              *store.UserStore
	RefreshTokenStore      *store.RefreshTokenStore
	JwksStore              *store.JwksStore
	OAuthProvider          *oauth.OAuthProvider
}

func New(ctx context.Context) *Container {
	settings := settings.New(ctx)

	// Logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Data sources
	db, err := database.New(filepath.Join(settings.DataDir, "go-lock.db"), settings.Environment)
	if err != nil {
		log.Fatal(err)
	}

	// Stores
	sessionStore := store.NewSessionStore(db)
	resourceServerStore := store.NewResourceServerStore(db)
	authorizationCodeStore := store.NewAuthorizationCodeStore(db)
	clientStore := store.NewClientStore(db)
	jwksStore := store.NewJwksStore(db)
	userStore := store.NewUserStore(db)
	refreshTokenStore := store.NewRefreshTokenStore(db)

	// Providers
	oauthProvider := oauth.NewOAuthProvider(settings.ClientId.String(), settings.ClientSecret, settings.Host+"/auth/oauth/authorize", settings.Host+"/auth/oauth/token", settings.Host+"/callback", settings.Host+"/api")

	return &Container{
		Settings:               settings,
		Logger:                 logger,
		Database:               db,
		SessionStore:           sessionStore,
		ResourceServerStore:    resourceServerStore,
		ClientStore:            clientStore,
		AuthorizationCodeStore: authorizationCodeStore,
		UserStore:              userStore,
		RefreshTokenStore:      refreshTokenStore,
		JwksStore:              jwksStore,
		OAuthProvider:          oauthProvider,
	}
}
