package shared

import (
	"log/slog"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/config"
	"github.com/freekieb7/go-lock/internal/oauth"
)

// BaseHandler contains the common dependencies for all API handlers
type BaseHandler struct {
	Config         *config.Config
	Logger         *slog.Logger
	AccountService *account.Service
	OAuthService   *oauth.Service
}

// NewBaseHandler creates a new base handler with all dependencies
func NewBaseHandler(cfg *config.Config, logger *slog.Logger, accountService *account.Service, oauthService *oauth.Service) BaseHandler {
	return BaseHandler{
		Config:         cfg,
		Logger:         logger,
		AccountService: accountService,
		OAuthService:   oauthService,
	}
}
