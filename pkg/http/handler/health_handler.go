package handler

import (
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/http/encoding"
)

type HealthHandler struct {
	logger   *slog.Logger
	Database *sql.DB
}

func NewHealthHandler(logger *slog.Logger, database *sql.DB) *HealthHandler {
	return &HealthHandler{
		logger,
		database,
	}
}

func (handler *HealthHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	databaseHealth := true
	if err := handler.Database.Ping(); err != nil {
		databaseHealth = false
		handler.logger.Error("database could not be pinged")
	}

	encoding.Encode(w, r, http.StatusOK, map[string]any{
		"alive":         true,
		"database_ping": databaseHealth,
	})
}
