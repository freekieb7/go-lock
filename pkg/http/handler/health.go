package handler

import (
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/http/encoding"
)

func Health(
	Logger *slog.Logger,
	Database *sql.DB,
) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			databaseHealth := true
			if err := Database.Ping(); err != nil {
				databaseHealth = false
				Logger.Error("database could not be pinged")
			}

			encoding.Encode(w, http.StatusOK, map[string]any{
				"alive":         true,
				"database_ping": databaseHealth,
			})
		},
	)
}
