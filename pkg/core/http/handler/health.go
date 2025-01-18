package handler

import (
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/core/http/encoding"
)

func Health(
	logger *slog.Logger,
	database *sql.DB,
) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				databaseHealth := true
				if err := database.Ping(); err != nil {
					databaseHealth = false
					logger.Error("database could not be pinged")
				}

				encoding.Encode(w, http.StatusOK, map[string]any{
					"alive":         true,
					"database_ping": databaseHealth,
				})
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}
