package middleware

import (
	"log"
	"log/slog"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/http/encoding"
)

func LogRoutes(logger *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.InfoContext(r.Context(), r.URL.String())

		h.ServeHTTP(w, r)
	})
}

func HandlePanic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover := recover(); recover != nil {
				log.Println(recover)

				encoding.EncodeError(w, r, http.StatusBadRequest, "server_error", "Something went wrong, please try again")
				return
			}
		}()

		h.ServeHTTP(w, r)
	})
}
