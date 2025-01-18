package handler

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/freekieb7/go-lock/pkg/core/http/encoding"
)

func LogMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		time.Since(start)

		logRow := fmt.Sprintf("%s %s %s", r.Method, time.Since(start).String(), r.URL.String())
		logger.InfoContext(r.Context(), logRow)
	})
}

func PanicMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Println(err)

				encoding.Encode(w, http.StatusInternalServerError, "Something went wrong, please try again")
			}
		}()

		next.ServeHTTP(w, r)
	})
}
