package middleware

import (
	"log/slog"
	"net/http"

	"github.com/freekieb7/go-lock/internal/session"
	"github.com/google/uuid"
)

func Authenticated(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := r.Context().Value(session.ContextKey).(session.Session)
			if !ok {
				// Session not in context - user is not authenticated
				logger.WarnContext(r.Context(), "User not authenticated")

				// Redirect to login page
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			if sess.UserID == uuid.Nil {
				// User not logged in
				logger.WarnContext(r.Context(), "User not logged in")

				// Redirect to login page
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// User is authenticated, proceed to next handler
			next.ServeHTTP(w, r)
		})
	}
}
