package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/freekieb7/go-lock/internal/session"
	"github.com/freekieb7/go-lock/internal/util"
)

func CSRF(logger *slog.Logger, sessionStore *session.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := r.Context().Value(session.ContextKey).(session.Session)
			if !ok {
				// Session not in context - this is the real bug
				logger.ErrorContext(r.Context(), "Session not found in context")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// Check request method
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				// Safe method, generate and set CSRF token
				csrfToken, err := util.GenerateRandomString(32)
				if err != nil {
					logger.ErrorContext(r.Context(), "Failed to generate CSRF token", "error", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				sess.Data["csrf_token"] = csrfToken
				savedSess, err := sessionStore.SaveSession(r.Context(), sess)
				if err != nil {
					logger.ErrorContext(r.Context(), "Failed to save session with CSRF token", "error", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				// Update context with saved session
				ctx := context.WithValue(r.Context(), session.ContextKey, savedSess)
				r = r.WithContext(ctx)
				next.ServeHTTP(w, r)
				return
			case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
				// Unsafe methods, validate CSRF token
				if err := r.ParseForm(); err != nil {
					logger.ErrorContext(r.Context(), "Failed to parse form", "error", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				csrfToken := r.FormValue("csrf_token")
				if csrfToken == "" {
					logger.WarnContext(r.Context(), "Missing CSRF token")
					w.WriteHeader(http.StatusForbidden)
					return
				}

				// Validate token
				savedTokenVal, found := sess.Data["csrf_token"]
				if !found {
					logger.WarnContext(r.Context(), "Missing CSRF token in session")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				savedToken, ok := savedTokenVal.(string)
				if !ok {
					logger.ErrorContext(r.Context(), "Invalid CSRF token type in session")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				logger.InfoContext(r.Context(), "CSRF validation",
					"received_token", csrfToken,
					"session_token", savedToken,
					"path", r.URL.Path,
					"method", r.Method)

				if savedToken != csrfToken {
					logger.WarnContext(r.Context(), "Invalid CSRF token",
						"received", csrfToken,
						"expected", savedToken)
					w.WriteHeader(http.StatusForbidden)
					return
				}

				// CSRF token valid, proceed
				next.ServeHTTP(w, r)
				return
			default:
				// Unknown method
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		})
	}
}
