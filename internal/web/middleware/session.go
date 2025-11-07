package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/freekieb7/go-lock/internal/config"
	"github.com/freekieb7/go-lock/internal/session"
)

func Session(cfg *config.Config, logger *slog.Logger, sessionStore *session.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var sess session.Session

			sessionCookie, err := r.Cookie(session.CookieName)
			if err != nil {
				if err != http.ErrNoCookie {
					logger.ErrorContext(r.Context(), "Failed to read session cookie", "error", err)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				// No session cookie, create new session
				sess, err = sessionStore.NewSession()
				if err != nil {
					logger.ErrorContext(r.Context(), "Failed to create new session", "error", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				sess, err = sessionStore.SaveSession(r.Context(), sess)
				if err != nil {
					logger.ErrorContext(r.Context(), "Failed to save new session", "error", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				http.SetCookie(w, &http.Cookie{
					Name:     session.CookieName,
					Value:    sess.Token,
					Path:     "/",
					HttpOnly: true,
					Secure:   cfg.Server.IsProduction(),
					SameSite: http.SameSiteLaxMode,
				})
			} else {
				// Load existing session
				sess, err = sessionStore.GetSessionByToken(r.Context(), sessionCookie.Value)
				if err != nil {
					if err != session.ErrSessionNotFound {
						logger.ErrorContext(r.Context(), "Failed to get session by token", "error", err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}

					// Session not found or expired
					sess, err = sessionStore.NewSession()
					if err != nil {
						logger.ErrorContext(r.Context(), "Failed to create new session", "error", err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}

					sess, err = sessionStore.SaveSession(r.Context(), sess)
					if err != nil {
						logger.ErrorContext(r.Context(), "Failed to save new session", "error", err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}

					http.SetCookie(w, &http.Cookie{
						Name:     session.CookieName,
						Value:    sess.Token,
						Path:     "/",
						HttpOnly: true,
						Secure:   cfg.Server.IsProduction(),
						SameSite: http.SameSiteLaxMode,
					})
				}
			}

			// Add session to request context
			ctx := context.WithValue(r.Context(), session.ContextKey, sess)
			r = r.WithContext(ctx)

			// Proceed to next handler
			next.ServeHTTP(w, r)
		})
	}
}
