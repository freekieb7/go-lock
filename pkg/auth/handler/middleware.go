package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/freekieb7/go-lock/pkg/core/data/store"
	"github.com/freekieb7/go-lock/pkg/core/session"
)

func sessionMiddleware(sessionStore *store.SessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie("ASID")
		if errors.Is(err, http.ErrNoCookie) {
			rawCookieValue := make([]byte, 16)
			rand.Read(rawCookieValue)

			cookie := &http.Cookie{
				Name:        "ASID",
				Value:       base64.URLEncoding.EncodeToString(rawCookieValue),
				Expires:     time.Now().Add(365 * 24 * time.Hour),
				Secure:      true,
				HttpOnly:    true,
				Path:        "/auth",
				Partitioned: true,
				SameSite:    http.SameSiteStrictMode,
			}

			r.AddCookie(cookie)
			http.SetCookie(w, cookie)
		}

		cookie, err := r.Cookie("ASID")
		if errors.Is(err, http.ErrNoCookie) {
			panic(err)
		}

		sessionId := cookie.Value

		sess, err := sessionStore.GetById(r.Context(), sessionId)
		if err != nil {
			if errors.Is(err, store.ErrSessionNotFound) {
				sess = &session.Session{
					Id:     sessionId,
					Values: make(map[string]any),
				}
			} else {
				panic(err)
			}
		}

		r = r.WithContext(context.WithValue(r.Context(), session.SessionKey, sess))

		next.ServeHTTP(w, r)

		if err := sessionStore.Save(r.Context(), *sess); err != nil {
			panic(err)
		}
	})
}
