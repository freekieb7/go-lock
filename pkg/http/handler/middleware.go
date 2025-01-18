package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/oauth"
	"github.com/freekieb7/go-lock/pkg/session"
	"github.com/google/uuid"
)

const sessionCookieKey string = "SID"

func authenticatedMiddleware(oauthProvider *oauth.OAuthProvider, sessionStore *store.SessionStore, next http.Handler) http.Handler {
	return sessionMiddleware(sessionStore, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := session.FromRequest(r)

		// Force user to be signed in
		if !sess.HasUser() {
			url, state := oauthProvider.AuthrorizationUrl()
			sess.Set("state", state)

			// Redirect to authorization server
			w.Header().Add("Location", url)
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		user := sess.User()

		// Refresh tokens if expired
		if user.TokenExpiresAt <= time.Now().Unix() {
			tokenResponse, err := oauthProvider.Refresh(user.RefreshToken)
			if err != nil {
				if errors.Is(err, oauth.ErrInvalidRefreshToken) {
					sess.Delete("user")

					w.Header().Add("Location", "/")
					w.WriteHeader(http.StatusSeeOther)
					return
				}

				panic(err)
			}

			sess.SetUser(session.SessionUser{
				Id:             uuid.New(),
				AccessToken:    tokenResponse.AccessToken,
				TokenExpiresAt: time.Now().Add(time.Second * time.Duration(tokenResponse.ExpiresIn)).Unix(),
				RefreshToken:   tokenResponse.RefreshToken,
				IdToken:        tokenResponse.IdToken,
			})

			w.Header().Add("Location", "/")
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	}))
}

func sessionMiddleware(sessionStore *store.SessionStore, next http.Handler) http.Handler {
	return cookieMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieKey)
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
	}))

}

func cookieMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie(sessionCookieKey)
		if errors.Is(err, http.ErrNoCookie) {
			rawCookieValue := make([]byte, 16)
			rand.Read(rawCookieValue)

			cookie := &http.Cookie{
				Name:        sessionCookieKey,
				Value:       base64.URLEncoding.EncodeToString(rawCookieValue),
				Expires:     time.Now().Add(365 * 24 * time.Hour),
				Secure:      true,
				HttpOnly:    true,
				Path:        "/",
				Partitioned: true,
				SameSite:    http.SameSiteStrictMode,
			}

			r.AddCookie(cookie)
			http.SetCookie(w, cookie)
		}

		next.ServeHTTP(w, r)
	})
}

func logMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		time.Since(start)

		logRow := fmt.Sprintf("%s %s %s", r.Method, time.Since(start).String(), r.URL.String())
		logger.InfoContext(r.Context(), logRow)
	})
}

func panicMiddleware(next http.Handler) http.Handler {

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
