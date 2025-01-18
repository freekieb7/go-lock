package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/freekieb7/go-lock/pkg/app/model"
	"github.com/freekieb7/go-lock/pkg/app/oauth"
	"github.com/freekieb7/go-lock/pkg/core/data/store"
	"github.com/freekieb7/go-lock/pkg/core/session"
	"github.com/google/uuid"
)

func authenticatedMiddleware(oauthProvider *oauth.OAuthProvider, sessionStore *store.SessionStore, next http.Handler) http.Handler {
	return sessionMiddleware(sessionStore, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := session.FromRequest(r)

		// Force user to be signed in
		if !sess.Has("user") {
			url, state := oauthProvider.AuthrorizationUrl()
			sess.Set("state", state)

			// Redirect to authorization server
			w.Header().Add("Location", url)
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		user := sess.Get("user").(model.SessionUser)

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

			user := model.SessionUser{
				Id:             uuid.New(),
				AccessToken:    tokenResponse.AccessToken,
				TokenExpiresAt: time.Now().Add(time.Second * time.Duration(tokenResponse.ExpiresIn)).Unix(),
				RefreshToken:   tokenResponse.RefreshToken,
				IdToken:        tokenResponse.IdToken,
			}
			sess.Set("user", user)

			log.Println(tokenResponse.ExpiresIn)
			log.Println(user.TokenExpiresAt)
			log.Println(time.Now().Unix())

			w.Header().Add("Location", "/")
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	}))
}

func sessionMiddleware(sessionStore *store.SessionStore, next http.Handler) http.Handler {
	return cookieMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("MSID")
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
		_, err := r.Cookie("MSID")
		if errors.Is(err, http.ErrNoCookie) {
			rawCookieValue := make([]byte, 16)
			rand.Read(rawCookieValue)

			cookie := &http.Cookie{
				Name:        "MSID",
				Value:       base64.URLEncoding.EncodeToString(rawCookieValue),
				Expires:     time.Now().Add(365 * 24 * time.Hour),
				Secure:      true,
				HttpOnly:    true,
				Path:        "/manager",
				Partitioned: true,
				SameSite:    http.SameSiteStrictMode,
			}

			r.AddCookie(cookie)
			http.SetCookie(w, cookie)
		}

		next.ServeHTTP(w, r)
	})
}
