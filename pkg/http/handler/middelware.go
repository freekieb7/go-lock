package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/http/session"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/freekieb7/go-lock/pkg/settings"
	"github.com/google/uuid"
)

func authenticatorMiddleware(sessionStore *store.SessionStore, next http.Handler) http.Handler {
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
				Path:        "/",
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

func appMiddleware(sessionStore *store.SessionStore, clientStore *store.ClientStore, settings *settings.Settings, next http.Handler) http.Handler {
	type tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IdToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}

	return appUnprotectedMiddleware(sessionStore, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := session.FromRequest(r)

		if !sess.Has("user") {
			client, err := clientStore.GetManagerCredentials(r.Context())
			if err != nil {
				panic(err)
			}

			state := random.NewUrlSafeString(10)
			sess.Set("state", state)

			w.Header().Add("Location", fmt.Sprintf("/auth/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&audience=%s&state=%s", client.Id, url.QueryEscape(client.RedirectUris[0]), url.QueryEscape(settings.Host+"/api"), state))
			w.WriteHeader(http.StatusSeeOther)
		} else {
			user := sess.Get("user").(map[string]any)
			account := user["account"].(map[string]any)
			accessTokenExpires := account["access_token_expires"].(int64)
			if time.Now().UTC().Unix() < accessTokenExpires {
				// refresh
				manager, err := clientStore.GetManagerCredentials(r.Context())
				if err != nil {
					panic(err)
				}
				refreshToken := account["refresh_token"]
				resp, err := http.Post(fmt.Sprintf("%s/auth/oauth/token?grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s", settings.Host, manager.Id, manager.Secret, refreshToken), "plain/text", nil)
				if err != nil {
					log.Println(err)
					encoding.Encode(w, http.StatusInternalServerError, "Creating request failed")
					return
				}
				defer resp.Body.Close()

				var tknRes tokenResponse
				if err := json.NewDecoder(resp.Body).Decode(&tknRes); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}

				user := map[string]any{
					"id": uuid.New(),
					"account": map[string]any{
						"access_token":         tknRes.AccessToken,
						"access_token_expires": time.Now().UTC().Unix() + (tknRes.ExpiresIn * 1000),
						"refresh_token":        tknRes.RefreshToken,
					},
				}
				sess.Set("user", user)

				w.Header().Add("Location", "/app")
				w.WriteHeader(http.StatusSeeOther)
			}
		}

		next.ServeHTTP(w, r)
	}))

}

func appUnprotectedMiddleware(sessionStore *store.SessionStore, next http.Handler) http.Handler {
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
				Path:        "/",
				Partitioned: true,
				SameSite:    http.SameSiteStrictMode,
			}

			r.AddCookie(cookie)
			http.SetCookie(w, cookie)
		}

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
	})
}
