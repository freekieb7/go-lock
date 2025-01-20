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
	"github.com/freekieb7/go-lock/pkg/jwt"
	"github.com/freekieb7/go-lock/pkg/oauth"
	"github.com/freekieb7/go-lock/pkg/session"
	"github.com/freekieb7/go-lock/pkg/settings"
	"github.com/google/uuid"
)

const sessionCookieKey string = "SID"
const defaultScope string = "offline_access openid"

func authenticatedMiddleware(settings *settings.Settings, oauthProvider *oauth.OAuthProvider, sessionStore *store.SessionStore, next http.Handler) http.Handler {
	return sessionMiddleware(sessionStore, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := session.FromRequest(r)

		// Force user to be signed in
		if !sess.HasUser() {
			url, state := oauthProvider.AuthrorizationUrl(defaultScope)
			sess.Set("state", state)

			// Redirect to authorization server
			w.Header().Add("Location", url)
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		user := sess.User()

		// Refresh tokens if expired
		if user.TokenExpiresAt <= time.Now().Unix() {
			if user.RefreshToken == "" {
				sess.Delete("user")

				w.Header().Add("Location", "/")
				w.WriteHeader(http.StatusSeeOther)
				return
			}

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

			idToken, err := jwt.Decode(tokenResponse.IdToken)
			if err != nil {
				panic(err)
			}

			// todo validate token
			// issuer := idToken.Payload["iss"].(string)
			// if issuer != settings.Host {
			// 	w.WriteHeader(http.StatusForbidden)
			// 	return
			// }

			// resOpenId, err := http.Get(issuer + "/.well-known/openid-configuration")
			// if err != nil {
			// 	panic(err)
			// }
			// defer resOpenId.Body.Close()

			// type OpenIdResponseBody struct {
			// 	JwksUri string `json:"jwks_uri"`
			// }
			// var openIdResponseBody OpenIdResponseBody
			// if err := json.NewDecoder(resOpenId.Body).Decode(&openIdResponseBody); err != nil {
			// 	panic(err)
			// }

			// resJwks, err := http.Get(openIdResponseBody.JwksUri)
			// if err != nil {
			// 	panic(err)
			// }
			// defer resJwks.Body.Close()

			// type JwksResponseBody struct {
			// 	Keys []struct {
			// 		Kid string `json:"kid"`
			// 	} `json:"keys"`
			// }
			// var jwksResponseBody JwksResponseBody
			// if err := json.NewDecoder(resJwks.Body).Decode(&jwksResponseBody); err != nil {
			// 	panic(err)
			// }

			// // todo proper signature check
			// found := false
			// for _, key := range jwksResponseBody.Keys {
			// 	if idToken.Header["kid"].(string) == key.Kid {
			// 		found = true
			// 		break
			// 	}
			// }

			// if !found {
			// 	panic("key not found for id token")
			// }

			subject := idToken.Payload["sub"].(string)
			userId := uuid.MustParse(subject)

			sess.SetUser(session.SessionUser{
				Id:             userId,
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
