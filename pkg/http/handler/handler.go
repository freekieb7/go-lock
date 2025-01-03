package handler

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/middleware"
	"github.com/freekieb7/go-lock/pkg/http/session"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/freekieb7/go-lock/pkg/settings"
)

func New(
	settings *settings.Settings,
	logger *slog.Logger,
	database *sql.DB,
	sessionStore *store.SessionStore,
	clientStore *store.ClientStore,
	jwksStore *store.JwksStore,
	authorizationCodeStore *store.AuthorizationCodeStore,
	resourceServerStore *store.ResourceServerStore,
	userStore *store.UserStore,
) http.Handler {
	mux := http.NewServeMux()

	authenticatorMiddleware := func(next http.Handler) http.Handler {
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

	managerMiddleware := func(next http.Handler, unprotected bool) http.Handler {
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

			if !unprotected && !sess.Has("user_id") {
				client, err := clientStore.GetManagerCredentials(r.Context())
				if err != nil {
					panic(err)
				}

				state := random.NewUrlSafeString(10)
				sess.Set("state", state)

				w.Header().Add("Location", fmt.Sprintf("/auth/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&audience=%s&state=%s", client.Id, url.QueryEscape(client.RedirectUris[0]), url.QueryEscape(settings.Host+"/api"), state))
				w.WriteHeader(http.StatusSeeOther)
			} else {
				next.ServeHTTP(w, r)
			}

			if err := sessionStore.Save(r.Context(), *sess); err != nil {
				panic(err)
			}
		})
	}

	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("./public"))))

	mux.Handle("/health", Health(logger, database))

	mux.Handle("/.well-known/openid-configuration", OpenIdConfigurations(settings))

	mux.Handle("/app", managerMiddleware(Home(), false))
	mux.Handle("/app/callback", managerMiddleware(Callback(settings, clientStore), true))

	mux.Handle("/auth/oidc/register", RegisterClient(clientStore))
	mux.Handle("/auth/oidc/jwks", Keys(jwksStore))

	mux.Handle("/auth/oauth/authorize", authenticatorMiddleware(OAuthAuthorize(clientStore, authorizationCodeStore, resourceServerStore)))
	mux.Handle("/auth/oauth/token", OAuthToken(settings, clientStore, authorizationCodeStore, jwksStore, resourceServerStore, userStore))

	mux.Handle("/auth/signin", authenticatorMiddleware(Signin(sessionStore, userStore)))
	mux.Handle("/auth/authorize", authenticatorMiddleware(Authorize()))

	mux.Handle("/api/users", Users(userStore))

	var handler http.Handler = mux
	handler = middleware.LogRoutes(logger, handler)
	handler = middleware.HandlePanic(handler)

	return handler
}
