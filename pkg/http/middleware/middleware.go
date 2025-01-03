package middleware

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/freekieb7/go-lock/pkg/http/encoding"
)

// func EnforceCookieMiddleware(cookieId string, next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		_, err := r.Cookie("SID")
// 		if errors.Is(err, http.ErrNoCookie) {
// 			rawCookieValue := make([]byte, 16)
// 			rand.Read(rawCookieValue)

// 			cookie := &http.Cookie{
// 				Name:        "SID",
// 				Value:       base64.URLEncoding.EncodeToString(rawCookieValue),
// 				Expires:     time.Now().Add(365 * 24 * time.Hour),
// 				Secure:      true,
// 				HttpOnly:    true,
// 				Path:        "/",
// 				Partitioned: true,
// 				SameSite:    http.SameSiteStrictMode,
// 			}

// 			r.AddCookie(cookie)
// 			http.SetCookie(w, cookie)
// 		}

// 		next.ServeHTTP(w, r)
// 	})
// }

// func SessionMiddleware(sessionId string, sessionStore *store.SessionStore, next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		cookie, err := r.Cookie(sessionId)
// 		if errors.Is(err, http.ErrNoCookie) {
// 			panic(err)
// 		}

// 		sessionId := cookie.Value

// 		sess, err := sessionStore.GetById(r.Context(), sessionId)
// 		if err != nil {
// 			if errors.Is(err, store.ErrSessionNotFound) {
// 				sess = &session.Session{
// 					Id:     sessionId,
// 					Values: make(map[string]any),
// 				}
// 			} else {
// 				panic(err)
// 			}
// 		}

// 		r = r.WithContext(context.WithValue(r.Context(), session.SessionKey, sess))

// 		next.ServeHTTP(w, r)

// 		if err := sessionStore.Save(r.Context(), *sess); err != nil {
// 			panic(err)
// 		}
// 	})
// }

func LogRoutes(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		time.Since(start)

		logRow := fmt.Sprintf("%s %s %s", r.Method, time.Since(start).String(), r.URL.String())
		logger.InfoContext(r.Context(), logRow)
	})
}

func HandlePanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover := recover(); recover != nil {
				log.Println(recover)

				encoding.Encode(w, http.StatusInternalServerError, "Something went wrong, please try again")
			}
		}()

		next.ServeHTTP(w, r)
	})
}
