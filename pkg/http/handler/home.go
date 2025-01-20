package handler

import (
	"fmt"
	"html/template"
	"log"
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

func HomePage() http.Handler {
	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/home.html")
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				errMsg := r.URL.Query().Get("error")

				tmpl.Execute(w, map[string]any{
					"Error": errMsg,
				})
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}

func Callback(oauthProvider *oauth.OAuthProvider, settings *settings.Settings, clientStore *store.ClientStore) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				sess := session.FromRequest(r)

				if !r.URL.Query().Has("code") {
					encoding.Encode(w, http.StatusBadRequest, "Required param : code")
					return
				}
				codeRaw := r.URL.Query().Get("code")

				if !r.URL.Query().Has("state") {
					encoding.Encode(w, http.StatusBadRequest, "Required param : state")
					return
				}
				stateRaw := r.URL.Query().Get("state")

				if !sess.Has("state") {
					log.Panic("session: state does not exist")
				}
				sessState := sess.Get("state")
				sess.Delete("state")

				if sessState != stateRaw {
					encoding.Encode(w, http.StatusBadRequest, fmt.Sprintf("Invalid state : %s", stateRaw))
					return
				}

				tokenResponse, err := oauthProvider.Tokens(codeRaw)
				if err != nil {
					log.Println(err)
					encoding.Encode(w, http.StatusBadRequest, "There are communication issues with authorization server")
					return
				}

				idToken, err := jwt.Decode(tokenResponse.IdToken)
				if err != nil {
					log.Println(err)
					encoding.Encode(w, http.StatusInternalServerError, "Internal server error")
					return
				}

				subject := idToken.Payload["sub"].(string)
				userId, err := uuid.Parse(subject)
				if err != nil {
					log.Println(err)
					encoding.Encode(w, http.StatusInternalServerError, "Internal server error")
					return
				}

				// todo validate tokens

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

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}
