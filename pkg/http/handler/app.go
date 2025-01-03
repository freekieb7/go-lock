package handler

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/http/session"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/freekieb7/go-lock/pkg/settings"
)

func Home() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				errMsg := r.URL.Query().Get("error")

				tmpl, err := template.ParseFiles("templates/base.html", "templates/home.html")
				if err != nil {
					w.WriteHeader(500)
					return
				}

				tmpl.Execute(w, map[string]any{
					"Error": errMsg,
				})
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}

func Callback(settings *settings.Settings, clientStore *store.ClientStore) http.Handler {
	type tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IdToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
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
				panic("session: state does not exist")
			}
			state := sess.Get("state")
			sess.Delete("state")

			if state != stateRaw {
				encoding.Encode(w, http.StatusBadRequest, fmt.Sprintf("Invalid state : %s", stateRaw))
				return
			}

			client, err := clientStore.GetManagerCredentials(r.Context())
			if err != nil {
				encoding.Encode(w, http.StatusBadRequest, fmt.Sprintf("Invalid state : %s", stateRaw))
				return
			}

			resp, err := http.Post(fmt.Sprintf("%s/auth/oauth/token?grant_type=authorization_code&client_id=%s&client_secret=%s&code=%s&redirect_uri=%s&audience=%s", settings.Host, client.Id, client.Secret, codeRaw, client.RedirectUris[0], settings.Host+"/api"), "plain/text", nil)
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

			sess.Set("user_id", random.NewString(10)) // todo change this bullshit
			sess.Set("api_access_token", tknRes.AccessToken)

			w.Header().Add("Location", "/app")
			w.WriteHeader(http.StatusSeeOther)
		},
	)
}
