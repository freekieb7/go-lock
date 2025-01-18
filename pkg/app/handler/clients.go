package handler

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/app/model"
	"github.com/freekieb7/go-lock/pkg/core/data/data_source/api"
	"github.com/freekieb7/go-lock/pkg/core/data/store"
	"github.com/freekieb7/go-lock/pkg/core/http/encoding"
	"github.com/freekieb7/go-lock/pkg/core/session"
	"github.com/google/uuid"
)

func Clients(lockApi *api.LockApi) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				sessUser := session.FromRequest(r).Get("user").(model.SessionUser)

				resClients, err := lockApi.GetClients(sessUser.AccessToken, api.GetClientsRequestBody{
					Limit:  10,
					Offset: 0,
				})
				if err != nil {
					panic(err)
				}

				tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/clients.html")
				if err != nil {
					panic(err)
				}

				clientsData := make([]map[string]any, len(resClients.Clients))
				for idx, client := range resClients.Clients {
					clientsData[idx] = map[string]any{
						"Id":   client.Id,
						"Name": client.Name,
						"Type": client.Type,
					}
				}

				tmpl.Execute(w, map[string]any{
					"Clients": clientsData,
				})
				return
			}

			if r.Method == http.MethodPost {
				sessUser := session.FromRequest(r).Get("user").(model.SessionUser)

				r.ParseForm()

				name := r.FormValue("name")
				createClientsRes, err := lockApi.CreateClient(sessUser.AccessToken, api.CreateClientRequestBody{
					Name: name,
				})
				if err != nil {
					panic(err)
				}

				w.Header().Add("Location", fmt.Sprintf("/clients/%s", createClientsRes.Id))
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}

func Client(clientStore *store.ClientStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			clientIdRaw := r.PathValue("client_id")

			clientId, err := uuid.Parse(clientIdRaw)
			if err != nil {
				encoding.Encode(w, http.StatusBadRequest, fmt.Sprintf("Invalid client id : %s", clientIdRaw))
				return
			}

			client, err := clientStore.GetById(r.Context(), clientId)
			if err != nil {
				panic(err)
			}

			tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/client.html")
			if err != nil {
				w.WriteHeader(500)
				return
			}

			tmpl.Execute(w, map[string]any{
				"Client": map[string]any{
					"Id": client.Id,
				},
			})
			return
		}

		if r.Method == http.MethodDelete {

		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})
}
