package handler

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/google/uuid"
)

func ClientsPage(clientStore *store.ClientStore) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				clients, err := clientStore.All(r.Context(), 10, 0)
				if err != nil {
					panic(err)
				}

				tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/clients.html")
				if err != nil {
					panic(err)
				}

				clientsData := make([]map[string]any, len(clients))
				for idx, client := range clients {
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
				r.ParseForm()

				name := r.FormValue("name")
				now := time.Now().Unix()
				client := model.Client{
					Id:             uuid.New(),
					Secret:         random.NewString(10),
					Type:           model.ClientTypeCustom,
					Name:           name,
					RedirectUrls:   "",
					IsConfidential: false,
					CreatedAt:      now,
					UpdatedAt:      now,
					DeletedAt:      0,
				}
				if err := clientStore.Create(r.Context(), client); err != nil {
					panic(err)
				}

				w.Header().Add("Location", fmt.Sprintf("/clients/%s", client.Id))
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}

func ClientPage(clientStore *store.ClientStore) http.Handler {
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

func Clients(clientStore *store.ClientStore) http.Handler {
	type postReqPayload struct {
		Name string `json:"name"`
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				clients, err := clientStore.All(r.Context(), 10, 0)
				if err != nil {
					panic(err)
				}

				resPayload := make([]map[string]any, len(clients))
				for idx, client := range clients {
					resPayload[idx] = map[string]any{
						"id":            client.Id,
						"name":          client.Name,
						"secret":        client.Secret,
						"redirect_urls": client.RedirectUrls,
					}
				}

				encoding.Encode(w, http.StatusOK, resPayload)
				return
			}

			if r.Method == "POST" {
				reqPayload, err := encoding.Decode[postReqPayload](r.Body)
				if err != nil {
					panic(err)
				}

				now := time.Now().Unix()
				client := model.Client{
					Id:             uuid.New(),
					Name:           reqPayload.Name,
					Secret:         random.NewString(15),
					Type:           model.ClientTypeCustom,
					IsConfidential: true,
					RedirectUrls:   "",
					CreatedAt:      now,
					UpdatedAt:      now,
					DeletedAt:      0,
				}

				if err := clientStore.Create(r.Context(), client); err != nil {
					panic(err)
				}

				resPayload := map[string]any{
					"id": client.Id,
				}

				encoding.Encode(w, http.StatusCreated, resPayload)
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}
