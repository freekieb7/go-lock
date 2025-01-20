package handler

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/google/uuid"
)

func ClientsPage(clientStore *store.ClientStore) http.Handler {
	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/clients_overview.html")
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				clients, err := clientStore.All(r.Context(), 10, 0)
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

func ClientCreatePage(clientStore *store.ClientStore) http.Handler {
	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/client_create.html")
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				tmpl.Execute(w, nil)
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
	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/client_details.html")
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIdRaw := r.PathValue("client_id")

		clientId, err := uuid.Parse(clientIdRaw)
		if err != nil {
			encoding.Encode(w, http.StatusBadRequest, fmt.Sprintf("Invalid client id : %s", clientIdRaw))
			return
		}

		client, err := clientStore.GetById(r.Context(), clientId)
		if err != nil {
			if errors.Is(err, store.ErrClientNotFound) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			panic(err)
		}

		if r.Method == http.MethodGet {
			errMsg := r.URL.Query().Get("error")

			tmpl.Execute(w, map[string]any{
				"Id":    client.Id,
				"Error": errMsg,
			})
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})
}

func ClientPageDelete(clientStore *store.ClientStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			clientIdRaw := r.PathValue("client_id")
			clientId, err := uuid.Parse(clientIdRaw)
			if err != nil {
				w.Header().Add("Location", fmt.Sprintf("/clients?error=%s", url.QueryEscape("Invalid ID provided")))
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			client, err := clientStore.GetById(r.Context(), clientId)
			if err != nil {
				if errors.Is(err, store.ErrClientNotFound) {
					w.Header().Add("Location", "/clients")
					w.WriteHeader(http.StatusSeeOther)
					return
				}

				panic(err)
			}

			if client.Type == model.ClientTypeSystem {
				w.Header().Add("Location", fmt.Sprintf("/clients/%s?error=%s", client.Id, url.QueryEscape("Forbidden form deleting a system client")))
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			if err := clientStore.DeleteById(r.Context(), client.Id); err != nil {
				panic(err)
			}

			w.Header().Add("Location", "/clients")
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})
}
