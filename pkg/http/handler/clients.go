package handler

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/freekieb7/go-lock/pkg/scope"
	"github.com/freekieb7/go-lock/pkg/session"
	"github.com/google/uuid"
)

type responseBodyClient struct {
	Id             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Secret         string    `json:"secret"`
	RedirectUris   []string  `json:"redirect_uris"`
	IsConfidential bool      `json:"is_confidential"`
	IsSystem       bool      `json:"is_system"`
	LogoUrl        string    `json:"logo_url"`
	CreatedAt      int64     `json:"created_at"`
	UpdatedAt      int64     `json:"updated_at"`
}

func Clients(clientStore *store.ClientStore) http.Handler {
	type postRequestBody struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		Secret         string   `json:"secret"`
		LogoUrl        string   `json:"logo_url"`
		IsConfidential bool     `json:"is_confidential"`
		RedirectUrls   []string `json:"redirect_urls"`
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				{
					// Permission check
					if !slices.Contains(session.FromRequest(r).Token().Scope, scope.ReadClients) {
						w.WriteHeader(http.StatusForbidden)
						return
					}

					clients, err := clientStore.All(r.Context())
					if err != nil {
						panic(err)
					}

					responseBody := make([]responseBodyClient, 0, len(clients))
					for _, client := range clients {
						responseBody = append(responseBody, responseBodyClient{
							Id:             client.Id,
							Name:           client.Name,
							Description:    client.Description,
							Secret:         client.Secret,
							RedirectUris:   client.RedirectUriList(),
							IsConfidential: client.IsConfidential,
							LogoUrl:        client.LogoUrl,
						})
					}

					encoding.Encode(w, http.StatusOK, responseBody)
				}
			case http.MethodPost:
				{
					// Permission check
					if !slices.Contains(session.FromRequest(r).Token().Scope, scope.CreateClients) {
						w.WriteHeader(http.StatusForbidden)
						return
					}

					requestBody, err := encoding.Decode[postRequestBody](r.Body)
					if err != nil {
						panic(err)
					}

					now := time.Now().Unix()
					client := model.Client{
						Id:             uuid.New(),
						Name:           requestBody.Name,
						Description:    requestBody.Description,
						Secret:         requestBody.Secret,
						IsSystem:       false,
						IsConfidential: requestBody.IsConfidential,
						LogoUrl:        requestBody.LogoUrl,
						RedirectUrls:   strings.Join(requestBody.RedirectUrls, " "),
						CreatedAt:      now,
						UpdatedAt:      now,
					}

					if client.Secret == "" {
						client.Secret = random.NewString(10)
					}

					if err := clientStore.Create(r.Context(), client); err != nil {
						panic(err)
					}

					encoding.Encode(w, http.StatusCreated, responseBodyClient{
						Id:             client.Id,
						Name:           client.Name,
						Description:    client.Description,
						Secret:         client.Secret,
						IsSystem:       client.IsSystem,
						RedirectUris:   client.RedirectUriList(),
						IsConfidential: client.IsConfidential,
						LogoUrl:        client.LogoUrl,
					})
				}
			default:
				{
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}
		},
	)
}

func Client(clientStore *store.ClientStore) http.Handler {
	type patchRequestBody struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		Secret         string   `json:"secret"`
		RedirectUrls   []string `json:"redirect_urls"`
		IsConfidential *bool    `json:"is_confidential"`
		LogoUrl        string   `json:"logo_url"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientId, err := uuid.Parse(r.PathValue("client_id"))
		if err != nil {
			panic(err)
		}

		switch r.Method {
		case http.MethodGet:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.ReadClients) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				client, err := clientStore.GetById(r.Context(), clientId)
				if err != nil {
					if errors.Is(err, store.ErrClientNotFound) {
						encoding.EncodeError(w, http.StatusNotFound, "Client not found", fmt.Sprintf("Invalid client : %s", clientId))
						return
					}

					panic(err)
				}

				encoding.Encode(w, http.StatusOK, responseBodyClient{
					Id:             client.Id,
					Name:           client.Name,
					Description:    client.Description,
					Secret:         client.Secret,
					RedirectUris:   client.RedirectUriList(),
					IsConfidential: client.IsConfidential,
					LogoUrl:        client.LogoUrl,
					CreatedAt:      client.CreatedAt,
					UpdatedAt:      client.UpdatedAt,
				})
			}
		case http.MethodPatch:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.UpdateClients) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				requestBody, err := encoding.Decode[patchRequestBody](r.Body)
				if err != nil {
					panic(err)
				}

				client, err := clientStore.GetById(r.Context(), clientId)
				if err != nil {
					if errors.Is(err, store.ErrClientNotFound) {
						encoding.EncodeError(w, http.StatusNotFound, "Client not found", fmt.Sprintf("Invalid client : %s", clientId))
						return
					}

					panic(err)
				}

				if client.IsSystem {
					panic(fmt.Errorf("cannot update system client"))
				}

				if requestBody.Name != "" {
					client.Name = requestBody.Name
				}

				if requestBody.Description != "" {
					client.Description = requestBody.Description
				}

				if requestBody.IsConfidential != nil {
					client.IsConfidential = *requestBody.IsConfidential
				}

				if requestBody.LogoUrl != "" {
					client.LogoUrl = requestBody.LogoUrl
				}

				if len(requestBody.RedirectUrls) > 0 {
					client.RedirectUrls = strings.Join(requestBody.RedirectUrls, " ")
				}

				if requestBody.Secret != "" {
					client.Secret = requestBody.Secret
				}

				client.UpdatedAt = time.Now().Unix()

				if err := clientStore.Update(r.Context(), client); err != nil {
					panic(err)
				}

				encoding.Encode(w, http.StatusOK, responseBodyClient{
					Id:             client.Id,
					Name:           client.Name,
					Description:    client.Description,
					Secret:         client.Secret,
					RedirectUris:   client.RedirectUriList(),
					IsConfidential: client.IsConfidential,
					LogoUrl:        client.LogoUrl,
					CreatedAt:      client.CreatedAt,
					UpdatedAt:      client.UpdatedAt,
				})
				return

			}
		case http.MethodDelete:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.DeleteClients) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				client, err := clientStore.GetById(r.Context(), clientId)
				if err != nil {
					panic(err)
				}

				if client.IsSystem {
					panic(fmt.Errorf("cannot update system client"))
				}

				if err := clientStore.DeleteById(r.Context(), clientId); err != nil {
					panic(err)
				}

				w.WriteHeader(http.StatusOK)
			}
		default:
			{
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}
	})
}

// func ClientsPage(clientStore *store.ClientStore) http.Handler {
// 	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/clients_overview.html")
// 	if err != nil {
// 		panic(err)
// 	}

// 	return http.HandlerFunc(
// 		func(w http.ResponseWriter, r *http.Request) {
// 			if r.Method == http.MethodGet {
// 				clients, err := clientStore.All(r.Context(), 10, 0)
// 				if err != nil {
// 					panic(err)
// 				}

// 				clientsData := make([]map[string]any, len(clients))
// 				for idx, client := range clients {
// 					clientsData[idx] = map[string]any{
// 						"Id":   client.Id,
// 						"Name": client.Name,
// 						"Type": client.Type,
// 					}
// 				}

// 				tmpl.Execute(w, map[string]any{
// 					"Clients": clientsData,
// 				})
// 				return
// 			}

// 			if r.Method == http.MethodPost {
// 				r.ParseForm()

// 				name := r.FormValue("name")
// 				now := time.Now().Unix()
// 				client := model.Client{
// 					Id:             uuid.New(),
// 					Secret:         random.NewString(10),
// 					Type:           model.ClientTypeCustom,
// 					Name:           name,
// 					RedirectUrls:   "",
// 					IsConfidential: false,
// 					CreatedAt:      now,
// 					UpdatedAt:      now,
// 				}
// 				if err := clientStore.Create(r.Context(), client); err != nil {
// 					panic(err)
// 				}

// 				w.Header().Add("Location", fmt.Sprintf("/clients/%s", client.Id))
// 				w.WriteHeader(http.StatusSeeOther)
// 				return
// 			}

// 			w.WriteHeader(http.StatusMethodNotAllowed)
// 		},
// 	)
// }

// func ClientCreatePage(clientStore *store.ClientStore) http.Handler {
// 	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/client_create.html")
// 	if err != nil {
// 		panic(err)
// 	}

// 	return http.HandlerFunc(
// 		func(w http.ResponseWriter, r *http.Request) {
// 			if r.Method == http.MethodGet {
// 				tmpl.Execute(w, nil)
// 				return
// 			}

// 			if r.Method == http.MethodPost {
// 				r.ParseForm()

// 				name := r.FormValue("name")

// 				now := time.Now().Unix()
// 				client := model.Client{
// 					Id:             uuid.New(),
// 					Secret:         random.NewString(10),
// 					Type:           model.ClientTypeCustom,
// 					Name:           name,
// 					RedirectUrls:   "",
// 					IsConfidential: false,
// 					CreatedAt:      now,
// 					UpdatedAt:      now,
// 				}
// 				if err := clientStore.Create(r.Context(), client); err != nil {
// 					panic(err)
// 				}

// 				w.Header().Add("Location", fmt.Sprintf("/clients/%s", client.Id))
// 				w.WriteHeader(http.StatusSeeOther)
// 				return
// 			}

// 			w.WriteHeader(http.StatusMethodNotAllowed)
// 		},
// 	)
// }

// func ClientPage(clientStore *store.ClientStore) http.Handler {
// 	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/client_details.html")
// 	if err != nil {
// 		panic(err)
// 	}

// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		clientIdRaw := r.PathValue("client_id")

// 		clientId, err := uuid.Parse(clientIdRaw)
// 		if err != nil {
// 			encoding.Encode(w, http.StatusBadRequest, fmt.Sprintf("Invalid client id : %s", clientIdRaw))
// 			return
// 		}

// 		client, err := clientStore.GetById(r.Context(), clientId)
// 		if err != nil {
// 			if errors.Is(err, store.ErrClientNotFound) {
// 				w.WriteHeader(http.StatusBadRequest)
// 				return
// 			}

// 			panic(err)
// 		}

// 		if r.Method == http.MethodGet {
// 			errMsg := r.URL.Query().Get("error")

// 			tmpl.Execute(w, map[string]any{
// 				"Id":    client.Id,
// 				"Error": errMsg,
// 			})
// 			return
// 		}

// 		w.WriteHeader(http.StatusMethodNotAllowed)
// 	})
// }

// func ClientPageDelete(clientStore *store.ClientStore) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		if r.Method == http.MethodPost {
// 			clientIdRaw := r.PathValue("client_id")
// 			clientId, err := uuid.Parse(clientIdRaw)
// 			if err != nil {
// 				w.Header().Add("Location", fmt.Sprintf("/clients?error=%s", url.QueryEscape("Invalid ID provided")))
// 				w.WriteHeader(http.StatusSeeOther)
// 				return
// 			}

// 			client, err := clientStore.GetById(r.Context(), clientId)
// 			if err != nil {
// 				if errors.Is(err, store.ErrClientNotFound) {
// 					w.Header().Add("Location", "/clients")
// 					w.WriteHeader(http.StatusSeeOther)
// 					return
// 				}

// 				panic(err)
// 			}

// 			if client.Type == model.ClientTypeSystem {
// 				w.Header().Add("Location", fmt.Sprintf("/clients/%s?error=%s", client.Id, url.QueryEscape("Forbidden form deleting a system client")))
// 				w.WriteHeader(http.StatusSeeOther)
// 				return
// 			}

// 			if err := clientStore.DeleteById(r.Context(), client.Id); err != nil {
// 				panic(err)
// 			}

// 			w.Header().Add("Location", "/clients")
// 			w.WriteHeader(http.StatusSeeOther)
// 			return
// 		}

// 		w.WriteHeader(http.StatusMethodNotAllowed)
// 	})
// }
