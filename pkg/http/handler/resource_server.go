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
	"github.com/google/uuid"
)

func ResourceServersPage(resourceServerStore *store.ResourceServerStore) http.Handler {
	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/resource_servers_overview.html")
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				resourceServers, err := resourceServerStore.All(r.Context(), 10, 0)
				if err != nil {
					panic(err)
				}

				resourceServersData := make([]map[string]any, len(resourceServers))
				for idx, resourceServer := range resourceServers {
					resourceServersData[idx] = map[string]any{
						"Id":   resourceServer.Id,
						"Name": resourceServer.Name,
						"Url":  resourceServer.Url,
						"Type": resourceServer.Type.UserFriendlyName(),
					}
				}

				tmpl.Execute(w, map[string]any{
					"ResourceServers": resourceServersData,
				})
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}

func ResourceServerCreatePage(resourceServerStore *store.ResourceServerStore) http.Handler {
	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/resource_server_create.html")
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

				nameRaw := r.FormValue("name")
				urlRaw := r.FormValue("url")

				now := time.Now().Unix()
				user := model.ResourceServer{
					Id:                       uuid.New(),
					Url:                      urlRaw,
					Type:                     model.ResourceServerTypeCustomServer,
					Name:                     nameRaw,
					SigningAlgorithm:         model.SigningAlgorithmRS256,
					Scopes:                   "",
					AllowSkippingUserConsent: false,
					CreatedAt:                now,
					UpdatedAt:                now,
					DeletedAt:                0,
				}
				if err := resourceServerStore.Create(r.Context(), user); err != nil {
					panic(err)
				}

				w.Header().Add("Location", fmt.Sprintf("/resourceServers/%s", user.Id))
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}

func ResourceServerPage(resourceServerStore *store.ResourceServerStore) http.Handler {
	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/resource_server_details.html")
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			resourceServerIdRaw := r.PathValue("resource_server_id")
			resourceServerId, err := uuid.Parse(resourceServerIdRaw)
			if err != nil {
				panic(err)
			}

			resourceServer, err := resourceServerStore.GetById(r.Context(), resourceServerId)
			if err != nil {
				if errors.Is(err, store.ErrResourceServerNotFound) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				panic(err)
			}

			if r.Method == http.MethodGet {
				errMsg := r.URL.Query().Get("error")

				tmpl.Execute(w, map[string]any{
					"Id":    resourceServer.Id,
					"Error": errMsg,
				})
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}

func ResourceServerPageDelete(resourceServerStore *store.ResourceServerStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			resourceServerIdRaw := r.PathValue("resource_server_id")
			resourceServerId, err := uuid.Parse(resourceServerIdRaw)
			if err != nil {
				w.Header().Add("Location", fmt.Sprintf("/resourceServers?error=%s", url.QueryEscape("Invalid ID provided")))
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			resourceServer, err := resourceServerStore.GetById(r.Context(), resourceServerId)
			if err != nil {
				if errors.Is(err, store.ErrResourceServerNotFound) {
					w.Header().Add("Location", "/resourceServers")
					w.WriteHeader(http.StatusSeeOther)
					return
				}

				panic(err)
			}

			if resourceServer.Type == model.ResourceServerTypeSystemServer {
				w.Header().Add("Location", fmt.Sprintf("/resourceServers/%s?error=%s", resourceServer.Id, url.QueryEscape("Forbidden form deleting a system resource server")))
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			if err := resourceServerStore.DeleteById(r.Context(), resourceServer.Id); err != nil {
				panic(err)
			}

			w.Header().Add("Location", "/resourceServers")
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})
}
