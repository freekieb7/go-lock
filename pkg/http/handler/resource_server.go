package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/scope"
	"github.com/freekieb7/go-lock/pkg/session"
	"github.com/google/uuid"
)

type httpBodyResourceServerScope struct {
	Value      string `json:"value"`
	Desciption string `json:"description"`
}

type responseBodyResourceServer struct {
	Id                       uuid.UUID                     `json:"id"`
	Name                     string                        `json:"name"`
	Desciption               string                        `json:"description"`
	Url                      string                        `json:"url"`
	IsSystem                 bool                          `json:"is_system"`
	Scopes                   []httpBodyResourceServerScope `json:"scopes"`
	SigningAlgorithm         string                        `json:"signing_algorithm"`
	AllowOfflineAccess       bool                          `json:"allow_offline_access"`
	AllowSkippingUserConsent bool                          `json:"allow_skipping_user_consent"`
	UpdatedAt                int64                         `json:"updated_at"`
	CreatedAt                int64                         `json:"created_at"`
}

func ResourceServers(resourceServerStore *store.ResourceServerStore) http.Handler {
	type getResponseBody struct {
		ResourceServers []responseBodyResourceServer `json:"resource_servers"`
	}

	type postRequestBody struct {
		Id                       uuid.UUID                     `json:"id"`
		Name                     string                        `json:"name"`
		Desciption               string                        `json:"description"`
		Url                      string                        `json:"url"`
		Scopes                   []httpBodyResourceServerScope `json:"scopes"`
		SigningAlgorithm         string                        `json:"signing_algorithm"`
		AllowOfflineAccess       bool                          `json:"allow_offline_access"`
		AllowSkippingUserConsent bool                          `json:"allow_skipping_user_consent"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.ReadResourceServers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				resourceServers, err := resourceServerStore.All(r.Context())
				if err != nil {
					panic(err)
				}

				var responseBody getResponseBody
				responseBody.ResourceServers = make([]responseBodyResourceServer, 0, len(resourceServers))
				for _, resourceServer := range resourceServers {
					responseScopes := make([]httpBodyResourceServerScope, 0, len(resourceServer.Scopes))
					for _, scope := range resourceServer.Scopes {
						responseScopes = append(responseScopes, httpBodyResourceServerScope{
							Value:      scope.Value,
							Desciption: scope.Description,
						})
					}

					responseBody.ResourceServers = append(responseBody.ResourceServers, responseBodyResourceServer{
						Id:                       resourceServer.Id,
						Url:                      resourceServer.Url,
						Name:                     resourceServer.Name,
						Desciption:               resourceServer.Description,
						IsSystem:                 resourceServer.IsSystem,
						Scopes:                   responseScopes,
						SigningAlgorithm:         string(resourceServer.SigningAlgorithm),
						AllowSkippingUserConsent: resourceServer.AllowSkippingUserConsent,
						AllowOfflineAccess:       resourceServer.AllowOfflineAccess,
						CreatedAt:                resourceServer.CreatedAt,
						UpdatedAt:                resourceServer.UpdatedAt,
					})
				}

				encoding.Encode(w, http.StatusOK, responseBody)
			}
		case http.MethodPost:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.CreateResourceServers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				requestBody, err := encoding.Decode[postRequestBody](r.Body)
				if err != nil {
					panic(err)
				}

				scopes := make([]model.ResourceServerScope, 0, len(requestBody.Scopes))
				for _, scope := range requestBody.Scopes {
					scopes = append(scopes, model.ResourceServerScope{
						Value:       scope.Value,
						Description: scope.Desciption,
					})
				}

				now := time.Now().Unix()
				resourceServer := model.ResourceServer{
					Id:                       requestBody.Id,
					Name:                     requestBody.Name,
					Description:              requestBody.Desciption,
					Url:                      requestBody.Url,
					IsSystem:                 false,
					Scopes:                   scopes,
					AllowSkippingUserConsent: requestBody.AllowSkippingUserConsent,
					AllowOfflineAccess:       requestBody.AllowOfflineAccess,
					SigningAlgorithm:         model.SigningAlgorithmRS256,
					CreatedAt:                now,
					UpdatedAt:                now,
				}
				if err := resourceServerStore.Create(r.Context(), resourceServer); err != nil {
					panic(err)
				}

				responseScopes := make([]httpBodyResourceServerScope, 0, len(resourceServer.Scopes))
				for _, scope := range resourceServer.Scopes {
					responseScopes = append(responseScopes, httpBodyResourceServerScope{
						Value:      scope.Value,
						Desciption: scope.Description,
					})
				}

				encoding.Encode(w, http.StatusOK, responseBodyResourceServer{
					Id:                       resourceServer.Id,
					Url:                      resourceServer.Url,
					Name:                     resourceServer.Name,
					Desciption:               resourceServer.Description,
					IsSystem:                 resourceServer.IsSystem,
					Scopes:                   responseScopes,
					SigningAlgorithm:         string(resourceServer.SigningAlgorithm),
					AllowSkippingUserConsent: resourceServer.AllowSkippingUserConsent,
					AllowOfflineAccess:       resourceServer.AllowOfflineAccess,
					CreatedAt:                resourceServer.CreatedAt,
					UpdatedAt:                resourceServer.UpdatedAt,
				})
			}
		default:
			{
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}
	})
}

func ResourceServer(resourceServerStore *store.ResourceServerStore) http.Handler {
	type patchRequestBodyScope struct {
		Value      string `json:"value"`
		Desciption string `json:"description"`
	}

	type patchRequestBody struct {
		Url                      string                  `json:"url"`
		Name                     string                  `json:"name"`
		Description              string                  `json:"description"`
		Scopes                   []patchRequestBodyScope `json:"scopes"`
		AllowSkippingUserConsent *bool                   `json:"allow_skipping_user_consent"`
		AllowOfflineAccess       *bool                   `json:"allow_offline_access"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resourceServerId, err := uuid.Parse(r.PathValue("resource_server_id"))
		if err != nil {
			panic(err)
		}

		switch r.Method {
		case http.MethodGet:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.ReadResourceServers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				resourceServer, err := resourceServerStore.GetById(r.Context(), resourceServerId)
				if err != nil {
					if errors.Is(err, store.ErrResourceServerNotFound) {
						encoding.EncodeError(w, http.StatusNotFound, "Resource Server not found", fmt.Sprintf("Invalid Resource Server ID : %s", resourceServerId))
					}
				}

				responseScopes := make([]httpBodyResourceServerScope, 0, len(resourceServer.Scopes))
				for _, scope := range resourceServer.Scopes {
					responseScopes = append(responseScopes, httpBodyResourceServerScope{
						Value:      scope.Value,
						Desciption: scope.Description,
					})
				}

				encoding.Encode(w, http.StatusOK, responseBodyResourceServer{
					Id:                       resourceServer.Id,
					Url:                      resourceServer.Url,
					Name:                     resourceServer.Name,
					Desciption:               resourceServer.Description,
					IsSystem:                 resourceServer.IsSystem,
					Scopes:                   responseScopes,
					SigningAlgorithm:         string(resourceServer.SigningAlgorithm),
					AllowSkippingUserConsent: resourceServer.AllowSkippingUserConsent,
					AllowOfflineAccess:       resourceServer.AllowOfflineAccess,
					CreatedAt:                resourceServer.CreatedAt,
					UpdatedAt:                resourceServer.UpdatedAt,
				})
			}
		case http.MethodPatch:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.UpdateResourceServers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				requestBody, err := encoding.Decode[patchRequestBody](r.Body)
				if err != nil {
					panic(err)
				}

				resourceServer, err := resourceServerStore.GetById(r.Context(), resourceServerId)
				if err != nil {
					if errors.Is(err, store.ErrResourceServerNotFound) {
						encoding.EncodeError(w, http.StatusNotFound, "Resource Server not found", fmt.Sprintf("Invalid Resource Server ID : %s", resourceServerId))
					}
				}

				if requestBody.Name != "" {
					resourceServer.Name = requestBody.Name
				}

				if requestBody.Description != "" {
					resourceServer.Description = requestBody.Description
				}

				if requestBody.Url != "" {
					resourceServer.Url = requestBody.Url
				}

				if requestBody.AllowSkippingUserConsent != nil {
					resourceServer.AllowSkippingUserConsent = *requestBody.AllowSkippingUserConsent
				}

				if requestBody.AllowOfflineAccess != nil {
					resourceServer.AllowOfflineAccess = *requestBody.AllowOfflineAccess
				}

				if requestBody.Scopes != nil {
					log.Println("scopes is not nil")
					resourceServer.Scopes = make([]model.ResourceServerScope, 0, len(requestBody.Scopes))

					for _, scope := range requestBody.Scopes {
						resourceServer.Scopes = append(resourceServer.Scopes, model.ResourceServerScope{
							Value:       scope.Value,
							Description: scope.Desciption,
						})
					}
				}

				resourceServer.UpdatedAt = time.Now().Unix()

				if err := resourceServerStore.Update(r.Context(), resourceServer); err != nil {
					panic(err)
				}

				responseScopes := make([]httpBodyResourceServerScope, 0, len(resourceServer.Scopes))
				for _, scope := range resourceServer.Scopes {
					responseScopes = append(responseScopes, httpBodyResourceServerScope{
						Value:      scope.Value,
						Desciption: scope.Description,
					})
				}

				encoding.Encode(w, http.StatusOK, responseBodyResourceServer{
					Id:                       resourceServer.Id,
					Url:                      resourceServer.Url,
					Name:                     resourceServer.Name,
					Desciption:               resourceServer.Description,
					IsSystem:                 resourceServer.IsSystem,
					Scopes:                   responseScopes,
					SigningAlgorithm:         string(resourceServer.SigningAlgorithm),
					AllowSkippingUserConsent: resourceServer.AllowSkippingUserConsent,
					AllowOfflineAccess:       resourceServer.AllowOfflineAccess,
					CreatedAt:                resourceServer.CreatedAt,
					UpdatedAt:                resourceServer.UpdatedAt,
				})
			}
		case http.MethodDelete:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.DeleteResourceServers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				if err := resourceServerStore.DeleteById(r.Context(), resourceServerId); err != nil {
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

// func ResourceServersPage(resourceServerStore *store.ResourceServerStore) http.Handler {
// 	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/resource_servers_overview.html")
// 	if err != nil {
// 		panic(err)
// 	}

// 	return http.HandlerFunc(
// 		func(w http.ResponseWriter, r *http.Request) {
// 			if r.Method == http.MethodGet {
// 				resourceServers, err := resourceServerStore.All(r.Context(), 10, 0)
// 				if err != nil {
// 					panic(err)
// 				}

// 				resourceServersData := make([]map[string]any, len(resourceServers))
// 				for idx, resourceServer := range resourceServers {
// 					resourceServersData[idx] = map[string]any{
// 						"Id":   resourceServer.Id,
// 						"Name": resourceServer.Name,
// 						"Url":  resourceServer.Url,
// 						"Type": resourceServer.Type.UserFriendlyName(),
// 					}
// 				}

// 				tmpl.Execute(w, map[string]any{
// 					"ResourceServers": resourceServersData,
// 				})
// 				return
// 			}

// 			w.WriteHeader(http.StatusMethodNotAllowed)
// 		},
// 	)
// }

// func ResourceServerCreatePage(resourceServerStore *store.ResourceServerStore) http.Handler {
// 	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/resource_server_create.html")
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

// 				nameRaw := r.FormValue("name")
// 				urlRaw := r.FormValue("url")

// 				now := time.Now().Unix()
// 				resourceServer := model.ResourceServer{
// 					Id:                       uuid.New(),
// 					Url:                      urlRaw,
// 					Type:                     model.ResourceServerTypeCustomServer,
// 					Name:                     nameRaw,
// 					SigningAlgorithm:         model.SigningAlgorithmRS256,
// 					AllowSkippingUserConsent: false,
// 					CreatedAt:                now,
// 					UpdatedAt:                now,
// 				}
// 				if err := resourceServerStore.Create(r.Context(), resourceServer, make([]model.ResourceServerScope, 0)); err != nil {
// 					panic(err)
// 				}

// 				w.Header().Add("Location", fmt.Sprintf("/resourceServers/%s", resourceServer.Id))
// 				w.WriteHeader(http.StatusSeeOther)
// 				return
// 			}

// 			w.WriteHeader(http.StatusMethodNotAllowed)
// 		},
// 	)
// }

// func ResourceServerPage(resourceServerStore *store.ResourceServerStore) http.Handler {
// 	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/resource_server_details.html")
// 	if err != nil {
// 		panic(err)
// 	}

// 	return http.HandlerFunc(
// 		func(w http.ResponseWriter, r *http.Request) {
// 			resourceServerIdRaw := r.PathValue("resource_server_id")
// 			resourceServerId, err := uuid.Parse(resourceServerIdRaw)
// 			if err != nil {
// 				panic(err)
// 			}

// 			resourceServer, err := resourceServerStore.GetById(r.Context(), resourceServerId)
// 			if err != nil {
// 				if errors.Is(err, store.ErrResourceServerNotFound) {
// 					w.WriteHeader(http.StatusBadRequest)
// 					return
// 				}

// 				panic(err)
// 			}

// 			if r.Method == http.MethodGet {
// 				errMsg := r.URL.Query().Get("error")

// 				tmpl.Execute(w, map[string]any{
// 					"Id":    resourceServer.Id,
// 					"Error": errMsg,
// 				})
// 				return
// 			}

// 			w.WriteHeader(http.StatusMethodNotAllowed)
// 		},
// 	)
// }

// func ResourceServerPageDelete(resourceServerStore *store.ResourceServerStore) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		if r.Method == http.MethodPost {
// 			resourceServerIdRaw := r.PathValue("resource_server_id")
// 			resourceServerId, err := uuid.Parse(resourceServerIdRaw)
// 			if err != nil {
// 				w.Header().Add("Location", fmt.Sprintf("/resourceServers?error=%s", url.QueryEscape("Invalid ID provided")))
// 				w.WriteHeader(http.StatusSeeOther)
// 				return
// 			}

// 			resourceServer, err := resourceServerStore.GetById(r.Context(), resourceServerId)
// 			if err != nil {
// 				if errors.Is(err, store.ErrResourceServerNotFound) {
// 					w.Header().Add("Location", "/resourceServers")
// 					w.WriteHeader(http.StatusSeeOther)
// 					return
// 				}

// 				panic(err)
// 			}

// 			if resourceServer.Type == model.ResourceServerTypeSystemServer {
// 				w.Header().Add("Location", fmt.Sprintf("/resourceServers/%s?error=%s", resourceServer.Id, url.QueryEscape("Forbidden form deleting a system resource server")))
// 				w.WriteHeader(http.StatusSeeOther)
// 				return
// 			}

// 			if err := resourceServerStore.DeleteById(r.Context(), resourceServer.Id); err != nil {
// 				panic(err)
// 			}

// 			w.Header().Add("Location", "/resourceServers")
// 			w.WriteHeader(http.StatusSeeOther)
// 			return
// 		}

// 		w.WriteHeader(http.StatusMethodNotAllowed)
// 	})
// }
