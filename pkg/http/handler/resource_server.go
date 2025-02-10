package handler

import (
	"errors"
	"fmt"
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

type responseBodyResourceServer struct {
	Id                       uuid.UUID `json:"id"`
	Name                     string    `json:"name"`
	Desciption               string    `json:"description"`
	Url                      string    `json:"url"`
	IsSystem                 bool      `json:"is_system"`
	SigningAlgorithm         string    `json:"signing_algorithm"`
	AllowOfflineAccess       bool      `json:"allow_offline_access"`
	AllowSkippingUserConsent bool      `json:"allow_skipping_user_consent"`
	UpdatedAt                int64     `json:"updated_at"`
	CreatedAt                int64     `json:"created_at"`
}

func ResourceServers(resourceServerStore *store.ResourceServerStore) http.Handler {
	type getResponseBody struct {
		ResourceServers []responseBodyResourceServer `json:"resource_servers"`
	}

	type postRequestBody struct {
		Id                       uuid.UUID `json:"id"`
		Name                     string    `json:"name"`
		Desciption               string    `json:"description"`
		Url                      string    `json:"url"`
		SigningAlgorithm         string    `json:"signing_algorithm"`
		AllowOfflineAccess       bool      `json:"allow_offline_access"`
		AllowSkippingUserConsent bool      `json:"allow_skipping_user_consent"`
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
					responseBody.ResourceServers = append(responseBody.ResourceServers, responseBodyResourceServer{
						Id:                       resourceServer.Id,
						Url:                      resourceServer.Url,
						Name:                     resourceServer.Name,
						Desciption:               resourceServer.Description,
						IsSystem:                 resourceServer.IsSystem,
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

				now := time.Now().Unix()
				resourceServer := model.ResourceServer{
					Id:                       requestBody.Id,
					Name:                     requestBody.Name,
					Description:              requestBody.Desciption,
					Url:                      requestBody.Url,
					IsSystem:                 false,
					AllowSkippingUserConsent: requestBody.AllowSkippingUserConsent,
					AllowOfflineAccess:       requestBody.AllowOfflineAccess,
					SigningAlgorithm:         model.SigningAlgorithmRS256,
					CreatedAt:                now,
					UpdatedAt:                now,
				}

				encoding.Encode(w, http.StatusOK, responseBodyResourceServer{
					Id:                       resourceServer.Id,
					Url:                      resourceServer.Url,
					Name:                     resourceServer.Name,
					Desciption:               resourceServer.Description,
					IsSystem:                 resourceServer.IsSystem,
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
	type patchRequestBody struct {
		Url                      string `json:"url"`
		Name                     string `json:"name"`
		Description              string `json:"description"`
		AllowSkippingUserConsent *bool  `json:"allow_skipping_user_consent"`
		AllowOfflineAccess       *bool  `json:"allow_offline_access"`
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
						return
					}

					panic(err)
				}

				encoding.Encode(w, http.StatusOK, responseBodyResourceServer{
					Id:                       resourceServer.Id,
					Url:                      resourceServer.Url,
					Name:                     resourceServer.Name,
					Desciption:               resourceServer.Description,
					IsSystem:                 resourceServer.IsSystem,
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

				resourceServer.UpdatedAt = time.Now().Unix()

				if err := resourceServerStore.Update(r.Context(), resourceServer); err != nil {
					panic(err)
				}

				encoding.Encode(w, http.StatusOK, responseBodyResourceServer{
					Id:                       resourceServer.Id,
					Url:                      resourceServer.Url,
					Name:                     resourceServer.Name,
					Desciption:               resourceServer.Description,
					IsSystem:                 resourceServer.IsSystem,
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

func ResourceServerPermissions(resourceServerStore *store.ResourceServerStore) http.Handler {
	type getReponseBodyPermissions struct {
		Id          uuid.UUID `json:"id"`
		Value       string    `json:"value"`
		Description string    `json:"description"`
	}

	type getResponseBody struct {
		Permissions []getReponseBodyPermissions `json:"permissions"`
	}

	type postRequestBody struct {
		Id          uuid.UUID `json:"id"`
		Value       string    `json:"value"`
		Description string    `json:"description"`
	}

	type postResponseBody struct {
		Id          uuid.UUID `json:"id"`
		Value       string    `json:"value"`
		Description string    `json:"description"`
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

				permissions, err := resourceServerStore.AllPermissions(r.Context(), resourceServerId)
				if err != nil {
					panic(err)
				}

				var responseBody getResponseBody
				responseBody.Permissions = make([]getReponseBodyPermissions, 0, len(permissions))
				for _, permission := range permissions {
					responseBody.Permissions = append(responseBody.Permissions, getReponseBodyPermissions{
						Id:          permission.Id,
						Value:       permission.Value,
						Description: permission.Description,
					})
				}

				encoding.Encode(w, http.StatusOK, responseBody)
			}
		case http.MethodPost:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.UpdateResourceServers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				requestBody, err := encoding.Decode[postRequestBody](r.Body)
				if err != nil {
					panic(err)
				}

				permission := model.Permission{
					Id:               requestBody.Id,
					ResourceServerId: resourceServerId,
					Value:            requestBody.Value,
					Description:      requestBody.Description,
				}

				if err := resourceServerStore.CreatePermission(r.Context(), permission); err != nil {
					panic(err)
				}

				encoding.Encode(w, http.StatusCreated, postResponseBody{
					Id:          permission.Id,
					Value:       permission.Value,
					Description: permission.Description,
				})
			}
		}
	})
}

func ResourceServerPermission(resourceServerStore *store.ResourceServerStore) http.Handler {
	type patchRequestBody struct {
		Value       string `json:"value"`
		Description string `json:"description"`
	}

	type responseBody struct {
		Id               uuid.UUID `json:"id"`
		ResourceServerId uuid.UUID `json:"resource_server_id"`
		Value            string    `json:"value"`
		Description      string    `json:"description"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resourceServerId, err := uuid.Parse(r.PathValue("resource_server_id"))
		if err != nil {
			panic(err)
		}

		permissionId, err := uuid.Parse(r.PathValue("permission_id"))
		if err != nil {
			panic(err)
		}

		switch r.Method {
		case http.MethodGet:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.UpdateResourceServers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				permission, err := resourceServerStore.GetPermissionById(r.Context(), permissionId)
				if err != nil {
					panic(err)
				}

				if permission.ResourceServerId != resourceServerId {
					encoding.EncodeError(w, http.StatusNotFound, "Not Found", fmt.Sprintf("Invalid permission : %s", permissionId))
				}

				encoding.Encode(w, http.StatusOK, responseBody{
					Id:               permission.Id,
					ResourceServerId: permission.ResourceServerId,
					Value:            permission.Value,
					Description:      permission.Description,
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

				permission, err := resourceServerStore.GetPermissionById(r.Context(), permissionId)
				if err != nil {
					panic(err)
				}

				if permission.ResourceServerId != resourceServerId {
					encoding.EncodeError(w, http.StatusNotFound, "Not Found", fmt.Sprintf("Invalid permission : %s", permissionId))
				}

				if requestBody.Value != "" {
					permission.Value = requestBody.Value
				}

				if requestBody.Description != "" {
					permission.Description = requestBody.Description
				}

				if err := resourceServerStore.UpdatePermission(r.Context(), permission); err != nil {
					panic(err)
				}

				encoding.Encode(w, http.StatusOK, responseBody{
					Id:               permission.Id,
					ResourceServerId: permission.ResourceServerId,
					Value:            permission.Value,
					Description:      permission.Description,
				})
			}
		case http.MethodDelete:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.UpdateResourceServers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				if err := resourceServerStore.DeletePermissionById(r.Context(), resourceServerId, permissionId); err != nil {
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
