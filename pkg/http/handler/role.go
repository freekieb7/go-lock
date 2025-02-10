package handler

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/scope"
	"github.com/freekieb7/go-lock/pkg/session"
	"github.com/google/uuid"
)

type responseBodyRole struct {
	Id          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

func Roles(roleStore *store.RoleStore) http.Handler {
	type getResponseBody struct {
		Roles []responseBodyRole `json:"roles"`
	}

	type postRequestBody struct {
		Id          uuid.UUID `json:"id"`
		Name        string    `json:"name"`
		Description string    `json:"description"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.ReadRoles) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				roles, err := roleStore.All(r.Context())
				if err != nil {
					panic(err)
				}

				responseBody := getResponseBody{
					Roles: make([]responseBodyRole, 0, len(roles)),
				}
				for _, role := range roles {
					responseBody.Roles = append(responseBody.Roles, responseBodyRole{
						Id:          role.Id,
						Name:        role.Name,
						Description: role.Description,
					})
				}

				encoding.Encode(w, http.StatusOK, responseBody)
			}
		case http.MethodPost:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.CreateRoles) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				requestBody, err := encoding.Decode[postRequestBody](r.Body)
				if err != nil {
					panic(err)
				}

				role := model.Role{
					Id:          requestBody.Id,
					Name:        requestBody.Name,
					Description: requestBody.Description,
				}

				if err := roleStore.Create(r.Context(), role); err != nil {
					panic(err)
				}

				encoding.Encode(w, http.StatusCreated, responseBodyRole{
					Id:          role.Id,
					Name:        role.Name,
					Description: role.Description,
				})
			}
		}
	})
}

func Role(roleStore *store.RoleStore) http.Handler {
	type patchRequestBody struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roleId, err := uuid.Parse(r.PathValue("role_id"))
		if err != nil {
			panic(err)
		}

		switch r.Method {
		case http.MethodGet:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.ReadRoles) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				role, err := roleStore.GetById(r.Context(), roleId)
				if err != nil {
					if errors.Is(err, store.ErrRoleNotFound) {
						encoding.EncodeError(w, http.StatusNotFound, "Not found", fmt.Sprintf("Invalid role id : %s", roleId))
						return
					}

					panic(err)
				}

				encoding.Encode(w, http.StatusOK, responseBodyRole{
					Id:          role.Id,
					Name:        role.Name,
					Description: role.Description,
				})
			}
		case http.MethodPatch:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.UpdateRoles) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				requestBody, err := encoding.Decode[patchRequestBody](r.Body)
				if err != nil {
					panic(err)
				}

				role, err := roleStore.GetById(r.Context(), roleId)
				if err != nil {
					if errors.Is(err, store.ErrRoleNotFound) {
						encoding.EncodeError(w, http.StatusNotFound, "Not found", fmt.Sprintf("Invalid role id : %s", roleId))
						return
					}
				}

				if requestBody.Name != "" {
					role.Name = requestBody.Name
				}

				if requestBody.Description != "" {
					role.Description = requestBody.Description
				}

				if err := roleStore.Update(r.Context(), role); err != nil {
					panic(err)
				}

				encoding.Encode(w, http.StatusOK, responseBodyRole{
					Id:          role.Id,
					Name:        role.Name,
					Description: role.Description,
				})
			}
		case http.MethodDelete:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.DeleteRoles) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				if err := roleStore.DeleteById(r.Context(), roleId); err != nil {
					panic(err)
				}

				w.WriteHeader(http.StatusOK)
			}
		}
	})
}

func RolePermissions(roleStore *store.RoleStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			{

			}
		case http.MethodPost:
			{

			}
		}
	})
}
