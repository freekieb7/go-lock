package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/scope"
	"github.com/freekieb7/go-lock/pkg/session"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type responseBodyUser struct {
	Id            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	Username      string    `json:"username"`
	Name          string    `json:"name"`
	Picture       string    `json:"picture"`
	EmailVerified bool      `json:"email_verified"`
	Blocked       bool      `json:"blocked"`
	CreatedAt     int64     `json:"created_at"`
	UpdatedAt     int64     `json:"updated_at"`
}

func Users(userStore *store.UserStore) http.Handler {
	type postRequestBody struct {
		Id            uuid.UUID `json:"id"`
		Email         string    `json:"email"`
		Username      string    `json:"username"`
		Password      string    `json:"password"`
		Name          string    `json:"name"`
		Picture       string    `json:"picture"`
		Blocked       bool      `json:"blocked"`
		EmailVerified bool      `json:"email_verified"`
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				{
					// Permission check
					if !slices.Contains(session.FromRequest(r).Token().Scope, scope.ReadUsers) {
						w.WriteHeader(http.StatusForbidden)
						return
					}

					var limit uint32
					var offset uint32

					if r.URL.Query().Has("limit") {
						limit64, err := strconv.ParseUint(r.URL.Query().Get("limit"), 10, 64)
						if err != nil {
							log.Println(err)
							w.WriteHeader(http.StatusInternalServerError)
							return
						}

						limit = uint32(limit64)
					}

					if r.URL.Query().Has("offset") {
						offset64, err := strconv.ParseUint(r.URL.Query().Get("offset"), 10, 64)
						if err != nil {
							log.Println(err)
							w.WriteHeader(http.StatusInternalServerError)
							return
						}

						offset = uint32(offset64)
					}

					users, err := userStore.All(r.Context(), store.AllUsersOptions{
						Limit:  limit,
						Offset: offset,
					})
					if err != nil {
						log.Println(err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}

					responseBody := make([]responseBodyUser, 0, len(users))
					for _, user := range users {
						responseBody = append(responseBody, responseBodyUser{
							Id:            user.Id,
							Email:         user.Email,
							Username:      user.Username,
							Name:          user.Name,
							Picture:       user.Picture,
							EmailVerified: user.EmailVerified,
							Blocked:       user.Blocked,
							CreatedAt:     user.CreatedAt,
							UpdatedAt:     user.UpdatedAt,
						})
					}

					encoding.Encode(w, http.StatusOK, responseBody)
				}
			case http.MethodPost:
				{
					// Permission check
					if !slices.Contains(session.FromRequest(r).Token().Scope, scope.CreateUsers) {
						w.WriteHeader(http.StatusForbidden)
						return
					}

					requestBody, err := encoding.Decode[postRequestBody](r.Body)
					if err != nil {
						panic(err)
					}

					var passwordHash []byte
					passwordHash, err = bcrypt.GenerateFromPassword([]byte(requestBody.Password), bcrypt.DefaultCost)
					if err != nil {
						panic(err)
					}

					now := time.Now().UTC().Unix()
					user := model.User{
						Id:            requestBody.Id,
						Email:         requestBody.Email,
						Username:      requestBody.Username,
						Name:          requestBody.Name,
						PasswordHash:  passwordHash,
						Type:          model.UserTypeUser,
						Picture:       requestBody.Picture,
						EmailVerified: requestBody.EmailVerified,
						Blocked:       requestBody.Blocked,
						CreatedAt:     now,
						UpdatedAt:     now,
					}

					if err := userStore.Create(r.Context(), user); err != nil {
						if errors.Is(err, store.ErrUserWithUsernameAlreadyExists) {
							encoding.EncodeError(w, http.StatusConflict, "Conflict", "Username is already in use")
							return
						}

						if errors.Is(err, store.ErrUserWithEmailAlreadyExists) {
							encoding.EncodeError(w, http.StatusConflict, "Conflict", "Email is already in use")
							return
						}

						panic(err)
					}

					encoding.Encode(w, http.StatusOK, responseBodyUser{
						Id:            user.Id,
						Email:         user.Email,
						Username:      user.Username,
						Name:          user.Username,
						Picture:       user.Picture,
						EmailVerified: user.EmailVerified,
						Blocked:       user.Blocked,
						CreatedAt:     user.CreatedAt,
						UpdatedAt:     user.UpdatedAt,
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

func User(userStore *store.UserStore) http.Handler {
	type patchRequestBody struct {
		Email         *string `json:"email"`
		Username      *string `json:"username"`
		Password      *string `json:"password"`
		Name          *string `json:"name"`
		Picture       *string `json:"picture"`
		Blocked       *bool   `json:"blocked"`
		EmailVerified *bool   `json:"email_verified"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId, err := uuid.Parse(r.PathValue("user_id"))
		if err != nil {
			encoding.EncodeError(w, http.StatusBadRequest, "Bad path value", "Invalid User ID")
			return
		}

		switch r.Method {
		case http.MethodPatch:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.UpdateUsers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				requestBody, err := encoding.Decode[patchRequestBody](r.Body)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				user, err := userStore.GetById(r.Context(), userId)
				if err != nil {
					if errors.Is(err, store.ErrUserNotFound) {
						encoding.EncodeError(w, http.StatusNotFound, "Not found", "User not found")
						w.WriteHeader(http.StatusNotFound)
						return
					}
				}

				if requestBody.Email != nil {
					user.Email = *requestBody.Email
				}

				if requestBody.Name != nil {
					user.Name = *requestBody.Name
				}

				if requestBody.Username != nil {
					user.Username = *requestBody.Username
				}

				if requestBody.Password != nil {
					passwordHash, err := bcrypt.GenerateFromPassword([]byte(*requestBody.Password), bcrypt.DefaultCost)
					if err != nil {
						panic(err)
					}

					user.PasswordHash = passwordHash
				}

				if requestBody.Picture != nil {
					user.Picture = *requestBody.Picture
				}

				if requestBody.EmailVerified != nil {
					user.EmailVerified = *requestBody.EmailVerified
				}

				if requestBody.Blocked != nil {
					user.Blocked = *requestBody.Blocked
				}

				user.UpdatedAt = time.Now().Unix()

				if err := userStore.Update(r.Context(), user); err != nil {
					panic(err)
				}

				encoding.Encode(w, http.StatusOK, responseBodyUser{
					Id:            user.Id,
					Email:         user.Email,
					Username:      user.Username,
					Name:          user.Name,
					Picture:       user.Picture,
					EmailVerified: user.EmailVerified,
					Blocked:       user.Blocked,
					CreatedAt:     user.CreatedAt,
					UpdatedAt:     user.UpdatedAt,
				})
				return
			}
		case http.MethodDelete:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.DeleteUsers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				if err := userStore.DeleteById(r.Context(), userId); err != nil {
					panic(err)
				}

				w.WriteHeader(http.StatusOK)
				return
			}
		default:
			{
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		}
	})
}

func UserPermissions(userStore *store.UserStore) http.Handler {
	type getResponseBodyPermissionDetails struct {
		Id               uuid.UUID `json:"id"`
		ResourceServerId uuid.UUID `json:"resource_server_id"`
		Value            string    `json:"value"`
		Description      string    `json:"description"`
	}

	type getResponseBody struct {
		Permissions []getResponseBodyPermissionDetails `json:"permissions"`
	}

	type postRequestBodyPermission struct {
		ResourceServerId uuid.UUID `json:"resource_server_id"`
		PermissionId     uuid.UUID `json:"permission_id"`
	}

	type postRequestBody struct {
		Permissions []postRequestBodyPermission `json:"permissions"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId, err := uuid.Parse(r.PathValue("user_id"))
		if err != nil {
			encoding.EncodeError(w, http.StatusBadRequest, "Bad path value", "Invalid User ID")
			return
		}

		switch r.Method {
		case http.MethodGet:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.ReadUsers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				_, err := userStore.GetById(r.Context(), userId)
				if err != nil {
					if errors.Is(err, store.ErrUserNotFound) {
						encoding.EncodeError(w, http.StatusNotFound, "Not found", fmt.Sprintf("Invalid User ID : %s", userId))
						return
					}

					panic(err)
				}

				permissions, err := userStore.AllPermissions(r.Context(), userId)
				if err != nil {
					panic(err)
				}

				var responseBody getResponseBody
				responseBody.Permissions = make([]getResponseBodyPermissionDetails, 0, len(permissions))
				for _, permission := range permissions {
					responseBody.Permissions = append(responseBody.Permissions, getResponseBodyPermissionDetails{
						Id:               permission.Id,
						ResourceServerId: permission.ResourceServerId,
						Value:            permission.Value,
						Description:      permission.Description,
					})
				}

				encoding.Encode(w, http.StatusOK, responseBody)
				return
			}
		case http.MethodPost:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.UpdateUsers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				requestBody, err := encoding.Decode[postRequestBody](r.Body)
				if err != nil {
					panic(err)
				}

				for _, permission := range requestBody.Permissions {
					userStore.AssignPermission(r.Context(), userId, permission.PermissionId)
				}

				w.WriteHeader(http.StatusCreated)
				return
			}
		case http.MethodDelete:
			{
				// Permission check
				if !slices.Contains(session.FromRequest(r).Token().Scope, scope.UpdateUsers) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				requestBody, err := encoding.Decode[postRequestBody](r.Body)
				if err != nil {
					panic(err)
				}

				for _, permission := range requestBody.Permissions {
					userStore.RevokePermission(r.Context(), userId, permission.PermissionId)
				}

				w.WriteHeader(http.StatusNoContent)
				return
			}
		default:
			{
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		}
	})
}

// func UsersPage(userStore *store.UserStore) http.Handler {
// 	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/users_overview.html")
// 	if err != nil {
// 		panic(err)
// 	}

// 	return http.HandlerFunc(
// 		func(w http.ResponseWriter, r *http.Request) {
// 			if r.Method == http.MethodGet {
// 				users, err := userStore.All(r.Context(), 10, 0)
// 				if err != nil {
// 					panic(err)
// 				}

// 				usersData := make([]map[string]any, len(users))
// 				for idx, user := range users {
// 					usersData[idx] = map[string]any{
// 						"Id":    user.Id,
// 						"Name":  user.Name,
// 						"Email": user.Email,
// 					}
// 				}

// 				tmpl.Execute(w, map[string]any{
// 					"Users": usersData,
// 				})
// 				return
// 			}

// 			w.WriteHeader(http.StatusMethodNotAllowed)
// 		},
// 	)
// }

// func UserCreatePage(userStore *store.UserStore) http.Handler {
// 	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/user_create.html")
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
// 				emailRaw := r.FormValue("email")
// 				usernameRaw := r.FormValue("username")
// 				passwordRaw := r.FormValue("password")

// 				if usernameRaw == "" {
// 					usernameRaw = emailRaw
// 				}

// 				if _, err := mail.ParseAddress(emailRaw); err != nil {
// 					w.WriteHeader(http.StatusBadRequest)
// 					return
// 				}

// 				passwordHash, err := bcrypt.GenerateFromPassword([]byte(passwordRaw), bcrypt.DefaultCost)
// 				if err != nil {
// 					panic(err)
// 				}

// 				now := time.Now().Unix()
// 				user := model.User{
// 					Id:           uuid.New(),
// 					Username:     usernameRaw,
// 					Email:        emailRaw,
// 					PasswordHash: passwordHash,
// 					Type:         model.UserTypeUser,
// 					Name:         nameRaw,
// 					CreatedAt:    now,
// 					UpdatedAt:    now,
// 					IsBlocked:    false,
// 				}
// 				if err := userStore.Create(r.Context(), user); err != nil {
// 					panic(err)
// 				}

// 				w.Header().Add("Location", fmt.Sprintf("/users/%s", user.Id))
// 				w.WriteHeader(http.StatusSeeOther)
// 				return
// 			}

// 			w.WriteHeader(http.StatusMethodNotAllowed)
// 		},
// 	)
// }

// func UserPage(userStore *store.UserStore) http.Handler {
// 	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/user_details.html")
// 	if err != nil {
// 		panic(err)
// 	}

// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		userIdRaw := r.PathValue("user_id")

// 		userId, err := uuid.Parse(userIdRaw)
// 		if err != nil {
// 			encoding.Encode(w, http.StatusBadRequest, fmt.Sprintf("Invalid user id : %s", userIdRaw))
// 			return
// 		}

// 		user, err := userStore.GetById(r.Context(), userId)
// 		if err != nil {
// 			if errors.Is(err, store.ErrUserNotFound) {
// 				w.WriteHeader(http.StatusBadRequest)
// 				return
// 			}

// 			panic(err)
// 		}

// 		if r.Method == http.MethodGet {
// 			errMsg := r.URL.Query().Get("error")

// 			tmpl.Execute(w, map[string]any{
// 				"Id":    user.Id,
// 				"Error": errMsg,
// 			})
// 			return
// 		}

// 		w.WriteHeader(http.StatusMethodNotAllowed)
// 	})
// }

// func UserPageDelete(userStore *store.UserStore) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		if r.Method == http.MethodPost {
// 			userIdRaw := r.PathValue("user_id")
// 			userId, err := uuid.Parse(userIdRaw)
// 			if err != nil {
// 				w.WriteHeader(http.StatusBadRequest)
// 				return
// 			}

// 			user, err := userStore.GetById(r.Context(), userId)
// 			if err != nil {
// 				if errors.Is(err, store.ErrUserNotFound) {
// 					w.Header().Add("Location", "/users")
// 					w.WriteHeader(http.StatusSeeOther)
// 					return
// 				}

// 				panic(err)
// 			}

// 			if user.Type == model.UserTypeUser {
// 				w.Header().Add("Location", fmt.Sprintf("/users/%s?error=%s", user.Id, url.QueryEscape("Forbidden form deleting a system user")))
// 				w.WriteHeader(http.StatusSeeOther)
// 				return
// 			}

// 			if err := userStore.DeleteById(r.Context(), user.Id); err != nil {
// 				panic(err)
// 			}

// 			w.Header().Add("Location", "/users")
// 			w.WriteHeader(http.StatusSeeOther)
// 			return
// 		}

// 		w.WriteHeader(http.StatusMethodNotAllowed)
// 	})
// }
