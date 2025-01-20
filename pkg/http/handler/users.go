package handler

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/mail"
	"net/url"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func UsersPage(userStore *store.UserStore) http.Handler {
	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/users_overview.html")
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				users, err := userStore.All(r.Context(), 10, 0)
				if err != nil {
					panic(err)
				}

				usersData := make([]map[string]any, len(users))
				for idx, user := range users {
					usersData[idx] = map[string]any{
						"Id":    user.Id,
						"Name":  user.Name,
						"Email": user.Email,
					}
				}

				tmpl.Execute(w, map[string]any{
					"Users": usersData,
				})
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}

func UserCreatePage(userStore *store.UserStore) http.Handler {
	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/user_create.html")
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
				emailRaw := r.FormValue("email")
				usernameRaw := r.FormValue("username")
				passwordRaw := r.FormValue("password")

				if usernameRaw == "" {
					usernameRaw = emailRaw
				}

				if _, err := mail.ParseAddress(emailRaw); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				passwordHash, err := bcrypt.GenerateFromPassword([]byte(passwordRaw), bcrypt.DefaultCost)
				if err != nil {
					panic(err)
				}

				now := time.Now().Unix()
				user := model.User{
					Id:           uuid.New(),
					Username:     usernameRaw,
					Email:        emailRaw,
					PasswordHash: passwordHash,
					Type:         model.UserTypeDefault,
					Name:         nameRaw,
					CreatedAt:    now,
					UpdatedAt:    now,
					DeletedAt:    0,
				}
				if err := userStore.Create(r.Context(), user); err != nil {
					panic(err)
				}

				w.Header().Add("Location", fmt.Sprintf("/users/%s", user.Id))
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}

func UserPage(userStore *store.UserStore) http.Handler {
	tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/user_details.html")
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userIdRaw := r.PathValue("user_id")

		userId, err := uuid.Parse(userIdRaw)
		if err != nil {
			encoding.Encode(w, http.StatusBadRequest, fmt.Sprintf("Invalid user id : %s", userIdRaw))
			return
		}

		user, err := userStore.GetById(r.Context(), userId)
		if err != nil {
			if errors.Is(err, store.ErrUserNotFound) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			panic(err)
		}

		if r.Method == http.MethodGet {
			errMsg := r.URL.Query().Get("error")

			tmpl.Execute(w, map[string]any{
				"Id":    user.Id,
				"Error": errMsg,
			})
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})
}

func UserPageDelete(userStore *store.UserStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			userIdRaw := r.PathValue("user_id")
			userId, err := uuid.Parse(userIdRaw)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			user, err := userStore.GetById(r.Context(), userId)
			if err != nil {
				if errors.Is(err, store.ErrUserNotFound) {
					w.Header().Add("Location", "/users")
					w.WriteHeader(http.StatusSeeOther)
					return
				}

				panic(err)
			}

			if user.Type == model.UserTypeSystem {
				w.Header().Add("Location", fmt.Sprintf("/users/%s?error=%s", user.Id, url.QueryEscape("Forbidden form deleting a system user")))
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			if err := userStore.DeleteById(r.Context(), user.Id); err != nil {
				panic(err)
			}

			w.Header().Add("Location", "/users")
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})
}
