package handler

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"

	"github.com/freekieb7/go-lock/pkg/core/data/model"
	"github.com/freekieb7/go-lock/pkg/core/data/store"
	"github.com/freekieb7/go-lock/pkg/core/http/encoding"
	"github.com/freekieb7/go-lock/pkg/core/session"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func Signin(sessionStore *store.SessionStore, userStore *store.UserStore) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				errMsg := r.URL.Query().Get("error")

				tmpl, err := template.ParseFiles("template/base.html", "template/signin.html")
				if err != nil {
					w.WriteHeader(500)
					return
				}

				tmpl.Execute(w, map[string]any{
					"Error": errMsg,
				})
				return
			}

			if r.Method == "POST" {
				if err := r.ParseForm(); err != nil {
					panic("parse form went wrong")
				}

				if !r.Form.Has("username") {
					encoding.Encode(w, http.StatusBadRequest, map[string]string{
						"message": "email is required",
					})
					return
				}
				usernameRaw := r.Form.Get("username")

				if !r.Form.Has("password") {
					encoding.Encode(w, http.StatusBadRequest, map[string]string{
						"message": "password is required",
					})
					return
				}
				passwordRaw := r.Form.Get("password")

				rememberMe := false
				if r.Form.Has("remember_me") {
					rememberMeRaw := r.Form.Get("remember_me")

					var err error
					rememberMe, err = strconv.ParseBool(rememberMeRaw)
					if err != nil {
						encoding.Encode(w, http.StatusBadRequest, map[string]string{
							"error":   "bad_request",
							"message": "remember_me must be true or false",
						})
						return
					}
				}

				var user model.User
				var err error
				if _, mailErr := mail.ParseAddress(usernameRaw); mailErr == nil {
					user, err = userStore.GetByEmail(r.Context(), usernameRaw)
				} else {
					user, err = userStore.GetByUsername(r.Context(), usernameRaw)
				}

				if err != nil {
					if errors.Is(err, store.ErrUserNotFound) {
						msg := url.QueryEscape("Invalid credentials")
						w.Header().Add("Location", fmt.Sprintf("signin?error=%s", msg))
						w.WriteHeader(http.StatusSeeOther)
						return
					}
					panic("todo")
				}

				if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(passwordRaw)); err != nil {
					msg := url.QueryEscape("Invalid credentials")
					w.Header().Add("Location", fmt.Sprintf("signin?error=%s", msg))
					w.WriteHeader(http.StatusSeeOther)
					return
				}

				if user.DeletedAt > 0 {
					msg := url.QueryEscape("User is blocked")
					w.Header().Add("Location", fmt.Sprintf("signin?error=%s", msg))
					w.WriteHeader(http.StatusSeeOther)
					return
				}

				session := session.FromRequest(r)
				if rememberMe {
					session.Set("user_id", user.Id)
				}

				authRequest := session.Get("auth_request").(AuthRequest)
				authRequest.UserId = user.Id

				session.Set("auth_request", authRequest)
				if err := sessionStore.Save(r.Context(), *session); err != nil {
					msg := url.QueryEscape("Internal server error")
					w.Header().Add("Location", fmt.Sprintf("signin?error=%s", msg))
					w.WriteHeader(http.StatusSeeOther)
					return
				}

				w.Header().Add("Location", "/auth/authorize")
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}

func Authorize() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			session := session.FromRequest(r)

			if !session.Has("auth_request") {
				panic("auth context required")
			}

			authRequest := session.Get("auth_request").(AuthRequest)
			if authRequest.UserId == (uuid.UUID{}) {
				w.Header().Add("Location", "/auth/signin")
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			if authRequest.Authorized {
				w.Header().Add("Location", "/auth/oauth/authorize")
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			if r.Method == http.MethodGet {
				tmpl, err := template.ParseFiles("template/base.html", "template/authorize.html")
				if err != nil {
					w.WriteHeader(500)
					return
				}

				tmpl.Execute(w, map[string]any{
					"Scope": authRequest.Scopes,
				})
				return
			}

			if r.Method == http.MethodPost {
				if err := r.ParseForm(); err != nil {
					panic(err)
				}

				if !r.Form.Has("authorized") {
					panic("authorized not found")
				}

				authorizedRaw := r.Form.Get("authorized")
				authorized, err := strconv.ParseBool(authorizedRaw)
				if err != nil {
					panic(authorized)
				}

				authRequest := session.Get("auth_request").(AuthRequest)
				authRequest.Authorized = authorized
				session.Set("auth_request", authRequest)

				w.Header().Add("Location", "/auth/oauth/authorize")
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}
