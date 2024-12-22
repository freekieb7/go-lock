package handler

import (
	"html/template"
	"net/http"
	"strconv"

	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/http/session"
	"github.com/freekieb7/go-lock/pkg/uuid"
)

func Signin() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				tmpl, err := template.ParseFiles("templates/base.html", "templates/signin.html")
				if err != nil {
					w.WriteHeader(500)
					return
				}

				tmpl.Execute(w, nil)
				return
			}

			if r.Method == "POST" {
				if err := r.ParseForm(); err != nil {
					panic("parse form went wrong")
				}

				if !r.Form.Has("email") {
					encoding.EncodeError(w, r, http.StatusBadRequest, "bad_request", "email is required")
					return
				}
				emailRaw := r.Form.Get("email")

				if !r.Form.Has("password") {
					encoding.EncodeError(w, r, http.StatusBadRequest, "bad_request", "password is required")
					return
				}
				passwordRaw := r.Form.Get("password")

				rememberMe := false
				if r.Form.Has("remember_me") {
					rememberMeRaw := r.Form.Get("remember_me")

					var err error
					rememberMe, err = strconv.ParseBool(rememberMeRaw)
					if err != nil {
						encoding.EncodeError(w, r, http.StatusBadRequest, "bad_request", "remember_me must be true or false")
						return
					}
				}

				if emailRaw != "admin@admin.com" || passwordRaw != "admin" {
					panic("bad password")
				}

				session := session.FromRequest(r)
				if rememberMe {
					session.Set("user_id", uuid.V4())
				}

				w.Header().Add("Location", "/authorize")
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			encoding.EncodeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
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

			if r.Method == "GET" {
				tmpl, err := template.ParseFiles("templates/base.html", "templates/authorize.html")
				if err != nil {
					w.WriteHeader(500)
					return
				}

				tmpl.Execute(w, nil)
				return
			}

			if r.Method == "POST" {
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

				w.Header().Add("Location", "/oauth/authorize")
				w.WriteHeader(http.StatusSeeOther)
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}
