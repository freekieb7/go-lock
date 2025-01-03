package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func Users(userStore *store.UserStore) http.Handler {
	type RequestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				var err error
				var reqBody RequestBody

				if err = json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
					encoding.Encode(w, http.StatusBadRequest, "Invalid body")
					return
				}

				if _, err = mail.ParseAddress(reqBody.Email); err != nil {
					encoding.Encode(w, http.StatusBadRequest, fmt.Sprintf("Invalid email : %s", reqBody.Email))
					return
				}

				var passwordHash []byte
				if reqBody.Password != "" {
					passwordHash, err = bcrypt.GenerateFromPassword([]byte(reqBody.Password), bcrypt.DefaultCost)
					if err != nil {
						encoding.Encode(w, http.StatusInternalServerError, "Internal server error, please try again")
						return
					}
				}

				now := time.Now().UTC().Unix()
				user := model.User{
					Id:           uuid.New(),
					Email:        reqBody.Email,
					PasswordHash: passwordHash,
					CreatedAt:    now,
					UpdatedAt:    now,
				}

				if err := userStore.Create(r.Context(), user); err != nil {
					if errors.Is(err, store.ErrUserAleadyExists) {
						encoding.Encode(w, http.StatusConflict, "User already exists")
						return
					}

					encoding.Encode(w, http.StatusInternalServerError, "Internal server error, please try again")
					return
				}

				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}
