package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"time"

	"github.com/freekieb7/go-lock/pkg/core/data/model"
	"github.com/freekieb7/go-lock/pkg/core/data/store"
	"github.com/freekieb7/go-lock/pkg/core/http/encoding"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func Users(userStore *store.UserStore) http.Handler {
	type requestPayload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				var err error
				var reqPayload requestPayload

				if err = json.NewDecoder(r.Body).Decode(&reqPayload); err != nil {
					encoding.Encode(w, http.StatusBadRequest, "Invalid body")
					return
				}

				if _, err = mail.ParseAddress(reqPayload.Email); err != nil {
					encoding.Encode(w, http.StatusBadRequest, fmt.Sprintf("Invalid email : %s", reqPayload.Email))
					return
				}

				var passwordHash []byte
				if reqPayload.Password != "" {
					passwordHash, err = bcrypt.GenerateFromPassword([]byte(reqPayload.Password), bcrypt.DefaultCost)
					if err != nil {
						encoding.Encode(w, http.StatusInternalServerError, "Internal server error, please try again")
						return
					}
				}

				now := time.Now().UTC().Unix()
				user := model.User{
					Id:           uuid.New(),
					Email:        reqPayload.Email,
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
