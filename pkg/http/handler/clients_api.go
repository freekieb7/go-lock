package handler

import (
	"net/http"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/google/uuid"
)

func Clients(clientStore *store.ClientStore) http.Handler {
	type postReqPayload struct {
		Name string `json:"name"`
	}

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				clients, err := clientStore.All(r.Context(), 10, 0)
				if err != nil {
					panic(err)
				}

				resPayload := make([]map[string]any, len(clients))
				for idx, client := range clients {
					resPayload[idx] = map[string]any{
						"id":            client.Id,
						"name":          client.Name,
						"secret":        client.Secret,
						"redirect_urls": client.RedirectUrls,
					}
				}

				encoding.Encode(w, http.StatusOK, resPayload)
				return
			}

			if r.Method == "POST" {
				reqPayload, err := encoding.Decode[postReqPayload](r.Body)
				if err != nil {
					panic(err)
				}

				now := time.Now().Unix()
				client := model.Client{
					Id:             uuid.New(),
					Name:           reqPayload.Name,
					Secret:         random.NewString(15),
					Type:           model.ClientTypeCustom,
					IsConfidential: true,
					RedirectUrls:   "",
					CreatedAt:      now,
					UpdatedAt:      now,
					DeletedAt:      0,
				}

				if err := clientStore.Create(r.Context(), client); err != nil {
					panic(err)
				}

				resPayload := map[string]any{
					"id": client.Id,
				}

				encoding.Encode(w, http.StatusCreated, resPayload)
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}
