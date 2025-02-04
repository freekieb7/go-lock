package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/freekieb7/go-lock/pkg/container"
	"github.com/freekieb7/go-lock/pkg/http/handler"
	"github.com/freekieb7/go-lock/pkg/migration"
	"github.com/google/uuid"
)

func TestCreateUser(t *testing.T) {
	t.Parallel()

	container := container.New(context.Background())
	migrator := migration.NewMigrator(container.Database)
	if err := migrator.Up(context.Background()); err != nil {
		t.Fatal(err)
	}

	a := func() {
		m, b := map[string]any{
			"id":             uuid.New(),
			"email":          "emails",
			"password":       "string",
			"blocked":        true,
			"name":           "string",
			"username":       "strings",
			"picture":        "string",
			"email_verified": false,
		}, new(bytes.Buffer)

		if err := json.NewEncoder(b).Encode(m); err != nil {
			t.Error(err)
			return
		}

		r := httptest.NewRequest("POST", "/api/users", b)
		w := httptest.NewRecorder()

		r.Header.Add("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6ImNyZWF0ZTp1c2VycyIsImlhdCI6MTUxNjIzOTAyMiwic3ViIjoiN2JiZTUwODQtNjJjZi00ODRiLWFlZTctMTQ3ODI4ZGVkMDY1In0.AZttADKwVhIRhQ-q8kwBodZ4hnLCyR8RNSPtYV6fYtE")
		r.Form = make(url.Values)
		r.Form.Add("email", "test@test.com")
		r.Form.Add("password", "test")

		http.Server{
			Handler: handler.New(container),
		}.Handler.ServeHTTP(w, r)

		if status := w.Code; status != http.StatusOK {
			t.Log(w.Body.String())
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}
	}

	a()
	a()
}
