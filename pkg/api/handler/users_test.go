package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/freekieb7/go-lock/pkg/core/container"
	"github.com/freekieb7/go-lock/pkg/core/http/handler"
)

func TestCreateUser(t *testing.T) {
	t.Parallel()

	container := container.New(context.Background())

	m, b := map[string]any{
		"email":    "test@test.com",
		"password": "test",
	}, new(bytes.Buffer)

	if err := json.NewEncoder(b).Encode(m); err != nil {
		t.Error(err)
		return
	}

	r := httptest.NewRequest("POST", "/api/users", b)
	w := httptest.NewRecorder()

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
