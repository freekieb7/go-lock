package handler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/freekieb7/go-lock/pkg/core/container"
	"github.com/freekieb7/go-lock/pkg/core/http/handler"
)

func TestHealthCheck(t *testing.T) {
	t.Parallel()

	container := container.New(context.Background())

	r := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	http.Server{
		Handler: handler.New(container),
	}.Handler.ServeHTTP(w, r)

	// Check the status code is what we expect.
	if status := w.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := `{"alive":true,"database_ping":true}`
	if strings.TrimSpace(w.Body.String()) != strings.TrimSpace(expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			w.Body.String(), expected)
	}
}
