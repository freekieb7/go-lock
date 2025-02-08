package handler_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/freekieb7/go-lock/pkg/container"
	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/http/handler"
	"github.com/freekieb7/go-lock/pkg/migration"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/google/uuid"
)

func TestGetTokenWithClientCredentials(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeoutCause(context.Background(), time.Second, errors.New("test took too long"))
	defer cancel()

	container := container.New(ctx)

	migrator := migration.NewMigrator(container.Database)
	if err := migrator.Up(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	resourceServer := model.ResourceServer{
		Id:                       uuid.New(),
		Name:                     "test123",
		Description:              "test",
		Url:                      "http://example.com",
		IsSystem:                 false,
		SigningAlgorithm:         model.SigningAlgorithmRS256,
		AllowSkippingUserConsent: false,
		AllowOfflineAccess:       false,
		CreatedAt:                now,
		UpdatedAt:                now,
	}
	scopes := make([]model.Scope, 0)

	if err := container.ResourceServerStore.Create(ctx, resourceServer, scopes); err != nil {
		t.Fatal(err)
	}

	// Create a Client to be used when authenticating
	client := model.Client{
		Id:             uuid.New(),
		Name:           "test123",
		Secret:         random.NewString(32),
		IsSystem:       false,
		RedirectUrls:   "",
		IsConfidential: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := container.ClientStore.Create(ctx, client); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("POST", "/auth/oauth/token", nil)
	w := httptest.NewRecorder()

	r.Form = make(url.Values)
	r.Form.Add("grant_type", "client_credentials")
	r.Form.Add("client_id", client.Id.String())
	r.Form.Add("client_secret", client.Secret)
	r.Form.Add("audience", resourceServer.Url)

	handler.New(container).ServeHTTP(w, r)

	// Check the status code is what we expect.
	if status := w.Code; status != http.StatusOK {
		t.Log(w.Body.String())
		t.Fatalf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	test, _ := encoding.Decode[map[string]any](w.Body)
	if test["ExpiresIn"] != time.Hour.Seconds() {
		t.Errorf("handler returned wrong expires in: got %v want %v",
			test["ExpiresIn"], time.Hour.Seconds())
	}
}

func TestAuthorizationFlow(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeoutCause(context.Background(), time.Second, errors.New("test took too long"))
	defer cancel()

	container := container.New(ctx)

	migrator := migration.NewMigrator(container.Database)
	migrator.Up(ctx)

	clientId := container.Settings.ClientId
	clientSecret := container.Settings.ClientSecret
	redirectUri := container.Settings.Host + "/callback"
	audience := container.Settings.Host + "/api"

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", fmt.Sprintf(`/auth/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&audience=%s&scope=offline_access`, clientId, redirectUri, audience), nil)

	http.Server{
		Handler: handler.New(container),
	}.Handler.ServeHTTP(w, r)

	// Check the status code is what we expect.
	if status := w.Code; status != http.StatusFound {
		t.Log(w.Body)
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	codeResponseQuery, err := url.ParseQuery(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	code := codeResponseQuery.Get("code")

	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/oauth/token", nil)
	r.Form = make(url.Values)
	r.Form.Add("grant_type", "authorization_code")
	r.Form.Add("client_id", clientId.String())
	r.Form.Add("client_secret", clientSecret)
	r.Form.Add("code", code)
	r.Form.Add("redirect_uri", redirectUri)

	http.Server{
		Handler: handler.New(container),
	}.Handler.ServeHTTP(w, r)

	// todo more
}
