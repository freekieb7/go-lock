package handler_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/freekieb7/go-lock/pkg/container"
	"github.com/freekieb7/go-lock/pkg/data/migration"
	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/http/handler"
	"github.com/freekieb7/go-lock/pkg/random"
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

	api := model.ResourceServer{
		Id:               random.NewString(32),
		Name:             "test_api",
		Uri:              "http://example.com",
		SigningAlgorithm: model.SigningAlgorithmRS256,
	}
	if err := container.ResourceServerStore.Create(ctx, api); err != nil {
		t.Fatal(err)
	}

	// Create a Client to be used when authenticating
	client := model.Client{
		Id:           random.NewString(32),
		Name:         "test123",
		Secret:       random.NewString(32),
		Confidential: true,
	}
	if err := container.ClientStore.Create(ctx, client); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("POST", "/oauth/token", nil)
	w := httptest.NewRecorder()

	r.Form = make(url.Values)
	r.Form.Add("grant_type", "client_credentials")
	r.Form.Add("client_id", client.Id)
	r.Form.Add("client_secret", client.Secret)
	r.Form.Add("audience", api.Uri)

	container.HttpServer.Handler.ServeHTTP(w, r)

	// Check the status code is what we expect.
	if status := w.Code; status != http.StatusOK {
		t.Log(w.Body.String())
		t.Fatalf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	test, _ := encoding.Decode[handler.TokenResponse](w.Body)
	if test.ExpiresIn != time.Hour.Seconds() {
		t.Errorf("handler returned wrong expires in: got %v want %v",
			test.ExpiresIn, time.Hour.Seconds())
	}
}

func TestAuthorizeByCode(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeoutCause(context.Background(), time.Second, errors.New("test took too long"))
	defer cancel()

	container := container.New(ctx)

	migrator := migration.NewMigrator(container.Database)
	migrator.Up(ctx)

	// Create an api to be used for audience
	resourceServer := model.ResourceServer{
		Id:               random.NewString(32),
		Name:             "test123",
		Uri:              "http://example.com",
		SigningAlgorithm: model.SigningAlgorithmRS256,
	}
	if err := container.ResourceServerStore.Create(ctx, resourceServer); err != nil {
		t.Fatal(err)
	}

	// Create a Client to be used when authentication
	client := model.Client{
		Id:           random.NewString(32),
		Name:         "test123",
		Secret:       random.NewString(32),
		Confidential: true,
		RedirectUris: []string{
			"https://example.com",
		},
	}
	if err := container.ClientStore.Create(ctx, client); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", fmt.Sprintf(`/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&audience=%s&scope=offline_access`, client.Id, client.RedirectUris[0], resourceServer.Uri), nil)

	container.HttpServer.Handler.ServeHTTP(w, r)

	// Check the status code is what we expect.
	if status := w.Code; status != http.StatusFound {
		t.Log(w.Body)
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestGetTokenWithCode(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeoutCause(context.Background(), time.Second, errors.New("test took too long"))
	defer cancel()

	container := container.New(ctx)

	migrator := migration.NewMigrator(container.Database)
	if err := migrator.Up(ctx); err != nil {
		t.Fatal(err)
	}

	resourceServer := model.ResourceServer{
		Id:               random.NewString(32),
		Name:             "test123",
		Uri:              "https://example.com",
		SigningAlgorithm: model.SigningAlgorithmRS256,
	}
	if err := container.ResourceServerStore.Create(ctx, resourceServer); err != nil {
		t.Fatal(err)
	}

	// Create a Client to be used when authentication
	client := model.Client{
		Id:           random.NewString(32),
		Name:         "test123",
		Secret:       random.NewString(32),
		Confidential: false,
		RedirectUris: []string{
			"https://example.com/callback",
		},
	}
	if err := container.ClientStore.Create(ctx, client); err != nil {
		t.Fatal(err)
	}

	// Create a redirect uri for that client
	authorizationCode := model.AuthorizationCode{
		ClientId: client.Id,
		Code:     random.NewString(32),
		// TODO
	}
	if err := container.AuthorizationCodeStore.Create(ctx, authorizationCode); err != nil {
		log.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/oauth/token", nil)
	r.Form = make(url.Values)
	r.Form.Add("grant_type", "authorization_code")
	r.Form.Add("client_id", client.Id)
	r.Form.Add("client_secret", client.Secret)
	r.Form.Add("code", authorizationCode.Code)
	r.Form.Add("redirect_uri", client.RedirectUris[0])

	container.HttpServer.Handler.ServeHTTP(w, r)

	// Check the status code is what we expect.
	if status := w.Code; status != http.StatusOK {
		t.Log(w.Body)
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}
