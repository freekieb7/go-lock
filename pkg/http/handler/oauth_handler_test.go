package handler_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/freekieb7/go-lock/pkg/container"
	"github.com/freekieb7/go-lock/pkg/data/local/migration"
	"github.com/freekieb7/go-lock/pkg/data/local/migration/migrator"
	migration_version "github.com/freekieb7/go-lock/pkg/data/local/migration/versions"
	"github.com/freekieb7/go-lock/pkg/data/local/model"
	"github.com/freekieb7/go-lock/pkg/http/encoding"
	"github.com/freekieb7/go-lock/pkg/http/handler"
	"github.com/freekieb7/go-lock/pkg/random"
)

func TestGetTokenWithClientCredentials(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeoutCause(context.Background(), time.Second, errors.New("test took too long"))
	defer cancel()

	container := container.New(ctx)

	migrator := migrator.New(container.Database)
	migrator.Up(ctx, []migration.Migration{
		migration_version.NewMigrationCreateTables(container.Settings),
	})

	// Create API
	api := model.Api{
		Id:               random.NewString(32),
		Name:             "test_api",
		Uri:              "http://example.com",
		SigningAlgorithm: model.SigningAlgorithmRS256,
	}
	if err := container.ApiStore.Create(ctx, api); err != nil {
		t.Fatal(err)
	}

	// Create a Client to be used when authenticating
	client := model.Client{
		Id:           random.NewString(32),
		Name:         "test123",
		Secret:       random.NewBytes(32),
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
	r.Form.Add("client_secret", base64.RawURLEncoding.EncodeToString(client.Secret))
	r.Form.Add("audience", api.Uri)

	container.HttpServer.Handler.ServeHTTP(w, r)

	// Check the status code is what we expect.
	if status := w.Code; status != http.StatusOK {
		t.Log(w.Body.String())
		t.Fatalf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	test, _ := encoding.Decode[handler.TokenResponse](w.Body)
	if test.ExpiresIn != (time.Hour * 24).Seconds() {
		t.Errorf("handler returned wrong expires in: got %v want %v",
			test.ExpiresIn, time.Hour.Seconds())
	}
}

func TestAuthorizeByCode(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeoutCause(context.Background(), time.Second, errors.New("test took too long"))
	defer cancel()

	container := container.New(ctx)

	migrator := migrator.New(container.Database)
	migrator.Up(ctx, []migration.Migration{
		migration_version.NewMigrationCreateTables(container.Settings),
	})

	// Create an api to be used for audience
	api := model.Api{
		Id:               random.NewString(32),
		Name:             "test123",
		Uri:              "http://example.com",
		SigningAlgorithm: model.SigningAlgorithmRS256,
	}
	if err := container.ApiStore.Create(ctx, api); err != nil {
		t.Fatal(err)
	}

	// Create a Client to be used when authentication
	client := model.Client{
		Id:           random.NewString(32),
		Name:         "test123",
		Secret:       random.NewBytes(32),
		Confidential: true,
	}
	if err := container.ClientStore.Create(ctx, client); err != nil {
		t.Fatal(err)
	}

	// Create a redirect uri for that client
	redirectUri := model.RedirectUri{
		ClientId: client.Id,
		Uri:      "https://example.com",
	}
	if err := container.RedirectUriStore.Create(ctx, redirectUri); err != nil {
		log.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", fmt.Sprintf(`/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s`, client.Id, redirectUri.Uri), nil)

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

	migrator := migrator.New(container.Database)
	if err := migrator.Up(ctx, []migration.Migration{
		migration_version.NewMigrationCreateTables(container.Settings),
	}); err != nil {
		t.Fatal(err)
	}

	// Create an api to be used for audience
	api := model.Api{
		Id:               random.NewString(32),
		Name:             "test123",
		Uri:              "https://example.com",
		SigningAlgorithm: model.SigningAlgorithmRS256,
	}
	if err := container.ApiStore.Create(ctx, api); err != nil {
		t.Fatal(err)
	}

	// Create a Client to be used when authentication
	client := model.Client{
		Id:           random.NewString(32),
		Name:         "test123",
		Secret:       random.NewBytes(32),
		Confidential: false,
	}
	if err := container.ClientStore.Create(ctx, client); err != nil {
		t.Fatal(err)
	}

	// Create a redirect uri for that client
	redirectUri := model.RedirectUri{
		ClientId: client.Id,
		Uri:      "https://example.com/callback",
	}
	if err := container.RedirectUriStore.Create(ctx, redirectUri); err != nil {
		log.Fatal(err)
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
	r := httptest.NewRequest("POST", fmt.Sprintf(`/oauth/token?response_type=code&client_id=%s&redirect_uri=%s`, client.Id, redirectUri.Uri), nil)
	r.Form = make(url.Values)
	r.Form.Add("grant_type", "authorization_code")
	r.Form.Add("client_id", client.Id)
	r.Form.Add("client_secret", base64.RawURLEncoding.EncodeToString(client.Secret))
	r.Form.Add("code", authorizationCode.Code)
	r.Form.Add("redirect_uri", redirectUri.Uri)

	container.HttpServer.Handler.ServeHTTP(w, r)

	// Check the status code is what we expect.
	if status := w.Code; status != http.StatusOK {
		t.Log(w.Body)
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}
