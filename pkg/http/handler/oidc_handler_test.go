package handler

import (
	"testing"
)

// func init() {
// 	os.Remove(os.Getenv("APP_ROOT") + "/var/sqlite/data.db")
// }

func TestRegister(t *testing.T) {
	// dbManager := database.NewManager()
	// clientRepository := repository.NewClientRepository(dbManager.DB)
	// redirectUriRepository := repository.NewRedirectUriRepository(dbManager.DB)
	// jwksRepository := repository.NewJwksRepository(dbManager.DB)
	// oidcHandler := NewOidcHandler(
	// 	clientRepository,
	// 	redirectUriRepository,
	// 	jwksRepository,
	// )

	// body, err := json.Marshal(clientRegistrationBody{
	// 	RedirectUris: []string{
	// 		"test",
	// 	},
	// })
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// req, err := http.NewRequest("POST", "/oidc/register", bytes.NewReader(body))
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// req.Header.Set("Content-Type", "application/json")

	// // We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	// rr := httptest.NewRecorder()
	// handlerFunc := http.HandlerFunc(oidcHandler.Register)

	// // Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// // directly and pass in our Request and ResponseRecorder.
	// handlerFunc.ServeHTTP(rr, req)

	// // Check the status code is what we expect.
	// if status := rr.Code; status != http.StatusCreated {
	// 	t.Log(rr.Body)
	// 	t.Errorf("handler returned wrong status code: got %v want %v",
	// 		status, http.StatusOK)
	// }

	// // Check the response body is what we expect.
	// expected := `{"alive": true}`
	// if rr.Body.String() != expected {
	// 	t.Errorf("handler returned unexpected body: got %v want %v",
	// 		rr.Body.String(), expected)
	// }
}
