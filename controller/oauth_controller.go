package controller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/freekieb/go-lock/random"
	"github.com/freekieb/go-lock/repository"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"log"
	"net/http"
	"strings"
	"time"
)

type OAuthController interface {
	ShowAuthorize(c fiber.Ctx) error
	ProcessAuthorize(c fiber.Ctx) error
	GenerateToken(c fiber.Ctx) error
}

type oauthController struct {
	sessionStore     *session.Store
	redisClient      *redis.Client
	clientRepository repository.ClientRepository
}

func NewOAuthController(sessionStore *session.Store, clientRepository repository.ClientRepository, redisClient *redis.Client) OAuthController {
	return &oauthController{
		sessionStore:     sessionStore,
		redisClient:      redisClient,
		clientRepository: clientRepository,
	}
}

func (controller *oauthController) ShowAuthorize(c fiber.Ctx) error {
	sess, err := controller.sessionStore.Get(c)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	userId := sess.Get("UserID")

	// User is authenticated
	if userId != nil {
		sess.Destroy()
		sess.Save()

		return c.Render("authorize", nil)
	}

	reqResponseType := c.Query("response_type") // code
	reqClientId := c.Query("client_id")         // 222222
	reqRedirectUri := c.Query("redirect_uri")   // redirect_uri
	//scope := c.Query("scope")                // read
	reqState := c.Query("state") // 1234xyz

	reqCodeChallenge := c.Query("code_challenge")
	reqCodeChallengeMethod := c.Query("code_challenge_method")
	//connection := c.Query("connection")
	//organization := c.Query("organization")
	//invitation := c.Query("invitation")

	// Status check
	if reqResponseType != "code" {
		return c.SendStatus(401)
	}

	// Code challenge method
	if reqCodeChallengeMethod != "S256" {
		return c.SendStatus(401)
	}

	// Code challenge verification
	lenCodeChallenge := len(reqCodeChallenge)
	if lenCodeChallenge < 43 || lenCodeChallenge > 128 {
		return c.SendStatus(401)
	}

	// Client ID check
	clientId, err := uuid.Parse(reqClientId)

	if err != nil {
		log.Println(err)
		return c.SendStatus(400)
	}

	_, err = controller.clientRepository.GetClient(clientId)

	if err != nil {
		log.Println(err)
		return c.SendStatus(403)
	}

	// Redirect uri check
	redirectExists := false
	redirectList, err := controller.clientRepository.GetClientCallbackList(clientId)

	if err != nil {
		log.Println(err)
		return c.SendStatus(403)
	}

	for _, redirect := range redirectList {
		if reqRedirectUri == redirect.Uri {
			redirectExists = true
			break
		}
	}

	if !redirectExists {
		return c.SendStatus(403)
	}

	// Save some data to session while we authenticate
	sess.Set("redirect_uri", reqRedirectUri)
	sess.Set("state", reqState)
	sess.Save()

	// Store code challenge
	controller.redisClient.Set(context.Background(), "code_challenge", reqCodeChallenge, time.Hour)

	return c.Redirect().Status(http.StatusFound).To("/login")
}

func (controller *oauthController) ProcessAuthorize(c fiber.Ctx) error {
	sess, err := controller.sessionStore.Get(c)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	// Fetch the previously verified data during authentication
	redirectUri := sess.Get("redirect_uri")
	state := sess.Get("state")

	// Generate a random code
	authorizationCode := random.String(10)

	// Use authorization code for later usage during token fetching
	res := controller.redisClient.Set(context.Background(), "authorization_code", authorizationCode, time.Hour)

	if res.Err() != nil {
		log.Println(res.Err())
		return c.SendStatus(500)
	}

	return c.Redirect().
		Status(http.StatusFound).
		To(fmt.Sprintf("%s?code=%s&state=%s", redirectUri, authorizationCode, state))
}

func (controller *oauthController) GenerateToken(c fiber.Ctx) error {
	reqGrantType := c.FormValue("grant_type")
	reqCodeVerifier := c.FormValue("code_verifier")
	reqCode := c.FormValue("code")
	reqRedirectUri := c.FormValue("redirect_uri")

	// Validate grant type
	if reqGrantType != "authorization_code" {
		return c.SendStatus(400)
	}

	// Validate code with authentication code generated during authentication
	var authorizationCode string
	err := controller.redisClient.Get(context.Background(), "authorization_code").Scan(&authorizationCode)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	if authorizationCode != reqCode {
		log.Println(fmt.Errorf("authorization_code `%s` does not equal code `%s`", authorizationCode, reqCode))
		return c.SendStatus(400)
	}

	// Validate client credentials from Authorization header
	const prefix = "Basic "

	authorizationHeader := string(c.Request().Header.Peek("Authorization"))

	if !strings.EqualFold(authorizationHeader[:len(prefix)], prefix) {
		return c.SendStatus(400)
	}

	clientCredentials, err := base64.StdEncoding.DecodeString(authorizationHeader[len(prefix):])

	if err != nil {
		return c.SendStatus(400)
	}

	clientIdUnparsed, clientSecret, ok := strings.Cut(string(clientCredentials), ":")

	if !ok {
		log.Println(errors.New("cutting client info failed"))
		return c.SendStatus(400)
	}

	clientId, err := uuid.Parse(clientIdUnparsed)

	if err != nil {
		log.Println(err)
		return c.SendStatus(400)
	}

	client, err := controller.clientRepository.GetClient(clientId)

	if err != nil {
		fmt.Println(err)
		return c.SendStatus(400)
	}

	if client.Secret != clientSecret {
		return c.SendStatus(400)
	}

	// Verify code challenge
	var codeChallenge string
	controller.redisClient.Get(context.Background(), "code_challenge").Scan(&codeChallenge)

	s256 := sha256.Sum256([]byte(reqCodeVerifier))

	// trim padding
	a := strings.TrimRight(base64.URLEncoding.EncodeToString(s256[:]), "=")
	b := strings.TrimRight(codeChallenge, "=")

	if a != b {
		log.Println(fmt.Errorf("code_verifier `%s` does not equal code_challenge `%s`", a, b))
		return c.SendStatus(400)
	}

	// Validate redirect uri
	redirectList, err := controller.clientRepository.GetClientCallbackList(clientId)

	if err != nil {
		fmt.Println(err)
		return c.SendStatus(400)
	}

	redirectExists := false
	for _, redirect := range redirectList {
		if redirect.Uri == reqRedirectUri {
			redirectExists = true
			break
		}
	}

	if !redirectExists {
		return c.SendStatus(400)
	}

	data := map[string]interface{}{
		"access_token": "something",
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	//
	//if scope := ti.GetScope(); scope != "" {
	//	data["scope"] = scope
	//}
	//
	//if refresh := ti.GetRefresh(); refresh != "" {
	//	data["refresh_token"] = refresh
	//}

	return c.JSON(data)
}
