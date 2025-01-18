package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/random"
)

var (
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

type OAuthProvider struct {
	ClientId     string
	ClientSecret string
	AuthUrl      string
	TokenUrl     string
	RedirectUrl  string
	Audience     string
}

func NewOAuthProvider(
	clientId string,
	clientSecret string,
	authUrl string,
	tokenUrl string,
	redirectUrl string,
	audience string,
) *OAuthProvider {
	return &OAuthProvider{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		AuthUrl:      authUrl,
		TokenUrl:     tokenUrl,
		RedirectUrl:  redirectUrl,
		Audience:     audience,
	}
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    uint32 `json:"expires_in"`
}

type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (provider *OAuthProvider) AuthrorizationUrl() (string, string) {
	state := random.NewUrlSafeString(10)
	url := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&audience=%s&state=%s", provider.AuthUrl, provider.ClientId, provider.RedirectUrl, provider.Audience, state)
	return url, state
}

func (provider *OAuthProvider) Tokens(code string) (TokenResponse, error) {
	var tokenResponse TokenResponse

	url := fmt.Sprintf("%s?grant_type=authorization_code&client_id=%s&client_secret=%s&code=%s&redirect_uri=%s&audience=%s", provider.TokenUrl, provider.ClientId, provider.ClientSecret, code, provider.RedirectUrl, provider.Audience)
	resp, err := http.Post(url, "plain/text", nil)
	if err != nil {
		return tokenResponse, err

	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return tokenResponse, err
	}

	return tokenResponse, nil
}

func (provider *OAuthProvider) Refresh(refreshToken string) (TokenResponse, error) {
	var tokenResponse TokenResponse

	url := fmt.Sprintf("%s?grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s", provider.TokenUrl, provider.ClientId, provider.ClientSecret, refreshToken)
	resp, err := http.Post(url, "plain/text", nil)
	if err != nil {
		return tokenResponse, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode > 499 && resp.StatusCode < 599 {
			return tokenResponse, errors.New("auth server has an internal error")
		}

		var tokenErrorResponse TokenErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&tokenErrorResponse); err != nil {
			return tokenResponse, err
		}

		if tokenErrorResponse.Error == "invalid_request" {
			return tokenResponse, ErrInvalidRefreshToken
		}

		return tokenResponse, errors.New("something is wrong with the refresh request")
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return tokenResponse, err
	}

	return tokenResponse, nil
}
