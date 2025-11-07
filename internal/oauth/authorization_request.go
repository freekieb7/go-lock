package oauth

import "github.com/google/uuid"

type AuthorizationRequest struct {
	ClientID            uuid.UUID `json:"client_id"`
	Scopes              []string  `json:"scopes"`
	RedirectURI         string    `json:"redirect_uri"`
	State               string    `json:"state"`
	ResponseType        string    `json:"response_type"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	OriginalURL         string    `json:"original_url"`
}
