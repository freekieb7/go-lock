package domain

import (
	"time"

	"github.com/google/uuid"
)

type AuthorizationCode struct {
	ID                  uuid.UUID `json:"id"`
	Code                string    `json:"code"`
	ClientID            uuid.UUID `json:"client_id"`
	UserID              uuid.UUID `json:"user_id"`
	Scopes              []string  `json:"scopes"`
	RedirectURI         string    `json:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
}
