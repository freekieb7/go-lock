package domain

import (
	"time"

	"github.com/google/uuid"
)

type AccessToken struct {
	ID        uuid.UUID
	Token     string
	ClientID  uuid.UUID
	AccountID uuid.UUID
	Scopes    []string
	ExpiresAt time.Time
	CreatedAt time.Time
}
