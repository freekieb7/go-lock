package domain

import (
	"time"

	"github.com/google/uuid"
)

const RefreshTokenExpiresIn = time.Hour * 24 * 30 // 30 days

type RefreshToken struct {
	ID            uuid.UUID
	Token         string
	ClientID      uuid.UUID
	UserID        uuid.UUID
	Scopes        []string
	ChainID       uuid.UUID  // Links related refresh tokens in a rotation chain
	ParentTokenID *uuid.UUID // Previous token in the chain (nullable)
	IsRevoked     bool       // Tracks if token has been used/revoked
	ExpiresAt     time.Time
	CreatedAt     time.Time
	UsedAt        *time.Time // When the token was used for refresh (nullable)
}
