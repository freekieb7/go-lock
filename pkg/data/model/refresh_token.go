package model

import (
	"time"

	"github.com/google/uuid"
)

const RefreshTokenExpiresIn = time.Hour * 24 * 30

type RefreshToken struct {
	Id               uuid.UUID
	ClientId         uuid.UUID
	UserId           uuid.UUID
	ResourceServerId uuid.UUID
	Scope            string
	CreatedAt        int64
	ExpiresAt        int64
}
