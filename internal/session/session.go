package session

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID        uuid.UUID
	Token     string
	UserID    uuid.UUID
	Data      map[string]any
	ExpiresAt time.Time
	CreatedAt time.Time
}
