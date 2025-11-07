package domain

import (
	"time"

	"github.com/google/uuid"
)

type ResourceServer struct {
	ID          uuid.UUID
	URL         string
	Description string
	Scopes      map[string]string // scope name -> scope description
	CreatedAt   time.Time
}
