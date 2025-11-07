package account

import (
	"time"

	"github.com/google/uuid"
)

type Client struct {
	ID             uuid.UUID
	PublicID       string
	Secret         string
	Name           string
	Description    string
	RedirectURIs   []string
	IsConfidential bool
	LogoURI        string
	CreatedAt      time.Time
}
