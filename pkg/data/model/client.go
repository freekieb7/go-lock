package model

import (
	"strings"

	"github.com/google/uuid"
)

type Client struct {
	Id             uuid.UUID
	Secret         string
	IsSystem       bool
	Name           string
	Description    string
	RedirectUrls   string
	LogoUrl        string
	CreatedAt      int64
	UpdatedAt      int64
	IsConfidential bool
}

func (client Client) RedirectUriList() []string {
	return strings.Split(client.RedirectUrls, " ")
}
