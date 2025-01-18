package model

import (
	"strings"

	"github.com/google/uuid"
)

type ClientType string

const (
	ClientTypeSystem ClientType = "system"
	ClientTypeCustom ClientType = "custom"
)

func (t ClientType) UserFriendlyName() string {
	switch t {
	case ClientTypeSystem:
		{
			return "System"
		}
	case ClientTypeCustom:
		{
			return "Custom"
		}
	}

	return "Unknown"
}

type Client struct {
	Id             uuid.UUID
	Secret         string
	Type           ClientType
	Name           string
	RedirectUrls   string
	CreatedAt      int64
	UpdatedAt      int64
	DeletedAt      int64
	IsConfidential bool
}

func (client Client) RedirectUriList() []string {
	return strings.Split(client.RedirectUrls, " ")
}
