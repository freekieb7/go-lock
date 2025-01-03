package model

import (
	"fmt"

	"github.com/google/uuid"
)

type ClientType string

var (
	ClientTypeDefault ClientType = "default"
	ClientTypeManager ClientType = "manager"
)

func ClientTypeFrom(key string) (ClientType, error) {
	switch key {
	case string(ClientTypeDefault):
		{
			return ClientTypeDefault, nil
		}
	case string(ClientTypeManager):
		{
			return ClientTypeManager, nil
		}
	default:
		{
			return ClientTypeDefault, fmt.Errorf("client type not found : %s", key)
		}
	}
}

type Client struct {
	Id             uuid.UUID
	Secret         string
	Name           string
	Type           ClientType
	IsConfidential bool
	RedirectUris   []string
}
