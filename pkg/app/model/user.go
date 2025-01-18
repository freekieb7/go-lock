package model

import (
	"encoding/gob"

	"github.com/google/uuid"
)

func init() {
	gob.Register(SessionUser{})
	gob.Register(uuid.UUID{})
}

type SessionUser struct {
	Id             uuid.UUID
	AccessToken    string
	TokenExpiresAt int64
	RefreshToken   string
	IdToken        string
}
