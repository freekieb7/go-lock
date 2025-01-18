package session

import (
	"encoding/gob"

	"github.com/google/uuid"
)

func init() {
	gob.Register(SessionUser{})
	gob.Register(uuid.UUID{})
}

const SessionUserKey string = "user"

type SessionUser struct {
	Id             uuid.UUID
	AccessToken    string
	TokenExpiresAt int64
	RefreshToken   string
	IdToken        string
}

func (s *Session) User() SessionUser {
	return s.Get(SessionUserKey).(SessionUser)
}

func (s *Session) SetUser(user SessionUser) {
	s.Set(SessionUserKey, user)
}

func (s *Session) HasUser() bool {
	return s.Has(SessionUserKey)
}
