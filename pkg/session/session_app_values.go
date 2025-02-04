package session

import (
	"encoding/gob"

	"github.com/google/uuid"
)

func init() {
	gob.Register(AppUser{})
	gob.Register(uuid.UUID{})
}

const (
	sessionKeyAppUser string = "app_user"
)

type AppUser struct {
	Id             uuid.UUID
	AccessToken    string
	TokenExpiresAt int64
	RefreshToken   string
	IdToken        string
}

func (s *Session) AppUser() AppUser {
	return s.Get(sessionKeyAppUser).(AppUser)
}

func (s *Session) SetAppUser(user AppUser) {
	s.Set(sessionKeyAppUser, user)
}

func (s *Session) HasAppUser() bool {
	return s.Has(sessionKeyAppUser)
}
