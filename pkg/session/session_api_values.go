package session

import (
	"encoding/gob"

	"github.com/google/uuid"
)

func init() {
	gob.Register(Token{})
	gob.Register(uuid.UUID{})
}

const (
	sessionKeyToken string = "token"
)

type Token struct {
	UserId uuid.UUID
	Scope  []string
}

func (s *Session) Token() Token {
	return s.Get(sessionKeyToken).(Token)
}

func (s *Session) SetToken(user Token) {
	s.Set(sessionKeyToken, user)
}

func (s *Session) HasToken() bool {
	return s.Has(sessionKeyToken)
}
