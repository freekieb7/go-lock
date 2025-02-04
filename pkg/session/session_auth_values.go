package session

import (
	"encoding/gob"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

func init() {
	gob.Register(Client{})
	gob.Register(uuid.UUID{})
}

const (
	sessionKeyUser         string = "user"
	sessionKeyClientPrefix string = "client-"
	sessionKeyRememberMe   string = "remember_me"
)

type Client struct {
	UserId uuid.UUID
}

func (s *Session) RememberMe() uuid.UUID {
	return s.Get(sessionKeyRememberMe).(uuid.UUID)
}

func (s *Session) HasRememberMe() bool {
	return s.Has(sessionKeyRememberMe)
}

func (s *Session) DeleteRememberMe() {
	s.Delete(sessionKeyRememberMe)
}

func (s *Session) Client(clientId uuid.UUID) Client {
	clientKey := fmt.Sprintf("%s%s", sessionKeyClientPrefix, clientId)
	return s.Get(clientKey).(Client)
}

func (s *Session) HasClient(clientId uuid.UUID) bool {
	clientKey := fmt.Sprintf("%s%s", sessionKeyClientPrefix, clientId)
	return s.Has(clientKey)
}

func (s *Session) DeleteClient(clientId uuid.UUID) {
	clientKey := fmt.Sprintf("%s%s", sessionKeyClientPrefix, clientId)
	s.Delete(clientKey)
}

func (s *Session) DeleteAllClients() {
	for key := range s.Values {
		if strings.HasPrefix(key, sessionKeyClientPrefix) {
			delete(s.Values, key)
		}
	}
}
