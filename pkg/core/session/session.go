package session

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net/http"
)

type Key string

const SessionKey Key = "session"

type Session struct {
	Id     string
	Values map[string]any
}

func (session *Session) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(session.Values); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (session *Session) Deserialize(src []byte) error {
	dec := gob.NewDecoder(bytes.NewBuffer(src))
	if err := dec.Decode(&session.Values); err != nil {
		return err
	}
	return nil
}

func FromRequest(r *http.Request) *Session {
	return r.Context().Value(SessionKey).(*Session)
}

func (session *Session) Has(key string) bool {
	_, found := session.Values[key]
	return found
}

func (session *Session) Set(name string, value any) {
	session.Values[name] = value
}

func (session *Session) Get(name string) any {
	value, found := session.Values[name]
	if !found {
		panic(fmt.Errorf("session: %s not found", name))
	}

	return value
}

func (session *Session) Delete(name string) {
	delete(session.Values, name)
}
