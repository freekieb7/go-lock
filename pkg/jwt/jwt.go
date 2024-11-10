package jwt

import (
	"crypto/rsa"
	"errors"
)

type Token struct {
	Header  map[string]any
	Payload map[string]any
}

func New() Token {
	return Token{
		Header:  make(map[string]any),
		Payload: make(map[string]any),
	}
}

func Encode(token Token, key any) (string, error) {
	token.Header["typ"] = "JWT"

	switch k := key.(type) {
	case *rsa.PrivateKey:
		{
			return encodeWithRSA(token, k)
		}
	default:
		{
			return "", errors.New("jwt encoding: invalid key")
		}
	}
}
