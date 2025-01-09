package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
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

func Decode(token string, key any) (Token, error) {
	var decodedToken Token
	tokenParts := strings.Split(token, ".")
	if len(token) != 3 {
		return decodedToken, errors.New("invalid token provided")
	}

	header, err := base64.RawURLEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return decodedToken, err
	}

	payload, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return decodedToken, err
	}

	if err := json.Unmarshal(header, &decodedToken.Header); err != nil {
		return decodedToken, err
	}

	if err := json.Unmarshal(payload, &decodedToken.Payload); err != nil {
		return decodedToken, err
	}

	// todo validate signature

	return decodedToken, nil
}
