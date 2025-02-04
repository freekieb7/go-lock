package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/freekieb7/go-lock/pkg/data/model"
)

type Token struct {
	Header    map[string]any
	Payload   map[string]any
	Signature []byte
}

func New() Token {
	return Token{
		Header:    make(map[string]any),
		Payload:   make(map[string]any),
		Signature: make([]byte, 0),
	}
}

func Sign(token Token, key any) (string, error) {
	token.Header["typ"] = "JWT"

	var err error
	var sig []byte
	switch k := key.(type) {
	case model.Jwks:
		{
			privateKey, err := ParseRSAPrivateKeyFromPEM(k.PrivateKey)
			if err != nil {
				return "", err
			}

			token.Header["kid"] = k.Id

			sig, err = SignWithRSAPublicKey(token, privateKey)
		}
	case *rsa.PrivateKey:
		{
			sig, err = SignWithRSAPublicKey(token, k)
		}
	default:
		{
			return "", errors.New("jwt encoding: invalid key")
		}
	}

	h, err := json.Marshal(token.Header)
	if err != nil {
		return "", err
	}

	c, err := json.Marshal(token.Payload)
	if err != nil {
		return "", err
	}

	signingString := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c) + "." + base64.RawURLEncoding.EncodeToString(sig)
	return signingString, nil
}

func Verify(token Token, key any) error {
	switch k := key.(type) {
	case model.Jwks:
		{
			publicKey, err := ParseRSAPublicKeyFromPEM(k.PublicKey)
			if err != nil {
				return err
			}

			return verifyWithRsa(token, publicKey)
		}
	case *rsa.PublicKey:
		{
			return verifyWithRsa(token, k)
		}
	default:
		{
			return errors.New("jwt encoding: invalid key")
		}
	}
}

func Decode(token string) (Token, error) {
	var decodedToken Token
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
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

	signature, err := base64.RawURLEncoding.DecodeString(tokenParts[2])
	if err != nil {
		return decodedToken, err
	}

	if err := json.Unmarshal(header, &decodedToken.Header); err != nil {
		return decodedToken, err
	}

	if err := json.Unmarshal(payload, &decodedToken.Payload); err != nil {
		return decodedToken, err
	}

	decodedToken.Signature = signature

	return decodedToken, nil
}
