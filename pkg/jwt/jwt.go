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
		Header:  make(map[string]any),
		Payload: make(map[string]any),
	}
}

func Encode(token Token, key any) (string, error) {
	token.Header["typ"] = "JWT"

	switch k := key.(type) {
	case model.Jwks:
		{
			privateKey, err := ParseRsaPrivateKey(k.PrivateKey)
			if err != nil {
				return "", err
			}

			token.Header["kid"] = k.Id

			return encodeWithRSA(token, privateKey)
		}
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

func VerifySignature(token Token, key any) error {
	switch k := key.(type) {
	case model.Jwks:
		{
			publicKey, err := ParseRsaPublicKey(k.PublicKey)
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

	signature, err := base64.RawStdEncoding.DecodeString(tokenParts[2])

	if err := json.Unmarshal(header, &decodedToken.Header); err != nil {
		return decodedToken, err
	}

	if err := json.Unmarshal(payload, &decodedToken.Payload); err != nil {
		return decodedToken, err
	}

	decodedToken.Signature = signature

	return decodedToken, nil
}
