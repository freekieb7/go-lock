package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Token represents a JWT token with header, payload, and signature
type Token struct {
	Header    map[string]any `json:"header"`
	Payload   map[string]any `json:"payload"`
	Signature []byte         `json:"signature"`
}

// NewToken creates a new empty JWT token
func NewToken() Token {
	return Token{
		Header:    make(map[string]any),
		Payload:   make(map[string]any),
		Signature: make([]byte, 0),
	}
}

// Sign signs a JWT token with the provided key and returns the JWT string
func Sign(token Token, key any) (string, error) {
	token.Header["typ"] = "JWT"

	var err error
	var sig []byte

	switch k := key.(type) {
	case *KeySet:
		privateKey, err := ParseRSAPrivateKeyFromPEM(k.PrivateKey)
		if err != nil {
			return "", err
		}
		token.Header["kid"] = k.ID
		sig, err = SignWithRSAPrivateKey(token, privateKey)
	case PrivateKeySigner:
		sig, err = k.Sign(token)
	default:
		return "", errors.New("jwt: unsupported key type for signing")
	}

	if err != nil {
		return "", err
	}

	h, err := json.Marshal(token.Header)
	if err != nil {
		return "", err
	}

	c, err := json.Marshal(token.Payload)
	if err != nil {
		return "", err
	}

	signingString := base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(c) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
	return signingString, nil
}

// Verify verifies a JWT token signature with the provided key
func Verify(token Token, key any) error {
	switch k := key.(type) {
	case *KeySet:
		publicKey, err := ParseRSAPublicKeyFromPEM(k.PublicKey)
		if err != nil {
			return err
		}
		return VerifyWithRSAPublicKey(token, publicKey)
	case PublicKeyVerifier:
		return k.Verify(token)
	default:
		return errors.New("jwt: unsupported key type for verification")
	}
}

// Decode decodes a JWT token string into a Token struct
func Decode(tokenString string) (Token, error) {
	var decodedToken Token
	tokenParts := strings.Split(tokenString, ".")
	if len(tokenParts) != 3 {
		return decodedToken, errors.New("jwt: invalid token format, expected 3 parts")
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

// KeySet represents a JWKS key pair for JWT operations
type KeySet struct {
	ID                string `json:"id"`
	PrivateKey        []byte `json:"private_key"`
	PublicKey         []byte `json:"public_key"`
	PublicKeyModules  []byte `json:"public_key_modules"`
	PublicKeyExponent []byte `json:"public_key_exponent"`
}

// PrivateKeySigner interface for types that can sign JWT tokens
type PrivateKeySigner interface {
	Sign(token Token) ([]byte, error)
}

// PublicKeyVerifier interface for types that can verify JWT tokens
type PublicKeyVerifier interface {
	Verify(token Token) error
}
