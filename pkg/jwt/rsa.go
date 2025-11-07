package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// Common JWT errors
var (
	ErrKeyMustBePEMEncoded       = errors.New("jwt: key must be a PEM encoded PKCS1 or PKCS8 key")
	ErrNotRSAPrivateKey          = errors.New("jwt: key is not a valid RSA private key")
	ErrNotRSAPublicKey           = errors.New("jwt: key is not a valid RSA public key")
	ErrInvalidKey                = errors.New("jwt: key is invalid")
	ErrInvalidKeyType            = errors.New("jwt: key is of invalid type")
	ErrHashUnavailable           = errors.New("jwt: the requested hash function is unavailable")
	ErrTokenMalformed            = errors.New("jwt: token is malformed")
	ErrTokenUnverifiable         = errors.New("jwt: token is unverifiable")
	ErrTokenSignatureInvalid     = errors.New("jwt: token signature is invalid")
	ErrTokenRequiredClaimMissing = errors.New("jwt: token is missing required claim")
	ErrTokenInvalidAudience      = errors.New("jwt: token has invalid audience")
	ErrTokenExpired              = errors.New("jwt: token is expired")
	ErrTokenUsedBeforeIssued     = errors.New("jwt: token used before issued")
	ErrTokenInvalidIssuer        = errors.New("jwt: token has invalid issuer")
	ErrTokenInvalidSubject       = errors.New("jwt: token has invalid subject")
	ErrTokenNotValidYet          = errors.New("jwt: token is not valid yet")
	ErrTokenInvalidId            = errors.New("jwt: token has invalid id")
	ErrTokenInvalidClaims        = errors.New("jwt: token has invalid claims")
	ErrInvalidType               = errors.New("jwt: invalid type for claim")
)

// ParseRSAPrivateKeyFromPEM parses a PEM encoded PKCS1 or PKCS8 private key
func ParseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	var parsedKey any
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, ErrNotRSAPrivateKey
	}

	return pkey, nil
}

// ParseRSAPublicKeyFromPEM parses a certificate or a PEM encoded PKCS1 or PKIX public key
func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey any
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			if parsedKey, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
				return nil, err
			}
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, ErrNotRSAPublicKey
	}

	return pkey, nil
}

// SignWithRSAPrivateKey signs a JWT token with an RSA private key
func SignWithRSAPrivateKey(token Token, key *rsa.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, errors.Join(errors.New("RSA sign expects *rsa.PrivateKey"), ErrInvalidKeyType)
	}

	// Create the hasher
	var hash crypto.Hash
	switch key.Size() {
	case 256:
		hash = crypto.SHA256
		token.Header["alg"] = "RS256"
	case 384:
		hash = crypto.SHA384
		token.Header["alg"] = "RS384"
	case 512:
		hash = crypto.SHA512
		token.Header["alg"] = "RS512"
	default:
		return nil, errors.New("jwt: unsupported RSA key size")
	}

	hasher := hash.New()

	h, err := json.Marshal(token.Header)
	if err != nil {
		return nil, fmt.Errorf("error marshalling token header: %w", err)
	}

	c, err := json.Marshal(token.Payload)
	if err != nil {
		return nil, fmt.Errorf("error marshalling token payload: %w", err)
	}

	signingString := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)

	hasher.Write([]byte(signingString))

	// Sign the string and return the encoded bytes
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, hash, hasher.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("error signing token: %w", err)
	}

	return sigBytes, nil
}

// VerifyWithRSAPublicKey verifies a JWT token signature with an RSA public key
func VerifyWithRSAPublicKey(token Token, key *rsa.PublicKey) error {
	if key == nil {
		return errors.Join(errors.New("RSA verify expects *rsa.PublicKey"), ErrInvalidKeyType)
	}

	var hash crypto.Hash
	switch token.Header["alg"] {
	case "RS256":
		hash = crypto.SHA256
	case "RS384":
		hash = crypto.SHA384
	case "RS512":
		hash = crypto.SHA512
	default:
		return errors.New("jwt: unsupported RSA algorithm")
	}

	hasher := hash.New()

	h, err := json.Marshal(token.Header)
	if err != nil {
		return fmt.Errorf("error marshalling token header: %w", err)
	}

	c, err := json.Marshal(token.Payload)
	if err != nil {
		return fmt.Errorf("error marshalling token payload: %w", err)
	}

	signingString := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	hasher.Write([]byte(signingString))

	return rsa.VerifyPKCS1v15(key, hash, hasher.Sum(nil), token.Signature)
}
