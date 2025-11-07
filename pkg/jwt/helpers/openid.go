package helpers

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/jwt"
)

// WellKnownOpenIDResponse represents the OpenID Connect discovery response
type WellKnownOpenIDResponse struct {
	JwksURI string `json:"jwks_uri"`
}

// OpenIDKey represents a key from the JWKS endpoint
type OpenIDKey struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
	X5t    string   `json:"x5t"`
	X5c    []string `json:"x5c"`
}

// JWKSResponse represents the JWKS endpoint response
type JWKSResponse struct {
	Keys []OpenIDKey `json:"keys"`
}

// VerifyWithOpenID validates a JWT token using OpenID Connect discovery
func VerifyWithOpenID(token jwt.Token) error {
	issuer, ok := token.Payload["iss"].(string)
	if !ok {
		return errors.New("jwt: missing or invalid issuer claim")
	}

	// Get OpenID Connect discovery document
	resOpenID, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		return err
	}
	defer resOpenID.Body.Close()

	var openIDResBody WellKnownOpenIDResponse
	if err := json.NewDecoder(resOpenID.Body).Decode(&openIDResBody); err != nil {
		return err
	}

	// Get JWKS from the discovered endpoint
	resJWKS, err := http.Get(openIDResBody.JwksURI)
	if err != nil {
		return err
	}
	defer resJWKS.Body.Close()

	var jwksResBody JWKSResponse
	if err := json.NewDecoder(resJWKS.Body).Decode(&jwksResBody); err != nil {
		return err
	}

	// Find the matching public key from JWKS
	var matchingKey OpenIDKey
	headerKid, ok := token.Header["kid"].(string)
	if !ok {
		return errors.New("jwt: missing kid in token header")
	}

	headerAlg, ok := token.Header["alg"].(string)
	if !ok {
		return errors.New("jwt: missing alg in token header")
	}

	for _, key := range jwksResBody.Keys {
		if headerKid != key.Kid {
			continue
		}

		if headerAlg != key.Alg {
			continue
		}

		if key.Use != "sig" {
			continue
		}

		matchingKey = key
		break
	}

	if matchingKey.Alg == "" {
		return errors.New("jwt: no matching public key found in JWKS")
	}

	// Decode the RSA public key from the JWKS
	decN, err := base64.RawURLEncoding.DecodeString(matchingKey.N)
	if err != nil {
		return err
	}
	n := big.NewInt(0)
	n.SetBytes(decN)

	decE, err := base64.RawURLEncoding.DecodeString(matchingKey.E)
	if err != nil {
		return err
	}

	var eBytes []byte
	if len(decE) < 8 {
		eBytes = make([]byte, 8-len(decE))
		eBytes = append(eBytes, decE...)
	} else {
		eBytes = decE
	}
	eReader := bytes.NewReader(eBytes)

	var e uint64
	err = binary.Read(eReader, binary.BigEndian, &e)
	if err != nil {
		return err
	}

	pubKey := &rsa.PublicKey{N: n, E: int(e)}

	// Verify the token signature
	return jwt.Verify(token, pubKey)
}
