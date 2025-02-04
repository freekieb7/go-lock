package helper

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
	jwta "github.com/golang-jwt/jwt/v5"
)

type wellKnownOpenIdResponseBody struct {
	JwksUri string `json:"jwks_uri"`
}

type openIdKey struct {
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

type jwksUriResponseBody struct {
	Keys []openIdKey `json:"keys"`
}

// todo refactor
func VerifyWithOpenId(token jwt.Token) error {
	issuer := token.Payload["iss"].(string)

	resOpenId, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		return err
	}
	defer resOpenId.Body.Close()

	var openIdResBody wellKnownOpenIdResponseBody
	if err := json.NewDecoder(resOpenId.Body).Decode(&openIdResBody); err != nil {
		return err
	}

	resJwks, err := http.Get(openIdResBody.JwksUri)
	if err != nil {
		return err
	}
	defer resJwks.Body.Close()

	var jwksUriResBody jwksUriResponseBody
	if err := json.NewDecoder(resJwks.Body).Decode(&jwksUriResBody); err != nil {
		return err
	}

	// todo proper signature check
	var matchingKey openIdKey
	for _, key := range jwksUriResBody.Keys {
		if token.Header["kid"].(string) != key.Kid {
			continue
		}

		if token.Header["alg"] != key.Alg {
			continue
		}

		if key.Use != "sig" {
			continue
		}

		matchingKey = key
	}

	if matchingKey.Alg == "" {
		return errors.New("no matching public key found")
	}

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
		eBytes = make([]byte, 8-len(decE), 8)
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

	header, err := json.Marshal(token.Header)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(token.Payload)
	if err != nil {
		return err
	}

	encodedToken := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)

	if err := jwta.GetSigningMethod("RS256").Verify(encodedToken, token.Signature, pubKey); err != nil {
		return err
	}

	if err := jwt.Verify(token, pubKey); err != nil {
		return err
	}

	return nil
}
