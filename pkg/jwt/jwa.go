package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// type JWA int

// const (
// 	_ JWA = iota
// 	SigningAlgorithmHS256
// 	SigningAlgorithmHS384
// 	SigningAlgorithmHS512
// 	SigningAlgorithmRS256
// 	SigningAlgorithmRS384
// 	SigningAlgorithmRS512
// 	SigningAlgorithmES256
// 	SigningAlgorithmES384
// 	SigningAlgorithmES512
// 	SigningAlgorithmPS256
// 	SigningAlgorithmPS384
// 	SigningAlgorithmPS512
// 	SigningAlgorithmNone
// )

func signWithRSA(token Token, key *rsa.PrivateKey) (string, error) {
	var hash crypto.Hash
	switch key.Size() {
	case 256:
		{
			hash = crypto.SHA256
			token.Header["alg"] = "RS256"
		}
	case 384:
		{
			hash = crypto.SHA384
			token.Header["alg"] = "RS384"
		}
	case 512:
		{
			hash = crypto.SHA512
			token.Header["alg"] = "RS512"
		}
	default:
		{
			return "", errors.New("rsa encoding : unknown type")
		}
	}

	header, err := json.Marshal(token.Header)
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(token.Payload)
	if err != nil {
		return "", err
	}

	encodedToken := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)

	hasher := hash.New()
	if _, err := hasher.Write([]byte(encodedToken)); err != nil {
		return "", err
	}

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, key, hash, hasher.Sum(nil))
	if err != nil {
		return "", err
	}

	signedToken := encodedToken + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	return signedToken, nil
}

func verifyWithRsa(token Token, key *rsa.PublicKey) error {
	var hash crypto.Hash
	switch token.Header["alg"] {
	case "RS256":
		{
			hash = crypto.SHA256
		}
	case "RS384":
		{
			hash = crypto.SHA384
		}
	case "RS512":
		{
			hash = crypto.SHA512
		}
	default:
		{
			return errors.New("rsa encoding : unknown type")
		}
	}
	hasher := hash.New()
	hasher.Write([]byte(token.Signature))

	return rsa.VerifyPKCS1v15(key, hash, hasher.Sum(nil), token.Signature)
}
