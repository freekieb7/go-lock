package helpers

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"

	"github.com/freekieb7/go-lock/internal/util"
	"github.com/freekieb7/go-lock/pkg/jwt"
)

// GenerateRSAKeySet generates a new RSA key pair for JWT signing
func GenerateRSAKeySet() (*jwt.KeySet, error) {
	var keySet jwt.KeySet

	// Generate RSA private key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA private key: %w", err)
	}
	publickey := &privatekey.PublicKey

	// Marshal private key to PEM format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privatekey)
	if err != nil {
		return nil, err
	}

	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	var privateKeyBuff bytes.Buffer
	err = pem.Encode(&privateKeyBuff, privateKeyBlock)
	if err != nil {
		return nil, err
	}

	// Marshal public key to PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return nil, err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	var publicKeyBuff bytes.Buffer
	err = pem.Encode(&publicKeyBuff, publicKeyBlock)
	if err != nil {
		return nil, err
	}

	// Convert exponent to bytes
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(publickey.E))
	bs = bs[1:] // drop most significant byte - leaving least-significant 3-bytes

	// Generate random ID
	id, err := util.GenerateRandomString(24)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random id for key set: %w", err)
	}

	keySet.ID = id
	keySet.PublicKey = publicKeyBuff.Bytes()
	keySet.PrivateKey = privateKeyBuff.Bytes()
	keySet.PublicKeyModules = publickey.N.Bytes()
	keySet.PublicKeyExponent = bs

	return &keySet, nil
}
