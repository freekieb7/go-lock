package jwt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"log"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/random"
)

func GenerateRsaJwks() (model.Jwks, error) {
	var jwks model.Jwks

	// generate key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privatekey)
	if err != nil {
		return jwks, err
	}

	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	var privateKeyBuff bytes.Buffer
	err = pem.Encode(&privateKeyBuff, privateKeyBlock)
	if err != nil {
		return jwks, err
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return jwks, err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	var publicKeyBuff bytes.Buffer
	err = pem.Encode(&publicKeyBuff, publicKeyBlock)
	if err != nil {
		return jwks, err
	}

	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(publickey.E))
	bs = bs[1:] // drop most significant byte - leaving least-significant 3-bytes

	jwks.Id = random.NewString(24)
	jwks.PublicKey = publicKeyBuff.Bytes()
	jwks.PrivateKey = privateKeyBuff.Bytes()
	jwks.PublicKeyModules = publickey.N.Bytes()
	jwks.PublicKeyExponent = bs

	return jwks, nil
}
