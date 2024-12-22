package model

type Jwks struct {
	Id                string
	PublicKey         []byte
	PrivateKey        []byte
	PublicKeyModules  []byte
	PublicKeyExponent []byte
}
