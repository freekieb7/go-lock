package jwks

import (
	"time"

	"github.com/google/uuid"
)

// JWKSRecord represents a JSON Web Key Set record in the database
type JWKSRecord struct {
	ID            uuid.UUID  `json:"id"`
	KID           string     `json:"kid"`       // Key ID
	KTY           string     `json:"kty"`       // Key Type (RSA, EC, etc.)
	Use           string     `json:"use"`       // Key Usage (sig, enc)
	Alg           string     `json:"alg"`       // Algorithm (RS256, RS384, etc.)
	N             string     `json:"n"`         // RSA Modulus (base64url)
	E             string     `json:"e"`         // RSA Exponent (base64url)
	PrivateKeyPEM string     `json:"-"`         // Private key PEM (not exported)
	PublicKeyPEM  string     `json:"-"`         // Public key PEM (not exported)
	IsActive      bool       `json:"is_active"` // Whether key is actively used
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

// JWK represents a JSON Web Key for public consumption (JWKS endpoint)
type JWK struct {
	KTY    string   `json:"kty"`               // Key Type
	Use    string   `json:"use"`               // Key Usage
	Alg    string   `json:"alg"`               // Algorithm
	KID    string   `json:"kid"`               // Key ID
	N      string   `json:"n"`                 // RSA Modulus (base64url)
	E      string   `json:"e"`                 // RSA Exponent (base64url)
	KeyOps []string `json:"key_ops,omitempty"` // Key Operations
}

// JWKSet represents a JSON Web Key Set (collection of JWKs)
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// ToJWK converts a JWKSRecord to a public JWK (removes private key material)
func (j *JWKSRecord) ToJWK() JWK {
	return JWK{
		KTY:    j.KTY,
		Use:    j.Use,
		Alg:    j.Alg,
		KID:    j.KID,
		N:      j.N,
		E:      j.E,
		KeyOps: []string{"verify"}, // Public keys are for verification only
	}
}

// IsExpired checks if the key has expired
func (j *JWKSRecord) IsExpired() bool {
	if j.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*j.ExpiresAt)
}

// IsRevoked checks if the key has been revoked
func (j *JWKSRecord) IsRevoked() bool {
	return j.RevokedAt != nil
}

// IsUsable checks if the key can be used (active, not expired, not revoked)
func (j *JWKSRecord) IsUsable() bool {
	return j.IsActive && !j.IsExpired() && !j.IsRevoked()
}
