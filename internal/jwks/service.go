package jwks

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"github.com/freekieb7/go-lock/internal/util"
	"github.com/freekieb7/go-lock/pkg/jwt"
	"github.com/google/uuid"
)

// JWKSService handles JWKS operations and key lifecycle management
type JWKSService struct {
	store  *JWKSStore
	logger *slog.Logger
}

// NewJWKSService creates a new JWKS service
func NewJWKSService(store *JWKSStore, logger *slog.Logger) *JWKSService {
	return &JWKSService{
		store:  store,
		logger: logger,
	}
}

// GenerateNewKey generates a new RSA key pair and stores it in the database
func (s *JWKSService) GenerateNewKey(ctx context.Context, keySize int, expiresIn time.Duration) (*JWKSRecord, error) {
	if keySize != 2048 && keySize != 3072 && keySize != 4096 {
		keySize = 2048 // Default to 2048 if invalid size provided
	}

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	publicKey := &privateKey.PublicKey

	// Generate unique key ID
	kid, err := util.GenerateRandomString(24)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	// Encode private key to PEM
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Extract RSA modulus and exponent for JWK format
	nBytes := publicKey.N.Bytes()
	eBytes := make([]byte, 4)
	eBytes[0] = byte(publicKey.E >> 24)
	eBytes[1] = byte(publicKey.E >> 16)
	eBytes[2] = byte(publicKey.E >> 8)
	eBytes[3] = byte(publicKey.E)

	// Remove leading zero bytes from exponent
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}

	// Base64url encode for JWK
	n := base64.RawURLEncoding.EncodeToString(nBytes)
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	// Determine algorithm based on key size
	alg := "RS256"
	switch keySize {
	case 3072:
		alg = "RS384"
	case 4096:
		alg = "RS512"
	}

	// Create JWKS record
	jwksRecord := &JWKSRecord{
		ID:            uuid.New(),
		KID:           kid,
		KTY:           "RSA",
		Use:           "sig",
		Alg:           alg,
		N:             n,
		E:             e,
		PrivateKeyPEM: string(privateKeyPEM),
		PublicKeyPEM:  string(publicKeyPEM),
		IsActive:      false, // Will be activated separately
		CreatedAt:     time.Now(),
	}

	if expiresIn > 0 {
		expiresAt := time.Now().Add(expiresIn)
		jwksRecord.ExpiresAt = &expiresAt
	}

	// Store in database
	if err := s.store.CreateJWKS(ctx, jwksRecord); err != nil {
		return nil, fmt.Errorf("failed to store JWKS: %w", err)
	}

	s.logger.InfoContext(ctx, "Generated new JWKS key",
		"kid", kid, "alg", alg, "key_size", keySize)

	return jwksRecord, nil
}

// RotateKey rotates the signing key by creating a new one and deactivating the old one
func (s *JWKSService) RotateKey(ctx context.Context, keySize int, expiresIn time.Duration) error {
	// Get current active key
	currentKey, err := s.store.GetActiveSigningKey(ctx)
	if err != nil && err != ErrNoActiveKey {
		return fmt.Errorf("failed to get current active key: %w", err)
	}

	// Generate new key
	newKey, err := s.GenerateNewKey(ctx, keySize, expiresIn)
	if err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	// Activate the new key
	if err := s.ActivateKey(ctx, newKey.KID); err != nil {
		return fmt.Errorf("failed to activate new key: %w", err)
	}

	// Deactivate the old key if it exists
	if currentKey != nil {
		if err := s.store.DeactivateKey(ctx, currentKey.KID); err != nil {
			s.logger.WarnContext(ctx, "Failed to deactivate old key",
				"old_kid", currentKey.KID, "error", err)
		}
	}

	s.logger.InfoContext(ctx, "Successfully rotated signing key",
		"new_kid", newKey.KID, "old_kid", func() string {
			if currentKey != nil {
				return currentKey.KID
			}
			return "none"
		}())

	return nil
}

// ActivateKey marks a key as the active signing key
func (s *JWKSService) ActivateKey(ctx context.Context, kid string) error {
	// First, deactivate all current active keys
	if err := s.store.DeactivateAllKeys(ctx); err != nil {
		return fmt.Errorf("failed to deactivate current keys: %w", err)
	}

	// Activate the specified key
	return s.store.ActivateKey(ctx, kid)
}

// GetPublicJWKS returns the public key set for the JWKS endpoint
func (s *JWKSService) GetPublicJWKS(ctx context.Context) (*JWKSet, error) {
	keys, err := s.store.GetPublicKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys: %w", err)
	}

	jwkSet := &JWKSet{
		Keys: make([]JWK, 0, len(keys)),
	}

	for _, key := range keys {
		if key.IsUsable() {
			jwkSet.Keys = append(jwkSet.Keys, key.ToJWK())
		}
	}

	return jwkSet, nil
}

// GetSigningKey returns the current active signing key for JWT creation
func (s *JWKSService) GetSigningKey(ctx context.Context) (*jwt.KeySet, error) {
	jwksRecord, err := s.store.GetActiveSigningKey(ctx)
	if err != nil {
		return nil, err
	}

	// Convert to jwt.KeySet format for the new JWT package
	return &jwt.KeySet{
		ID:                jwksRecord.KID,
		PrivateKey:        []byte(jwksRecord.PrivateKeyPEM),
		PublicKey:         []byte(jwksRecord.PublicKeyPEM),
		PublicKeyModules:  s.decodeBase64URL(jwksRecord.N),
		PublicKeyExponent: s.decodeBase64URL(jwksRecord.E),
	}, nil
}

// EnsureSigningKey ensures there's at least one active signing key
func (s *JWKSService) EnsureSigningKey(ctx context.Context) error {
	_, err := s.store.GetActiveSigningKey(ctx)
	if err == ErrNoActiveKey {
		s.logger.InfoContext(ctx, "No active signing key found, generating new one")

		// Generate and activate a new key
		if err := s.RotateKey(ctx, 2048, 0); err != nil {
			return fmt.Errorf("failed to create initial signing key: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check for active signing key: %w", err)
	}

	return nil
}

// CleanupExpiredKeys removes expired keys after a grace period
func (s *JWKSService) CleanupExpiredKeys(ctx context.Context, gracePeriod time.Duration) error {
	return s.store.CleanupExpiredKeys(ctx, gracePeriod)
}

// Helper methods

func (s *JWKSService) decodeBase64URL(encoded string) []byte {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil
	}
	return decoded
}
