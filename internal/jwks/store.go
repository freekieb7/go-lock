package jwks

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/freekieb7/go-lock/internal/database"
)

var (
	ErrJWKSNotFound = errors.New("JWKS not found")
	ErrNoActiveKey  = errors.New("no active signing key found")
)

// JWKSStore handles database operations for JSON Web Key Sets
type JWKSStore struct {
	DB *database.Database
}

// NewJWKSStore creates a new JWKS store
func NewJWKSStore(db *database.Database) *JWKSStore {
	return &JWKSStore{DB: db}
}

// CreateJWKS stores a new JWKS record in the database
func (s *JWKSStore) CreateJWKS(ctx context.Context, jwks *JWKSRecord) error {
	query := `
		INSERT INTO tbl_jwks (
			id, kid, kty, use_sig, alg, n, e, 
			private_key_pem, public_key_pem, is_active, 
			created_at, expires_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)`

	_, err := s.DB.Exec(ctx, query,
		jwks.ID, jwks.KID, jwks.KTY, jwks.Use, jwks.Alg,
		jwks.N, jwks.E, jwks.PrivateKeyPEM, jwks.PublicKeyPEM,
		jwks.IsActive, jwks.CreatedAt, jwks.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create JWKS: %w", err)
	}

	return nil
}

// GetActiveSigningKey retrieves the currently active signing key
func (s *JWKSStore) GetActiveSigningKey(ctx context.Context) (*JWKSRecord, error) {
	query := `
		SELECT id, kid, kty, use_sig, alg, n, e, 
			   private_key_pem, public_key_pem, is_active, 
			   created_at, expires_at, revoked_at
		FROM tbl_jwks 
		WHERE is_active = true AND use_sig = 'sig'
		AND (expires_at IS NULL OR expires_at > NOW())
		AND revoked_at IS NULL
		ORDER BY created_at DESC 
		LIMIT 1`

	jwks := &JWKSRecord{}
	err := s.DB.QueryRow(ctx, query).Scan(
		&jwks.ID, &jwks.KID, &jwks.KTY, &jwks.Use, &jwks.Alg,
		&jwks.N, &jwks.E, &jwks.PrivateKeyPEM, &jwks.PublicKeyPEM,
		&jwks.IsActive, &jwks.CreatedAt, &jwks.ExpiresAt, &jwks.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, database.ErrNoRows) {
			return nil, ErrNoActiveKey
		}
		return nil, fmt.Errorf("failed to get active signing key: %w", err)
	}

	return jwks, nil
}

// GetJWKSByKID retrieves a JWKS by its key ID
func (s *JWKSStore) GetJWKSByKID(ctx context.Context, kid string) (*JWKSRecord, error) {
	query := `
		SELECT id, kid, kty, use_sig, alg, n, e, 
			   private_key_pem, public_key_pem, is_active, 
			   created_at, expires_at, revoked_at
		FROM tbl_jwks 
		WHERE kid = $1`

	jwks := &JWKSRecord{}
	err := s.DB.QueryRow(ctx, query, kid).Scan(
		&jwks.ID, &jwks.KID, &jwks.KTY, &jwks.Use, &jwks.Alg,
		&jwks.N, &jwks.E, &jwks.PrivateKeyPEM, &jwks.PublicKeyPEM,
		&jwks.IsActive, &jwks.CreatedAt, &jwks.ExpiresAt, &jwks.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, database.ErrNoRows) {
			return nil, ErrJWKSNotFound
		}
		return nil, fmt.Errorf("failed to get JWKS by KID: %w", err)
	}

	return jwks, nil
}

// GetPublicKeys retrieves all public keys for the JWKS endpoint
func (s *JWKSStore) GetPublicKeys(ctx context.Context) ([]JWKSRecord, error) {
	query := `
		SELECT id, kid, kty, use_sig, alg, n, e, 
			   private_key_pem, public_key_pem, is_active, 
			   created_at, expires_at, revoked_at
		FROM tbl_jwks 
		WHERE use_sig = 'sig' 
		AND (expires_at IS NULL OR expires_at > NOW())
		AND revoked_at IS NULL
		ORDER BY is_active DESC, created_at DESC`

	rows, err := s.DB.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys: %w", err)
	}
	defer rows.Close()

	var keys []JWKSRecord
	for rows.Next() {
		jwks := JWKSRecord{}
		err := rows.Scan(
			&jwks.ID, &jwks.KID, &jwks.KTY, &jwks.Use, &jwks.Alg,
			&jwks.N, &jwks.E, &jwks.PrivateKeyPEM, &jwks.PublicKeyPEM,
			&jwks.IsActive, &jwks.CreatedAt, &jwks.ExpiresAt, &jwks.RevokedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan JWKS record: %w", err)
		}
		keys = append(keys, jwks)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating JWKS records: %w", err)
	}

	return keys, nil
}

// DeactivateKey marks a key as inactive (for key rotation)
func (s *JWKSStore) DeactivateKey(ctx context.Context, kid string) error {
	query := `UPDATE tbl_jwks SET is_active = false WHERE kid = $1`

	commandTag, err := s.DB.Exec(ctx, query, kid)
	if err != nil {
		return fmt.Errorf("failed to deactivate key: %w", err)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrJWKSNotFound
	}

	return nil
}

// RevokeKey marks a key as revoked (for security incidents)
func (s *JWKSStore) RevokeKey(ctx context.Context, kid string) error {
	query := `UPDATE tbl_jwks SET revoked_at = NOW(), is_active = false WHERE kid = $1`

	commandTag, err := s.DB.Exec(ctx, query, kid)
	if err != nil {
		return fmt.Errorf("failed to revoke key: %w", err)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrJWKSNotFound
	}

	return nil
}

// ActivateKey marks a specific key as active
func (s *JWKSStore) ActivateKey(ctx context.Context, kid string) error {
	query := `UPDATE tbl_jwks SET is_active = true WHERE kid = $1`

	commandTag, err := s.DB.Exec(ctx, query, kid)
	if err != nil {
		return fmt.Errorf("failed to activate key: %w", err)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrJWKSNotFound
	}

	return nil
}

// DeactivateAllKeys deactivates all currently active keys
func (s *JWKSStore) DeactivateAllKeys(ctx context.Context) error {
	query := `UPDATE tbl_jwks SET is_active = false WHERE is_active = true`

	_, err := s.DB.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to deactivate all keys: %w", err)
	}

	return nil
}

// CleanupExpiredKeys removes keys that have been expired for a certain duration
func (s *JWKSStore) CleanupExpiredKeys(ctx context.Context, gracePeriod time.Duration) error {
	cutoff := time.Now().Add(-gracePeriod)

	query := `
		DELETE FROM tbl_jwks 
		WHERE expires_at IS NOT NULL 
		AND expires_at < $1`

	commandTag, err := s.DB.Exec(ctx, query, cutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired keys: %w", err)
	}

	// Log the number of cleaned up keys (you might want to use a logger here)
	_ = commandTag.RowsAffected()

	return nil
}
