package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/freekieb7/go-lock/internal/database"
	"github.com/freekieb7/go-lock/internal/oauth/domain"
	"github.com/freekieb7/go-lock/internal/util"
	"github.com/google/uuid"
)

var (
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
)

type RefreshTokenService struct {
	DB *database.Database
}

func NewRefreshTokenService(db *database.Database) *RefreshTokenService {
	return &RefreshTokenService{
		DB: db,
	}
}

func (s *RefreshTokenService) NewRefreshToken(clientID, userID uuid.UUID, scopes []string) (domain.RefreshToken, error) {
	token, err := util.GenerateRandomString(64)
	if err != nil {
		return domain.RefreshToken{}, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create new chain ID for the first token in a chain
	chainID := uuid.New()

	return domain.RefreshToken{
		ID:            uuid.New(),
		Token:         token,
		ClientID:      clientID,
		UserID:        userID,
		Scopes:        scopes,
		ChainID:       chainID,
		ParentTokenID: nil, // First token in chain has no parent
		IsRevoked:     false,
		ExpiresAt:     time.Now().Add(domain.RefreshTokenExpiresIn),
		CreatedAt:     time.Now(),
		UsedAt:        nil,
	}, nil
}

// NewRefreshTokenFromParent creates a new refresh token as part of an existing chain
func (s *RefreshTokenService) NewRefreshTokenFromParent(parentToken domain.RefreshToken, scopes []string) (domain.RefreshToken, error) {
	token, err := util.GenerateRandomString(64)
	if err != nil {
		return domain.RefreshToken{}, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return domain.RefreshToken{
		Token:         token,
		ClientID:      parentToken.ClientID,
		UserID:        parentToken.UserID,
		Scopes:        scopes,
		ChainID:       parentToken.ChainID, // Keep same chain ID
		ParentTokenID: &parentToken.ID,     // Link to parent token
		IsRevoked:     false,
		ExpiresAt:     time.Now().Add(domain.RefreshTokenExpiresIn),
		CreatedAt:     time.Now(),
		UsedAt:        nil,
	}, nil
}

func (s *RefreshTokenService) CreateRefreshToken(ctx context.Context, refreshToken domain.RefreshToken) (domain.RefreshToken, error) {
	query := `
		INSERT INTO tbl_refresh_token (token, client_id, user_id, scopes, chain_id, parent_token_id, is_revoked, expires_at, created_at, used_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at
	`

	if err := s.DB.QueryRow(ctx, query,
		refreshToken.Token,
		refreshToken.ClientID,
		refreshToken.UserID,
		refreshToken.Scopes,
		refreshToken.ChainID,
		refreshToken.ParentTokenID,
		refreshToken.IsRevoked,
		refreshToken.ExpiresAt,
		refreshToken.CreatedAt,
		refreshToken.UsedAt,
	).Scan(&refreshToken.ID, &refreshToken.CreatedAt); err != nil {
		return domain.RefreshToken{}, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return refreshToken, nil
}

func (s *RefreshTokenService) GetRefreshTokenByToken(ctx context.Context, token string) (domain.RefreshToken, error) {
	var refreshToken domain.RefreshToken

	query := `
		SELECT id, token, client_id, user_id, scopes, chain_id, parent_token_id, is_revoked, expires_at, created_at, used_at
		FROM tbl_refresh_token 
		WHERE token = $1 AND expires_at > NOW() AND is_revoked = FALSE
	`

	err := s.DB.QueryRow(ctx, query, token).Scan(
		&refreshToken.ID,
		&refreshToken.Token,
		&refreshToken.ClientID,
		&refreshToken.UserID,
		&refreshToken.Scopes,
		&refreshToken.ChainID,
		&refreshToken.ParentTokenID,
		&refreshToken.IsRevoked,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
		&refreshToken.UsedAt,
	)

	if err != nil {
		if errors.Is(err, database.ErrNoRows) {
			return domain.RefreshToken{}, ErrRefreshTokenNotFound
		}
		return domain.RefreshToken{}, fmt.Errorf("failed to get refresh token: %w", err)
	}

	// Check if token is expired
	if time.Now().After(refreshToken.ExpiresAt) {
		return domain.RefreshToken{}, ErrRefreshTokenExpired
	}

	return refreshToken, nil
}

// MarkRefreshTokenAsUsed marks a refresh token as used and returns updated token
func (s *RefreshTokenService) MarkRefreshTokenAsUsed(ctx context.Context, token string) (domain.RefreshToken, error) {
	now := time.Now()

	query := `
		UPDATE tbl_refresh_token 
		SET is_revoked = TRUE, used_at = $2
		WHERE token = $1
		RETURNING id, token, client_id, user_id, scopes, chain_id, parent_token_id, is_revoked, expires_at, created_at, used_at
	`

	var refreshToken domain.RefreshToken
	err := s.DB.QueryRow(ctx, query, token, now).Scan(
		&refreshToken.ID,
		&refreshToken.Token,
		&refreshToken.ClientID,
		&refreshToken.UserID,
		&refreshToken.Scopes,
		&refreshToken.ChainID,
		&refreshToken.ParentTokenID,
		&refreshToken.IsRevoked,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
		&refreshToken.UsedAt,
	)

	if err != nil {
		if errors.Is(err, database.ErrNoRows) {
			return domain.RefreshToken{}, ErrRefreshTokenNotFound
		}
		return domain.RefreshToken{}, fmt.Errorf("failed to mark refresh token as used: %w", err)
	}

	return refreshToken, nil
}

// RevokeRefreshTokenChain revokes all tokens in a refresh token chain (security breach response)
func (s *RefreshTokenService) RevokeRefreshTokenChain(ctx context.Context, chainID uuid.UUID) error {
	query := `
		UPDATE tbl_refresh_token 
		SET is_revoked = TRUE, used_at = NOW()
		WHERE chain_id = $1 AND is_revoked = FALSE
	`

	if _, err := s.DB.Exec(ctx, query, chainID); err != nil {
		return fmt.Errorf("failed to revoke refresh token chain: %w", err)
	}

	return nil
}

// CheckRefreshTokenReplay checks if a refresh token has already been used (replay attack detection)
func (s *RefreshTokenService) CheckRefreshTokenReplay(ctx context.Context, token string) (bool, domain.RefreshToken, error) {
	var refreshToken domain.RefreshToken

	query := `
		SELECT id, token, client_id, user_id, scopes, chain_id, parent_token_id, is_revoked, expires_at, created_at, used_at
		FROM tbl_refresh_token 
		WHERE token = $1
	`

	err := s.DB.QueryRow(ctx, query, token).Scan(
		&refreshToken.ID,
		&refreshToken.Token,
		&refreshToken.ClientID,
		&refreshToken.UserID,
		&refreshToken.Scopes,
		&refreshToken.ChainID,
		&refreshToken.ParentTokenID,
		&refreshToken.IsRevoked,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
		&refreshToken.UsedAt,
	)

	if err != nil {
		if errors.Is(err, database.ErrNoRows) {
			return false, domain.RefreshToken{}, ErrRefreshTokenNotFound
		}
		return false, domain.RefreshToken{}, fmt.Errorf("failed to check refresh token: %w", err)
	}

	// If token is already revoked/used, it's a replay attack
	isReplay := refreshToken.IsRevoked || refreshToken.UsedAt != nil

	return isReplay, refreshToken, nil
}

func (s *RefreshTokenService) DeleteRefreshToken(ctx context.Context, token string) error {
	query := `DELETE FROM tbl_refresh_token WHERE token = $1`

	if _, err := s.DB.Exec(ctx, query, token); err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

func (s *RefreshTokenService) RevokeRefreshToken(ctx context.Context, token string) error {
	query := `
		UPDATE tbl_refresh_token 
		SET is_revoked = TRUE, used_at = NOW()
		WHERE token = $1
	`

	if _, err := s.DB.Exec(ctx, query, token); err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}
