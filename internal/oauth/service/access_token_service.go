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

type AccessTokenService struct {
	DB *database.Database
}

func NewAccessTokenService(db *database.Database) *AccessTokenService {
	return &AccessTokenService{
		DB: db,
	}
}

func (s *AccessTokenService) NewAccessToken(clientID, accountID uuid.UUID, scopes []string) (domain.AccessToken, error) {
	token, err := util.GenerateRandomString(48)
	if err != nil {
		return domain.AccessToken{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	return domain.AccessToken{
		Token:     token,
		ClientID:  clientID,
		AccountID: accountID,
		Scopes:    scopes,
		ExpiresAt: time.Time{}, // Set by SaveAccessToken
	}, nil
}

func (s *AccessTokenService) SaveAccessToken(ctx context.Context, accessToken domain.AccessToken, expiresIn uint32) (domain.AccessToken, error) {
	if !accessToken.ExpiresAt.IsZero() {
		return domain.AccessToken{}, errors.New("updating existing access tokens is not supported")
	}

	// Calculate expiry time
	accessToken.ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)

	query := `
		INSERT INTO tbl_access_token (token, client_id, account_id, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at
	`

	err := s.DB.QueryRow(ctx, query,
		accessToken.Token,
		accessToken.ClientID,
		accessToken.AccountID,
		accessToken.Scopes,
		accessToken.ExpiresAt,
	).Scan(&accessToken.ID, &accessToken.CreatedAt)

	if err != nil {
		return domain.AccessToken{}, fmt.Errorf("failed to save access token: %w", err)
	}

	return accessToken, nil
}
