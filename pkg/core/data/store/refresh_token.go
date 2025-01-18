package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/freekieb7/go-lock/pkg/core/data/model"
	"github.com/google/uuid"
)

var (
	ErrRefreshTokenDuplicate    = errors.New("refresh token store: refresh token already exists")
	ErrRefreshTokenNotFound     = errors.New("refresh token store: refresh token does not found")
	ErrRefreshTokenDeleteFailed = errors.New("refresh token store: refresh token delete failed")
)

func NewRefreshTokenStore(db *sql.DB) *RefreshTokenStore {
	return &RefreshTokenStore{
		db,
	}
}

type RefreshTokenStore struct {
	db *sql.DB
}

func (store *RefreshTokenStore) Create(ctx context.Context, refreshToken model.RefreshToken) error {
	_, err := store.db.ExecContext(ctx, "INSERT INTO tbl_refresh_token (id, client_id, user_id, audience, scope, expires_at, created_at) values(?,?,?,?,?,?,?)",
		refreshToken.Id,
		refreshToken.ClientId,
		refreshToken.UserId,
		refreshToken.Audience,
		refreshToken.Scope,
		refreshToken.ExpiresAt,
		refreshToken.CreatedAt,
	)
	if err != nil {
		// var sqliteErr sqlite3.Error
		// if errors.As(err, &sqliteErr) {
		// 	if errors.Is(sqliteErr.ExtendedCode, sqlite3.ErrConstraintUnique) {
		// 		return ErrApiDuplicate
		// 	}
		// }
		return err
	}

	return nil

}

func (store *RefreshTokenStore) GetById(ctx context.Context, id, clientId uuid.UUID) (*model.RefreshToken, error) {
	row := store.db.QueryRowContext(ctx, "SELECT id, client_id, user_id, audience, scope, expires_at, created_at FROM tbl_refresh_token WHERE id = ? AND client_id = ? LIMIT 1;", id, clientId)

	var refreshToken model.RefreshToken
	if err := row.Scan(&refreshToken.Id, &refreshToken.ClientId, &refreshToken.UserId, &refreshToken.Audience, &refreshToken.Scope, &refreshToken.ExpiresAt, &refreshToken.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrResourceServerNotFound
		}
		return nil, err
	}
	return &refreshToken, nil
}

func (store *RefreshTokenStore) DeleteById(ctx context.Context, id, clientId uuid.UUID) error {
	_, err := store.db.ExecContext(ctx, "DELETE FROM tbl_refresh_token WHERE id = ? AND client_id = ? LIMIT 1;", id, clientId)
	if err != nil {
		return err
	}

	return nil
}
