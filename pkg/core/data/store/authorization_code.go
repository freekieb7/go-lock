package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/freekieb7/go-lock/pkg/core/data/model"
)

var (
	ErrAuthorizationCodeDuplicate    = errors.New("authorization code store: authorization code already exists")
	ErrAuthorizationCodeNotFound     = errors.New("authorization code store: authorization code not found")
	ErrAuthorizationCodeDeleteFailed = errors.New("authorization code store: authorization code delete failed")
)

func NewAuthorizationCodeStore(db *sql.DB) *AuthorizationCodeStore {
	return &AuthorizationCodeStore{
		db,
	}
}

type AuthorizationCodeStore struct {
	db *sql.DB
}

func (store *AuthorizationCodeStore) Create(ctx context.Context, authorizationCode model.AuthorizationCode) error {
	_, err := store.db.ExecContext(
		ctx,
		"INSERT INTO tbl_authorization_code (client_id, user_id, code, audience, scope, code_challenge) VALUES (?,?,?,?,?,?)",
		authorizationCode.ClientId, authorizationCode.UserId, authorizationCode.Code, authorizationCode.Audience, authorizationCode.Scope, authorizationCode.CodeChallenge,
	)
	if err != nil {
		// var sqliteErr sqlite3.Error
		// if errors.As(err, &sqliteErr) {
		// 	if errors.Is(sqliteErr.ExtendedCode, sqlite3.ErrConstraintUnique) {
		// 		return ErrAuthorizationCodeDuplicate
		// 	}
		// }
		return err
	}

	return nil
}

func (store *AuthorizationCodeStore) GetByCode(ctx context.Context, code, clientId string) (*model.AuthorizationCode, error) {
	row := store.db.QueryRowContext(ctx, "SELECT client_id, user_id, code, audience, scope, code_challenge FROM tbl_authorization_code WHERE client_id = ? AND code = ? LIMIT 1;", clientId, code)

	var authorizationCode model.AuthorizationCode
	if err := row.Scan(&authorizationCode.ClientId, &authorizationCode.UserId, &authorizationCode.Code, &authorizationCode.Audience, &authorizationCode.Scope, &authorizationCode.CodeChallenge); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAuthorizationCodeNotFound
		}
		return nil, err
	}
	return &authorizationCode, nil
}
