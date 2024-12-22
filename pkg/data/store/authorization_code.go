package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/freekieb7/go-lock/pkg/data/model"
)

var (
	ErrAuthorizationCodeDuplicate    = errors.New("authorization code already exists")
	ErrAuthorizationCodeNotExists    = errors.New("authorization code does not exists")
	ErrAuthorizationCodeDeleteFailed = errors.New("authorization code delete failed")
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
		"INSERT INTO tbl_authorization_code (client_id, code, audience, scope, code_challenge) VALUES (?,?,?,?,?)",
		authorizationCode.ClientId, authorizationCode.Code, authorizationCode.Audience, authorizationCode.Scope, authorizationCode.CodeChallenge,
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

func (store *AuthorizationCodeStore) Get(ctx context.Context, clientId, code string) (*model.AuthorizationCode, error) {
	row := store.db.QueryRowContext(ctx, "SELECT * FROM tbl_authorization_code WHERE client_id = ? AND code = ? LIMIT 1;", clientId, code)

	var authorizationCode model.AuthorizationCode
	if err := row.Scan(&authorizationCode.ClientId, &authorizationCode.Code, &authorizationCode.Audience, &authorizationCode.Scope, &authorizationCode.CodeChallenge); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAuthorizationCodeNotExists
		}
		return nil, err
	}
	return &authorizationCode, nil
}
