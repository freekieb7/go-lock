package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/freekieb7/go-lock/pkg/data/local/model"
	"github.com/mattn/go-sqlite3"
)

var (
	ErrRedirectUriDuplicate = errors.New("redirect uri already exists")
)

func NewRedirectUriStore(db *sql.DB) *RedirectUriStore {
	return &RedirectUriStore{
		db,
	}
}

type RedirectUriStore struct {
	db *sql.DB
}

func (store *RedirectUriStore) Create(ctx context.Context, redirectUri model.RedirectUri) error {
	_, err := store.db.ExecContext(ctx, "INSERT INTO tbl_redirect_uri(client_id, uri) values(?,?)", redirectUri.ClientId, redirectUri.Uri)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) {
			if errors.Is(sqliteErr.ExtendedCode, sqlite3.ErrConstraintUnique) {
				return ErrRedirectUriDuplicate
			}
		}
		return err
	}

	return nil
}

func (store *RedirectUriStore) AllByClientId(ctx context.Context, clientId string) ([]model.RedirectUri, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT * FROM tbl_redirect_uri WHERE client_id = ?", clientId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []model.RedirectUri
	for rows.Next() {
		var redirectUri model.RedirectUri
		if err := rows.Scan(&redirectUri.ClientId, &redirectUri.Uri); err != nil {
			return nil, err
		}
		all = append(all, redirectUri)
	}
	return all, nil
}

func (store *RedirectUriStore) Exists(ctx context.Context, clientId, redirectUri string) (bool, error) {
	row := store.db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM tbl_redirect_uri WHERE client_id = ? AND redirect_uri = ? LIMIT 1);")
	if err := row.Scan(); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}
