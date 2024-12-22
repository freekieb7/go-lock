package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/freekieb7/go-lock/pkg/data/model"
)

var (
	ErrClientDuplicate = errors.New("client already exists")
	ErrClientNotExists = errors.New("client does not exists")
)

func NewClientStore(db *sql.DB) *ClientStore {
	return &ClientStore{
		db,
	}
}

type ClientStore struct {
	db *sql.DB
}

func (store *ClientStore) Create(ctx context.Context, client model.Client) error {
	_, err := store.db.ExecContext(ctx, "INSERT INTO tbl_client (id, secret, name, is_confidential, redirect_uris) values(?,?,?,?,?)", client.Id, client.Secret, client.Name, client.Confidential, strings.Join(client.RedirectUris, " "))
	if err != nil {
		// var sqliteErr sqlite3.Error
		// if errors.As(err, &sqliteErr) {
		// 	if errors.Is(sqliteErr.ExtendedCode, sqlite3.ErrConstraintUnique) {
		// 		return ErrClientDuplicate
		// 	}
		// }
		return err
	}

	return nil
}

func (store *ClientStore) GetById(ctx context.Context, identifier string) (*model.Client, error) {
	row := store.db.QueryRowContext(ctx, "SELECT id, secret, name, is_confidential, redirect_uris FROM tbl_client WHERE id = ? LIMIT 1;", identifier)

	var client model.Client
	var redirectUris string
	if err := row.Scan(&client.Id, &client.Secret, &client.Name, &client.Confidential, &redirectUris); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotExists
		}
		return nil, err
	}

	client.RedirectUris = strings.Split(redirectUris, " ")
	return &client, nil
}
