package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/freekieb7/go-lock/pkg/data/local/model"
	"github.com/mattn/go-sqlite3"
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
	_, err := store.db.ExecContext(ctx, "INSERT INTO tbl_client(id, secret, name, confidential) values(?,?,?,?)", client.Id, client.Secret, client.Name, client.Confidential)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) {
			if errors.Is(sqliteErr.ExtendedCode, sqlite3.ErrConstraintUnique) {
				return ErrClientDuplicate
			}
		}
		return err
	}

	return nil
}

func (store *ClientStore) GetById(ctx context.Context, identifier string) (*model.Client, error) {
	row := store.db.QueryRowContext(ctx, "SELECT * FROM tbl_client WHERE id = ? LIMIT 1;", identifier)

	var client model.Client
	if err := row.Scan(&client.Id, &client.Secret, &client.Name, &client.Confidential); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotExists
		}
		return nil, err
	}
	return &client, nil
}
