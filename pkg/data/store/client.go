package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/freekieb7/go-lock/pkg/data/model"
)

var (
	ErrClientDuplicate = errors.New("client store: client already exists")
	ErrClientNotFound  = errors.New("client store: client not found")
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
	if _, err := store.db.ExecContext(ctx, "INSERT INTO tbl_client (id, secret, name, type, is_confidential, redirect_uris) values(?,?,?,?,?,?)",
		client.Id, client.Secret, client.Name, client.Type, client.IsConfidential, strings.Join(client.RedirectUris, " "),
	); err != nil {
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

func (store *ClientStore) GetManagerCredentials(ctx context.Context) (*model.Client, error) {
	row := store.db.QueryRowContext(ctx, `SELECT id, secret, name, type, is_confidential, redirect_uris FROM tbl_client WHERE type = ? LIMIT 1;`, model.ClientTypeManager)

	var client model.Client
	var redirectUris string
	var sType string
	if err := row.Scan(&client.Id, &client.Secret, &client.Name, &sType, &client.IsConfidential, &redirectUris); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}

	cType, err := model.ClientTypeFrom(sType)
	if err != nil {
		return nil, err
	}
	client.Type = cType
	client.RedirectUris = strings.Split(redirectUris, " ")
	return &client, nil
}

func (store *ClientStore) GetById(ctx context.Context, id string) (*model.Client, error) {
	row := store.db.QueryRowContext(ctx, "SELECT id, secret, name, type, is_confidential, redirect_uris FROM tbl_client WHERE id = ? LIMIT 1;", id)

	var client model.Client
	var redirectUris string
	var sType string
	if err := row.Scan(&client.Id, &client.Secret, &client.Name, &sType, &client.IsConfidential, &redirectUris); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}

	cType, err := model.ClientTypeFrom(sType)
	if err != nil {
		return nil, err
	}
	client.Type = cType
	client.RedirectUris = strings.Split(redirectUris, " ")
	return &client, nil
}
