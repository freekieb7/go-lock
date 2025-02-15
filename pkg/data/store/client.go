package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/google/uuid"
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
	if _, err := store.db.ExecContext(ctx, "INSERT INTO tbl_client (id, secret, name, description, is_system, is_confidential, logo_url, redirect_urls, created_at, updated_at) values(?,?,?,?,?,?,?,?,?,?)",
		client.Id, client.Secret, client.Name, client.Description, client.IsSystem, client.IsConfidential, client.LogoUrl, client.RedirectUrls, client.CreatedAt, client.UpdatedAt,
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

func (store *ClientStore) Update(ctx context.Context, client model.Client) error {
	if _, err := store.db.ExecContext(ctx, "UPDATE tbl_client SET secret = ?, name = ?, is_system = ?, is_confidential = ?, redirect_urls = ?, updated_at = ? WHERE id = ?",
		client.Secret, client.Name, client.IsSystem, client.IsConfidential, client.RedirectUrls, client.UpdatedAt, client.Id,
	); err != nil {
		return err
	}

	return nil
}

func (store *ClientStore) All(ctx context.Context) ([]model.Client, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT id, secret, name, description, is_system, is_confidential, logo_url, redirect_urls, created_at, updated_at FROM tbl_client;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	clients := make([]model.Client, 0)
	for rows.Next() {
		var client model.Client
		if err := rows.Scan(&client.Id, &client.Secret, &client.Name, &client.Description, &client.IsSystem, &client.IsConfidential, &client.LogoUrl, &client.RedirectUrls, &client.CreatedAt, &client.UpdatedAt); err != nil {
			return nil, err
		}

		clients = append(clients, client)
	}
	return clients, nil
}

func (store *ClientStore) GetById(ctx context.Context, id uuid.UUID) (model.Client, error) {
	var client model.Client

	row := store.db.QueryRowContext(ctx, "SELECT id, secret, name, description, is_system, is_confidential, logo_url, redirect_urls, created_at, updated_at FROM tbl_client WHERE id = ? LIMIT 1;", id)

	if err := row.Scan(&client.Id, &client.Secret, &client.Name, &client.Description, &client.IsSystem, &client.IsConfidential, &client.LogoUrl, &client.RedirectUrls, &client.CreatedAt, &client.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return client, ErrClientNotFound
		}
		return client, err
	}

	return client, nil
}

func (store *ClientStore) DeleteById(ctx context.Context, id uuid.UUID) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM tbl_client WHERE id = ? AND is_system = false;`, id)
	if err != nil {
		return err
	}

	return nil
}
