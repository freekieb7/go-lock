package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/google/uuid"
)

var (
	ErrResourceServerDuplicate    = errors.New("resource server store: resource server already exists")
	ErrResourceServerNotFound     = errors.New("resource server store: resource server does not found")
	ErrResourceServerDeleteFailed = errors.New("resource server store: resource server delete failed")
)

func NewResourceServerStore(db *sql.DB) *ResourceServerStore {
	return &ResourceServerStore{
		db,
	}
}

type ResourceServerStore struct {
	db *sql.DB
}

func (store *ResourceServerStore) Create(ctx context.Context, resourceServer model.ResourceServer) error {
	_, err := store.db.ExecContext(ctx, "INSERT INTO tbl_resource_server (id, url, name, signing_algorithm, scopes, allow_skipping_user_consent, type, created_at, updated_at, deleted_at) values(?,?,?,?,?,?,?,?,?)",
		resourceServer.Id,
		resourceServer.Url,
		resourceServer.Name,
		resourceServer.SigningAlgorithm,
		resourceServer.Scopes,
		resourceServer.AllowSkippingUserConsent,
		resourceServer.Type,
		resourceServer.CreatedAt,
		resourceServer.UpdatedAt,
		resourceServer.DeletedAt,
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

func (store *ResourceServerStore) GetById(ctx context.Context, id uuid.UUID) (model.ResourceServer, error) {
	var resourceServer model.ResourceServer

	row := store.db.QueryRowContext(ctx, "SELECT id, url, name, type, signing_algorithm, scopes, allow_skipping_user_consent, created_at, updated_at, deleted_at FROM tbl_resource_server WHERE id = ? LIMIT 1;", id)

	if err := row.Scan(&resourceServer.Id, &resourceServer.Url, &resourceServer.Name, &resourceServer.Type, &resourceServer.SigningAlgorithm, &resourceServer.Scopes, &resourceServer.AllowSkippingUserConsent, &resourceServer.CreatedAt, &resourceServer.UpdatedAt, &resourceServer.DeletedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return resourceServer, ErrResourceServerNotFound
		}
		return resourceServer, err
	}
	return resourceServer, nil
}

func (store *ResourceServerStore) GetByUrl(ctx context.Context, url string) (model.ResourceServer, error) {
	var resourceServer model.ResourceServer

	row := store.db.QueryRowContext(ctx, "SELECT id, url, name, type, signing_algorithm, scopes, allow_skipping_user_consent, created_at, updated_at, deleted_at FROM tbl_resource_server WHERE url = ? LIMIT 1;", url)

	if err := row.Scan(&resourceServer.Id, &resourceServer.Url, &resourceServer.Name, &resourceServer.Type, &resourceServer.SigningAlgorithm, &resourceServer.Scopes, &resourceServer.AllowSkippingUserConsent, &resourceServer.CreatedAt, &resourceServer.UpdatedAt, &resourceServer.DeletedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return resourceServer, ErrResourceServerNotFound
		}
		return resourceServer, err
	}
	return resourceServer, nil
}

func (store *ResourceServerStore) DeleteById(ctx context.Context, id uuid.UUID) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM tbl_resource_server WHERE id = ? LIMIT 1;`, id)
	if err != nil {
		return err
	}

	return nil
}

func (store *ResourceServerStore) All(ctx context.Context, limit, offset uint32) ([]model.ResourceServer, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT id, url, name, type, signing_algorithm, scopes, allow_skipping_user_consent, created_at, updated_at, deleted_at FROM tbl_resource_server LIMIT ? OFFSET ?;", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resourceServers := make([]model.ResourceServer, 0, limit)
	for rows.Next() {
		var resourceServer model.ResourceServer
		if err := rows.Scan(&resourceServer.Id, &resourceServer.Url, &resourceServer.Name, &resourceServer.Type, &resourceServer.SigningAlgorithm, &resourceServer.Scopes, &resourceServer.AllowSkippingUserConsent, &resourceServer.CreatedAt, &resourceServer.UpdatedAt, &resourceServer.DeletedAt); err != nil {
			return nil, err
		}

		resourceServers = append(resourceServers, resourceServer)
	}
	return resourceServers, nil
}
