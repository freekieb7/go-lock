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
	if _, err := store.db.Exec("INSERT INTO tbl_resource_server (id, url, name, description, is_system, signing_algorithm, allow_skipping_user_consent, allow_offline_access, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
		resourceServer.Id,
		resourceServer.Url,
		resourceServer.Name,
		resourceServer.Description,
		resourceServer.IsSystem,
		resourceServer.SigningAlgorithm,
		resourceServer.AllowSkippingUserConsent,
		resourceServer.AllowOfflineAccess,
		resourceServer.CreatedAt,
		resourceServer.UpdatedAt,
	); err != nil {
		return errors.Join(errors.New("resource server store: inserting resource server failed"), err)
	}

	return nil
}

func (store *ResourceServerStore) GetById(ctx context.Context, id uuid.UUID) (model.ResourceServer, error) {
	var resourceServer model.ResourceServer

	row := store.db.QueryRowContext(ctx, "SELECT id, url, name, description, is_system, signing_algorithm, allow_skipping_user_consent, allow_offline_access, created_at, updated_at FROM tbl_resource_server WHERE id = ? LIMIT 1;", id)

	if err := row.Scan(&resourceServer.Id, &resourceServer.Url, &resourceServer.Name, &resourceServer.Description, &resourceServer.IsSystem, &resourceServer.SigningAlgorithm, &resourceServer.AllowSkippingUserConsent, &resourceServer.AllowOfflineAccess, &resourceServer.CreatedAt, &resourceServer.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return resourceServer, ErrResourceServerNotFound
		}
		return resourceServer, err
	}

	return resourceServer, nil
}

func (store *ResourceServerStore) GetByUrl(ctx context.Context, url string) (model.ResourceServer, error) {
	var resourceServer model.ResourceServer

	row := store.db.QueryRowContext(ctx, "SELECT id, url, name, description, is_system, signing_algorithm, allow_skipping_user_consent, allow_offline_access, created_at, updated_at FROM tbl_resource_server WHERE url = ? LIMIT 1;", url)

	if err := row.Scan(&resourceServer.Id, &resourceServer.Url, &resourceServer.Name, &resourceServer.Description, &resourceServer.IsSystem, &resourceServer.SigningAlgorithm, &resourceServer.AllowSkippingUserConsent, &resourceServer.AllowOfflineAccess, &resourceServer.CreatedAt, &resourceServer.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return resourceServer, ErrResourceServerNotFound
		}
		return resourceServer, err
	}
	return resourceServer, nil
}

func (store *ResourceServerStore) Update(ctx context.Context, resourceServer model.ResourceServer) error {
	if _, err := store.db.ExecContext(ctx, "UPDATE tbl_resource_server SET name = ?, description = ?, url = ?, is_system = ?, allow_skipping_user_consent = ?, allow_offline_access = ?, signing_algorithm = ?, updated_at = ? WHERE id = ?;",
		resourceServer.Name,
		resourceServer.Description,
		resourceServer.Url,
		resourceServer.IsSystem,
		resourceServer.AllowSkippingUserConsent,
		resourceServer.AllowOfflineAccess,
		resourceServer.SigningAlgorithm,
		resourceServer.UpdatedAt,
		resourceServer.Id,
	); err != nil {
		return err
	}

	return nil
}

func (store *ResourceServerStore) DeleteById(ctx context.Context, id uuid.UUID) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM tbl_resource_server WHERE id = ? AND is_system = false;`, id)
	if err != nil {
		return err
	}

	return nil
}

func (store *ResourceServerStore) All(ctx context.Context) ([]model.ResourceServer, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT id, url, name, description, is_system, signing_algorithm, allow_skipping_user_consent, allow_offline_access, created_at, updated_at FROM tbl_resource_server;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resourceServers := make([]model.ResourceServer, 0)

	for rows.Next() {
		var resourceServer model.ResourceServer
		if err := rows.Scan(&resourceServer.Id, &resourceServer.Url, &resourceServer.Name, &resourceServer.Description, &resourceServer.IsSystem, &resourceServer.SigningAlgorithm, &resourceServer.AllowSkippingUserConsent, &resourceServer.AllowOfflineAccess, &resourceServer.CreatedAt, &resourceServer.UpdatedAt); err != nil {
			return nil, err
		}
		resourceServers = append(resourceServers, resourceServer)
	}

	return resourceServers, nil
}

func (store *ResourceServerStore) AllPermissions(ctx context.Context, resourceServerId uuid.UUID) ([]model.Permission, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT id, value, description FROM tbl_permission WHERE resource_server_id = ?;", resourceServerId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	permissions := make([]model.Permission, 0)
	for rows.Next() {
		var permission model.Permission
		permission.ResourceServerId = resourceServerId
		if err := rows.Scan(&permission.Id, &permission.Value, &permission.Description); err != nil {
			return nil, err
		}

		permissions = append(permissions, permission)
	}

	return permissions, nil
}

func (store *ResourceServerStore) CreatePermission(ctx context.Context, permission model.Permission) error {
	if _, err := store.db.ExecContext(ctx, "INSERT INTO tbl_permission (id, resource_server_id, value, description) VALUES (?,?,?,?);",
		permission.Id,
		permission.ResourceServerId,
		permission.Value,
		permission.Description,
	); err != nil {
		return err
	}

	return nil
}

func (store *ResourceServerStore) GetPermissionById(ctx context.Context, id uuid.UUID) (model.Permission, error) {
	var permission model.Permission
	permission.Id = id

	row := store.db.QueryRowContext(ctx, "SELECT value, description FROM tbl_permission WHERE id = ?;", id)

	if err := row.Scan(&permission.Value, &permission.Description); err != nil {
		return permission, err
	}

	return permission, nil
}

func (store *ResourceServerStore) UpdatePermission(ctx context.Context, permission model.Permission) error {
	if _, err := store.db.ExecContext(ctx, "UPDATE tbl_permission SET value = ? AND description = ? WHERE id = ?;",
		permission.Value, permission.Description, permission.Id,
	); err != nil {
		return err
	}

	return nil
}

func (store *ResourceServerStore) DeletePermissionById(ctx context.Context, resourceServerId, id uuid.UUID) error {
	if _, err := store.db.ExecContext(ctx, "DELETE FROM tbl_permission WHERE resource_server_id = ? AND id = ?;", resourceServerId, id); err != nil {
		return err
	}

	return nil
}
