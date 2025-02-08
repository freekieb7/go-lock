package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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

func (store *ResourceServerStore) Create(ctx context.Context, resourceServer model.ResourceServer, scopes []model.Scope) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec("INSERT INTO tbl_resource_server (id, url, name, description, is_system, signing_algorithm, allow_skipping_user_consent, allow_offline_access, enabled_rbac, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
		resourceServer.Id,
		resourceServer.Url,
		resourceServer.Name,
		resourceServer.Description,
		resourceServer.IsSystem,
		resourceServer.SigningAlgorithm,
		resourceServer.AllowSkippingUserConsent,
		resourceServer.AllowOfflineAccess,
		resourceServer.EnabledRbac,
		resourceServer.CreatedAt,
		resourceServer.UpdatedAt,
	)
	if err != nil {
		return errors.Join(errors.New("resource server store: inserting resource server failed"), err)
	}

	if len(scopes) > 0 {
		query := "INSERT INTO tbl_scope (id, resource_server_id, value, description) VALUES "
		args := make([]any, 0, len(scopes)*4)

		for idx, scope := range scopes {
			if idx != 0 {
				query += ", "
			}

			query += "(?,?,?,?)"
			args = append(args, scope.Id, scope.ResourceServerId, scope.Value, scope.Description)
		}

		_, err = tx.Exec(query, args...)
		if err != nil {
			return errors.Join(fmt.Errorf("resource server store: query failed %s", query), err)
		}
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (store *ResourceServerStore) GetById(ctx context.Context, id uuid.UUID) (model.ResourceServer, error) {
	var resourceServer model.ResourceServer

	row := store.db.QueryRowContext(ctx, "SELECT id, url, name, description, is_system, signing_algorithm, allow_skipping_user_consent, allow_offline_access, enabled_rbac, created_at, updated_at FROM tbl_resource_server WHERE id = ? LIMIT 1;", id)

	if err := row.Scan(&resourceServer.Id, &resourceServer.Url, &resourceServer.Name, &resourceServer.Description, &resourceServer.IsSystem, &resourceServer.SigningAlgorithm, &resourceServer.AllowSkippingUserConsent, &resourceServer.AllowOfflineAccess, &resourceServer.EnabledRbac, &resourceServer.CreatedAt, &resourceServer.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return resourceServer, ErrResourceServerNotFound
		}
		return resourceServer, err
	}

	return resourceServer, nil
}

func (store *ResourceServerStore) GetByUrl(ctx context.Context, url string) (model.ResourceServer, error) {
	var resourceServer model.ResourceServer

	row := store.db.QueryRowContext(ctx, "SELECT id, url, name, description, is_system, signing_algorithm, allow_skipping_user_consent, allow_offline_access, enabled_rbac, created_at, updated_at FROM tbl_resource_server WHERE url = ? LIMIT 1;", url)

	if err := row.Scan(&resourceServer.Id, &resourceServer.Url, &resourceServer.Name, &resourceServer.Description, &resourceServer.IsSystem, &resourceServer.SigningAlgorithm, &resourceServer.AllowSkippingUserConsent, &resourceServer.AllowOfflineAccess, &resourceServer.EnabledRbac, &resourceServer.CreatedAt, &resourceServer.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return resourceServer, ErrResourceServerNotFound
		}
		return resourceServer, err
	}
	return resourceServer, nil
}

func (store *ResourceServerStore) Update(ctx context.Context, resourceServer model.ResourceServer, scopes []model.Scope) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "UPDATE tbl_resource_server SET name = ?, description = ?, url = ?, is_system = ?, allow_skipping_user_consent = ?, allow_offline_access = ?, signing_algorithm = ?, enabled_rbac = ?, updated_at = ? WHERE id = ?;",
		resourceServer.Name,
		resourceServer.Description,
		resourceServer.Url,
		resourceServer.IsSystem,
		resourceServer.AllowSkippingUserConsent,
		resourceServer.AllowOfflineAccess,
		resourceServer.SigningAlgorithm,
		resourceServer.EnabledRbac,
		resourceServer.UpdatedAt,
		resourceServer.Id,
	); err != nil {
		return err
	}

	// Delete all unwanted scopes
	query := "DELETE FROM tbl_scope WHERE resource_server_id = ? AND value NOT IN ("
	args := make([]any, 0, 1+len(scopes))
	args = append(args, resourceServer.Id)

	for idx, scope := range scopes {
		if idx != 0 {
			query += ","
		}
		query += "?"
		args = append(args, scope.Value)
	}
	query += ")"

	if _, err := tx.Exec(query, args...); err != nil {
		return err
	}

	// Add or update scope on conflict
	query = "INSERT INTO tbl_scope (id, resource_server_id, value, description) VALUES "
	args = make([]any, 0, len(scopes))
	for idx, scope := range scopes {
		if scope.ResourceServerId != resourceServer.Id {
			return fmt.Errorf("resource server store: inconsistent scope resource server id %s, expected %s", scope.ResourceServerId, resourceServer.Id)
		}

		if idx != 0 {
			query += ","
		}

		query += "(?,?,?,?)"
		args = append(args, scope.Id, scope.ResourceServerId, scope.Value, scope.Description)
	}
	query += " ON CONFLICT(resource_server_id, value) DO UPDATE SET description=excluded.description;"

	if _, err := tx.Exec(query, args...); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
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

func (store *ResourceServerStore) AllWithScopes(ctx context.Context) ([]model.ResourceServer, [][]model.Scope, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT id, url, name, description, is_system, signing_algorithm, allow_skipping_user_consent, allow_offline_access, enabled_rbac, created_at, updated_at FROM tbl_resource_server;")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	resourceServers := make([]model.ResourceServer, 0)
	resourceServerScopes := make([][]model.Scope, 0)

	for rows.Next() {
		var resourceServer model.ResourceServer
		if err := rows.Scan(&resourceServer.Id, &resourceServer.Url, &resourceServer.Name, &resourceServer.Description, &resourceServer.IsSystem, &resourceServer.SigningAlgorithm, &resourceServer.AllowSkippingUserConsent, &resourceServer.AllowOfflineAccess, &resourceServer.EnabledRbac, &resourceServer.CreatedAt, &resourceServer.UpdatedAt); err != nil {
			return nil, nil, err
		}
		resourceServers = append(resourceServers, resourceServer)

		scopes, err := store.AllScopes(ctx, resourceServer.Id)
		if err != nil {
			return nil, nil, err
		}
		resourceServerScopes = append(resourceServerScopes, scopes)

	}

	return resourceServers, resourceServerScopes, nil
}

func (store *ResourceServerStore) AllScopes(ctx context.Context, resourceServerId uuid.UUID) ([]model.Scope, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT id, value, description FROM tbl_scope WHERE resource_server_id = ?;", resourceServerId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scopes := make([]model.Scope, 0)
	for rows.Next() {
		var scope model.Scope
		scope.ResourceServerId = resourceServerId
		if err := rows.Scan(&scope.Id, &scope.Value, &scope.Description); err != nil {
			return nil, err
		}

		scopes = append(scopes, scope)
	}

	return scopes, nil
}

func (store *ResourceServerStore) AddScope(ctx context.Context, scope model.Scope) error {
	if _, err := store.db.ExecContext(ctx, "INSERT INTO tbl_scope (id, resource_server_id, value, description) VALUES (?,?,?,?);",
		scope.Id,
		scope.ResourceServerId,
		scope.Value,
		scope.Description,
	); err != nil {
		return err
	}

	return nil
}

func (store *ResourceServerStore) DeleteScopeById(ctx context.Context, id uuid.UUID) error {
	if _, err := store.db.ExecContext(ctx, "DELETE FROM tbl_scope WHERE id = ?;", id); err != nil {
		return err
	}

	return nil
}
