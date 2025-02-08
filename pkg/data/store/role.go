package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/google/uuid"
)

var (
	ErrRoleNotFound = errors.New("role store: role not found")
)

type RoleStore struct {
	db *sql.DB
}

func NewRoleStore(db *sql.DB) *RoleStore {
	return &RoleStore{
		db,
	}
}

func (store *RoleStore) All(ctx context.Context) ([]model.Role, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT id, name, description FROM tbl_role;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]model.Role, 0)

	for rows.Next() {
		var role model.Role
		if err := rows.Scan(&role.Id, &role.Name, &role.Description); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func (store *RoleStore) Create(ctx context.Context, role model.Role) error {
	if _, err := store.db.ExecContext(ctx, "INSERT INTO tbl_role (id, name, description) VALUES (?,?,?);",
		role.Id, role.Name, role.Description,
	); err != nil {
		return err
	}

	return nil
}

func (store *RoleStore) GetById(ctx context.Context, id uuid.UUID) (model.Role, error) {
	var role model.Role

	row, err := store.db.QueryContext(ctx, "SELECT id, name, description FROM tbl_role WHERE id = ?;", id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return role, ErrRoleNotFound
		}
	}

	if err := row.Scan(&role.Id, &role.Name, &role.Description); err != nil {
		return role, err
	}

	return role, nil
}

func (store *RoleStore) Update(ctx context.Context, role model.Role) error {
	if _, err := store.db.ExecContext(ctx, "UPDATE tbl_role SET name = ?, description = ? WHERE id = ?;", role.Name, role.Description, role.Id); err != nil {
		return err
	}

	return nil
}

func (store *RoleStore) DeleteById(ctx context.Context, id uuid.UUID) error {
	if _, err := store.db.ExecContext(ctx, "DELETE FROM tbl_role WHERE id = ?;", id); err != nil {
		return err
	}

	return nil
}
