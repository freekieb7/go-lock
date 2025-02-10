package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/google/uuid"
	"modernc.org/sqlite"
)

var (
	ErrUserNotFound                  = errors.New("user store: user not found")
	ErrUserWithEmailAlreadyExists    = errors.New("user store: email already exist")
	ErrUserWithUsernameAlreadyExists = errors.New("user store: username already exists")
)

type UserStore struct {
	db *sql.DB
}

func NewUserStore(db *sql.DB) *UserStore {
	return &UserStore{
		db,
	}
}

func (store *UserStore) Create(ctx context.Context, user model.User) error {
	_, err := store.db.ExecContext(ctx, "INSERT INTO tbl_user (id, name, username, email, password_hash, type, picture, email_verified, blocked, created_at, updated_at) values(?,?,?,?,?,?,?,?,?,?,?);",
		user.Id, user.Name, user.Username, user.Email, user.PasswordHash, user.Type, user.Picture, user.EmailVerified, user.Blocked, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		if err, ok := err.(*sqlite.Error); ok {
			if err.Code() == 2067 {
				if strings.Contains(err.Error(), "username") {
					return ErrUserWithUsernameAlreadyExists
				}

				if strings.Contains(err.Error(), "email") {
					return ErrUserWithEmailAlreadyExists
				}
			}
		}

		return err
	}

	return nil
}

func (store *UserStore) GetById(ctx context.Context, id uuid.UUID) (model.User, error) {
	row := store.db.QueryRowContext(ctx, "SELECT id, name, username, email, password_hash, type, picture, email_verified, blocked, created_at, updated_at FROM tbl_user WHERE id = ? LIMIT 1;", id)

	var user model.User
	if err := row.Scan(&user.Id, &user.Name, &user.Username, &user.Email, &user.PasswordHash, &user.Type, &user.Picture, &user.EmailVerified, &user.Blocked, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, ErrUserNotFound
		}
		return user, err
	}
	return user, nil
}

func (store *UserStore) GetByUsername(ctx context.Context, username string) (model.User, error) {
	var user model.User

	row := store.db.QueryRowContext(ctx, "SELECT id, name, username, email, password_hash, type, picture, email_verified, blocked, created_at, updated_at FROM tbl_user WHERE username = ? LIMIT 1;", username)

	if err := row.Scan(&user.Id, &user.Name, &user.Username, &user.Email, &user.PasswordHash, &user.Type, &user.Picture, &user.EmailVerified, &user.Blocked, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, ErrUserNotFound
		}
		return user, err
	}
	return user, nil
}

func (store *UserStore) GetByEmail(ctx context.Context, email string) (model.User, error) {
	var user model.User

	row := store.db.QueryRowContext(ctx, "SELECT id, name, email, password_hash, type, created_at, updated_at, is_blocked FROM tbl_user WHERE email = ? LIMIT 1;", email)

	if err := row.Scan(&user.Id, &user.Name, &user.Username, &user.Email, &user.PasswordHash, &user.Type, &user.Picture, &user.EmailVerified, &user.Blocked, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, ErrUserNotFound
		}
		return user, err
	}
	return user, nil
}

func (store *UserStore) Update(ctx context.Context, user model.User) error {
	_, err := store.db.ExecContext(ctx, "UPDATE tbl_user SET name = ?, username = ?, email = ?, password_hash = ?, type = ?, picture = ?, email_verified = ?, is_blocked = ?, created_at = ?, updated_at = ? WHERE id = ?;",
		user.Name, user.Username, user.Email, user.PasswordHash, user.Type, user.Picture, user.EmailVerified, user.Blocked, user.CreatedAt, user.UpdatedAt, user.Id,
	)
	return err
}

type AllUsersOptions struct {
	Limit  uint32
	Offset uint32
}

func (store *UserStore) All(ctx context.Context, options AllUsersOptions) ([]model.User, error) {
	query := "SELECT id, name, username, email, password_hash, type, picture, email_verified, blocked created_at, updated_at FROM tbl_user"

	if options.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", options.Limit)
	}

	if options.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", options.Offset)
	}

	rows, err := store.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []model.User
	for rows.Next() {
		var user model.User
		if err := rows.Scan(&user.Id, &user.Name, &user.Username, &user.Email, &user.PasswordHash, &user.Type, &user.Picture, &user.EmailVerified, &user.Blocked, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

func (store *UserStore) DeleteById(ctx context.Context, id uuid.UUID) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM tbl_user WHERE id = ?;`, id)
	if err != nil {
		return err
	}

	return nil
}

func (store *UserStore) AllPermissions(ctx context.Context, userId uuid.UUID) ([]model.Permission, error) {
	permissions := make([]model.Permission, 0)

	rows, err := store.db.QueryContext(ctx, `
		SELECT permission.id, permission.resource_server_id, permission.value, permission.description
		FROM tbl_role_per_user role_per_user
		LEFT JOIN tbl_permission_per_role permission_per_role ON role_per_user.role_id = permission_per_role.role_id
		LEFT JOIN tbl_permission permission ON permission.id = permission_per_role.permission_id
		WHERE role_per_user.user_id = ?
		UNION
		SELECT permission.id, permission.resource_server_id, permission.value, permission.description
		FROM tbl_permission_per_user permission_per_user
		LEFT JOIN tbl_permission permission ON permission.id = permission_per_user.permission_id
		WHERE permission_per_user.user_id = ?
	`, userId, userId)
	if err != nil {
		return permissions, err
	}
	defer rows.Close()

	for rows.Next() {
		var permission model.Permission
		if err := rows.Scan(&permission.Id, &permission.ResourceServerId, &permission.Value, &permission.Description); err != nil {
			return permissions, err
		}

		permissions = append(permissions, permission)
	}
	return permissions, nil
}

func (store *UserStore) AssignPermission(ctx context.Context, userId uuid.UUID, permissionId uuid.UUID) error {
	_, err := store.db.ExecContext(ctx, `INSERT INTO tbl_permission_per_user (user_id, permission_id) VALUES (?,?);`, userId, permissionId)
	if err != nil {
		return err
	}

	return nil
}

func (store *UserStore) RevokePermission(ctx context.Context, userId uuid.UUID, permissionId uuid.UUID) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM tbl_permission_per_user WHERE user_id = ? AND permission_id = ?;`, userId, permissionId)
	if err != nil {
		return err
	}

	return nil
}
