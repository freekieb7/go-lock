package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/google/uuid"
)

var (
	ErrUserNotFound     = errors.New("user store: user not found")
	ErrUserAleadyExists = errors.New("user store: user already exist")
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
	_, err := store.db.ExecContext(ctx, "INSERT INTO tbl_user (id, email, password_hash, role, created_at, updated_at) values(?,?,?,?,?,?);",
		user.Id,
		user.Email,
		user.PasswordHash,
		user.Role,
		user.CreatedAt,
		user.UpdatedAt,
	)
	return err
}

func (store *UserStore) GetById(ctx context.Context, userId uuid.UUID) (*model.User, error) {
	row := store.db.QueryRowContext(ctx, "SELECT id, email, password_hash, created_at, updated_at FROM tbl_user WHERE id = ? LIMIT 1;", userId)

	var user model.User
	if err := row.Scan(&user.Id, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (store *UserStore) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	row := store.db.QueryRowContext(ctx, "SELECT id, email, password_hash, created_at, updated_at FROM tbl_user WHERE email = ? LIMIT 1;", email)

	var user model.User
	if err := row.Scan(&user.Id, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (store *UserStore) Update(ctx context.Context, user *model.User) error {
	_, err := store.db.ExecContext(ctx, "UPDATE tbl_user SET email = ?, password_hash = ?, created_at = ?, updated_at = ? WHERE id = ? LIMIT 1;",
		user.Email,
		user.PasswordHash,
		user.CreatedAt,
		user.UpdatedAt,
		user.Id,
	)
	return err
}

func (store *UserStore) AllByRole(ctx context.Context, role model.UserRole) ([]model.User, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT id, email, password_hash, role, created_at, updated_at FROM tbl_user WHERE role = ?", role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []model.User
	for rows.Next() {
		var users model.User
		if err := rows.Scan(&users.Id, &users.Email, &users.PasswordHash, &users.Role, &users.CreatedAt, &users.UpdatedAt); err != nil {
			return nil, err
		}
		all = append(all, users)
	}

	return all, nil
}
