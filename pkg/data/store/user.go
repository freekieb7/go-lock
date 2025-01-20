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
	_, err := store.db.ExecContext(ctx, "INSERT INTO tbl_user (id, name, username, email, password_hash, type, created_at, updated_at, deleted_at) values(?,?,?,?,?,?,?,?,?);",
		user.Id, user.Name, user.Username, user.Email, user.PasswordHash, user.Type, user.CreatedAt, user.UpdatedAt, user.DeletedAt,
	)
	return err
}

func (store *UserStore) GetById(ctx context.Context, id uuid.UUID) (model.User, error) {
	row := store.db.QueryRowContext(ctx, "SELECT id, name, username, email, password_hash, type, created_at, updated_at, deleted_at FROM tbl_user WHERE id = ? LIMIT 1;", id)

	var user model.User
	if err := row.Scan(&user.Id, &user.Name, &user.Username, &user.Email, &user.PasswordHash, &user.Type, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, ErrUserNotFound
		}
		return user, err
	}
	return user, nil
}

func (store *UserStore) GetByUsername(ctx context.Context, username string) (model.User, error) {
	var user model.User

	row := store.db.QueryRowContext(ctx, "SELECT id, name, username, email, password_hash, type, created_at, updated_at, deleted_at FROM tbl_user WHERE username = ? LIMIT 1;", username)

	if err := row.Scan(&user.Id, &user.Name, &user.Username, &user.Email, &user.PasswordHash, &user.Type, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, ErrUserNotFound
		}
		return user, err
	}
	return user, nil
}

func (store *UserStore) GetByEmail(ctx context.Context, email string) (model.User, error) {
	var user model.User

	row := store.db.QueryRowContext(ctx, "SELECT id, name, email, password_hash, type, created_at, updated_at, deleted_at FROM tbl_user WHERE email = ? LIMIT 1;", email)

	if err := row.Scan(&user.Id, &user.Name, &user.Username, &user.Email, &user.PasswordHash, &user.Type, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, ErrUserNotFound
		}
		return user, err
	}
	return user, nil
}

func (store *UserStore) Update(ctx context.Context, user *model.User) error {
	_, err := store.db.ExecContext(ctx, "UPDATE tbl_user SET name = ?, username = ?, email = ?, password_hash = ?, type = ?, created_at = ?, updated_at = ?, deleted_at = ? WHERE id = ? LIMIT 1;",
		user.Name, user.Username, user.Email, user.PasswordHash, user.Type, user.CreatedAt, user.UpdatedAt, user.DeletedAt, user.Id,
	)
	return err
}

func (store *UserStore) All(ctx context.Context, limit, offset uint) ([]model.User, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT id, name, username, email, password_hash, type, created_at, updated_at, deleted_at FROM tbl_user LIMIT ? OFFSET ?;", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []model.User
	for rows.Next() {
		var user model.User
		if err := rows.Scan(&user.Id, &user.Name, &user.Username, &user.Email, &user.PasswordHash, &user.Type, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt); err != nil {
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
