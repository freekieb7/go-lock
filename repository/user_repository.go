package repository

import (
	"database/sql"
	"fmt"
	"github.com/freekieb/go-lock/model"
	"github.com/google/uuid"
)

type UserRepository interface {
	GetUser(userId uuid.UUID) (model.User, error)
	GetUserByEmail(email string) (model.User, error)
	GetUserList() ([]model.User, error)
	CreateUser(user model.User) error
}

type userRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &userRepository{
		db: db,
	}
}

func (repository *userRepository) GetUser(userId uuid.UUID) (model.User, error) {
	var user model.User

	row := repository.db.QueryRow("SELECT id, email, password FROM tbl_user WHERE id = ?;", userId)

	if err := row.Scan(&user.ID, &user.Email, &user.Password); err != nil {
		return user, fmt.Errorf("GetUser %d: %v", userId, err)
	}

	return user, nil
}

func (repository *userRepository) GetUserByEmail(email string) (model.User, error) {
	var user model.User

	row := repository.db.QueryRow("SELECT id, email, password FROM tbl_user WHERE email = ?;", email)

	if err := row.Scan(&user.ID, &user.Email, &user.Password); err != nil {
		return user, fmt.Errorf("GetUserByEmail %d: %v", email, err)
	}

	return user, nil
}

func (repository *userRepository) GetUserList() ([]model.User, error) {
	var userList []model.User

	rows, err := repository.db.Query("SELECT id, email, password FROM tbl_user;")

	if err != nil {
		return nil, fmt.Errorf("GetUserList: %v", err)
	}

	defer rows.Close()

	for rows.Next() {
		var user model.User

		if err := rows.Scan(&user.ID, &user.Email, &user.Password); err != nil {
			return nil, fmt.Errorf("GetUserList: %v", err)
		}

		userList = append(userList, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserList: %v", err)
	}

	return userList, nil
}

func (repository *userRepository) CreateUser(user model.User) error {
	_, err := repository.db.Exec(
		"INSERT INTO tbl_user (id, email, password) VALUES (?,?,?);",
		user.ID, user.Email, user.Password,
	)

	return err
}
