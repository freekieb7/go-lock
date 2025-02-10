package model

import "github.com/google/uuid"

type UserType string

const (
	UserTypeAdmin UserType = "admin"
	UserTypeUser  UserType = "user"
)

type User struct {
	Id            uuid.UUID
	Name          string
	Username      string
	Email         string
	PasswordHash  []byte
	Type          UserType
	Picture       string
	EmailVerified bool
	Blocked       bool
	CreatedAt     int64
	UpdatedAt     int64
}
