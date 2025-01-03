package model

import "github.com/google/uuid"

type UserRole uint8

const (
	UserRoleAdmin UserRole = iota
	UserRoleNone
)

type User struct {
	Id           uuid.UUID
	Email        string
	PasswordHash []byte
	Role         UserRole
	CreatedAt    int64
	UpdatedAt    int64
}
