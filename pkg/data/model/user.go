package model

import "github.com/google/uuid"

type UserType string

const (
	UserTypeSystem  UserType = "system"
	UserTypeDefault UserType = "default"
)

type User struct {
	Id           uuid.UUID
	Name         string
	Username     string
	Email        string
	PasswordHash []byte
	Type         UserType
	CreatedAt    int64
	UpdatedAt    int64
	DeletedAt    int64
}
