package model

import "github.com/google/uuid"

type User struct {
	Id           uuid.UUID
	Name         string
	Username     string
	Email        string
	PasswordHash []byte
	CreatedAt    int64
	UpdatedAt    int64
	DeletedAt    int64
}
