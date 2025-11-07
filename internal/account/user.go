package account

import (
	"time"

	"github.com/google/uuid"
)

type UserType string

const (
	UserTypeUser  UserType = "user"
	UserTypeAdmin UserType = "admin"
)

type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	Type         UserType
	CreatedAt    time.Time
}
