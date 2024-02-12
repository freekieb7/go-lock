package model

import "github.com/google/uuid"

type ClientRedirect struct {
	ID       uuid.UUID
	ClientID uuid.UUID
	Uri      string
}
