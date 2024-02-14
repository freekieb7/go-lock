package model

import "github.com/google/uuid"

type ClientCallback struct {
	ID       uuid.UUID
	ClientID uuid.UUID
	Uri      string
}
