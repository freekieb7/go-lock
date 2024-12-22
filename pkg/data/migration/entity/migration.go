package entity

import (
	"time"
)

type Migration struct {
	Id          string
	PerformedAt time.Time
	Success     bool
}
