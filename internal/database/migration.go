package database

import (
	"time"
)

type Migration struct {
	Name      string
	UpSQL     string
	DownSQL   string
	AppliedAt time.Time
}
