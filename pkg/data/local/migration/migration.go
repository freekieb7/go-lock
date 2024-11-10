package migration

import "time"

type Migration interface {
	Identifier() string
	Up() (string, []any)
	Down() (string, []any)
}

type MigrationEntity struct {
	Id          string
	PerformedAt time.Time
	Success     bool
}
