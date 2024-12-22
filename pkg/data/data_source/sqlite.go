package database

import (
	"database/sql"

	"github.com/freekieb7/go-lock/pkg/settings"
	_ "modernc.org/sqlite"
)

type Manager struct {
	DB *sql.DB
}

func New(dbPath string, mode settings.Environment) (*sql.DB, error) {
	// Note: the busy_timeout pragma must be first because
	// the connection needs to be set to block on busy before WAL mode
	// is set in case it hasn't been already set by another connection.
	pragmas := "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=journal_size_limit(200000000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_pragma=temp_store(MEMORY)&_pragma=cache_size(-16000)"
	if mode == settings.Testing {
		pragmas += "&mode=memory"
	}

	db, err := sql.Open("sqlite", dbPath+pragmas)
	if err != nil {
		return nil, err
	}

	return db, nil
}
