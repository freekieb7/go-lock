package database

import (
	"database/sql"
	"errors"

	"github.com/mattn/go-sqlite3"
)

var (
	ErrDuplicate    = errors.New("record already exists")
	ErrNotExists    = errors.New("row not exists")
	ErrUpdateFailed = errors.New("update failed")
	ErrDeleteFailed = errors.New("delete failed")
)

type Manager struct {
	DB *sql.DB
}

const (
	driverName = "gk_sqlite3"
)

func init() {
	sql.Register(driverName, &sqlite3.SQLiteDriver{
		ConnectHook: func(conn *sqlite3.SQLiteConn) error {
			_, err := conn.Exec(`
				PRAGMA busy_timeout       = 5000;
				PRAGMA journal_mode       = WAL;
				PRAGMA journal_size_limit = 200000000;
				PRAGMA synchronous        = NORMAL;
				PRAGMA foreign_keys       = ON;
				PRAGMA temp_store         = MEMORY;
				PRAGMA cache_size         = -16000;
			`, nil)

			return err
		},
	})
}

func New(dbPath string) (*sql.DB, error) {
	db, err := sql.Open(driverName, dbPath)
	if err != nil {
		return nil, errors.Join(errors.New("opening database failed"))
	}

	if err := db.Ping(); err != nil {
		return nil, errors.Join(errors.New("ping db failed"), err)
	}

	return db, nil
}

// func migrate(db *sql.DB) error {
// 	content, err := os.ReadFile(initFile)

// 	if err != nil {
// 		return err
// 	}

// 	_, err = db.Exec(string(content))

// 	return err
// }
