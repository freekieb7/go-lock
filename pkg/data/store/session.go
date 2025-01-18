package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/freekieb7/go-lock/pkg/session"
)

var (
	ErrSessionNotFound = errors.New("session store: session not found")
)

func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{
		db,
	}
}

type SessionStore struct {
	db *sql.DB
}

func (store *SessionStore) Save(ctx context.Context, session session.Session) error {
	data, err := session.Serialize()
	if err != nil {
		return err
	}

	_, err = store.db.ExecContext(ctx, "INSERT INTO tbl_session (id, data) values(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data;",
		session.Id,
		data,
	)
	if err != nil {
		return err
	}

	return nil

}

func (store *SessionStore) GetById(ctx context.Context, id string) (*session.Session, error) {
	row := store.db.QueryRowContext(ctx, "SELECT id, data FROM tbl_session WHERE id = ? LIMIT 1;", id)

	var session session.Session
	var data []byte
	if err := row.Scan(&session.Id, &data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	if err := session.Deserialize(data); err != nil {
		return nil, err
	}

	return &session, nil
}
