package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/freekieb7/go-lock/pkg/data/local/model"
	"github.com/mattn/go-sqlite3"
)

var (
	ErrApiDuplicate    = errors.New("api already exists")
	ErrApiNotExists    = errors.New("api does not exists")
	ErrApiDeleteFailed = errors.New("api delete failed")
)

func NewApiStore(db *sql.DB) *ApiStore {
	return &ApiStore{
		db,
	}
}

type ApiStore struct {
	db *sql.DB
}

func (store *ApiStore) Create(ctx context.Context, api model.Api) error {
	_, err := store.db.ExecContext(ctx, "INSERT INTO tbl_api(id, name, uri, signing_algorithm) values(?,?,?,?)", api.Id, api.Name, api.Uri, api.SigningAlgorithm)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) {
			if errors.Is(sqliteErr.ExtendedCode, sqlite3.ErrConstraintUnique) {
				return ErrApiDuplicate
			}
		}
		return err
	}

	return nil

}

func (store *ApiStore) GetByUri(ctx context.Context, uri string) (*model.Api, error) {
	row := store.db.QueryRowContext(ctx, "SELECT * FROM tbl_api WHERE uri = ? LIMIT 1;", uri)

	var api model.Api
	if err := row.Scan(&api.Id, &api.Name, &api.Uri, &api.SigningAlgorithm); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrApiNotExists
		}
		return nil, err
	}
	return &api, nil
}
