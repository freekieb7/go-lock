package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/freekieb7/go-lock/pkg/data/model"
)

var (
	ErrResourceServerDuplicate    = errors.New("resource server store: resource server already exists")
	ErrResourceServerNotFound     = errors.New("resource server store: resource server does not found")
	ErrResourceServerDeleteFailed = errors.New("resource server store: resource server delete failed")
)

func NewResourceServerStore(db *sql.DB) *ResourceServerStore {
	return &ResourceServerStore{
		db,
	}
}

type ResourceServerStore struct {
	db *sql.DB
}

func (store *ResourceServerStore) Create(ctx context.Context, resourceServer model.ResourceServer) error {
	_, err := store.db.ExecContext(ctx, "INSERT INTO tbl_resource_server (id, name, uri, signing_algorithm, scopes) values(?,?,?,?,?)",
		resourceServer.Id,
		resourceServer.Name,
		resourceServer.Uri,
		resourceServer.SigningAlgorithm,
		strings.Join(resourceServer.Scopes, " "),
	)
	if err != nil {
		// var sqliteErr sqlite3.Error
		// if errors.As(err, &sqliteErr) {
		// 	if errors.Is(sqliteErr.ExtendedCode, sqlite3.ErrConstraintUnique) {
		// 		return ErrApiDuplicate
		// 	}
		// }
		return err
	}

	return nil

}

func (store *ResourceServerStore) GetByUri(ctx context.Context, uri string) (*model.ResourceServer, error) {
	row := store.db.QueryRowContext(ctx, "SELECT id, uri, name, signing_algorithm, scopes FROM tbl_resource_server WHERE uri = ? LIMIT 1;", uri)

	var resourceServer model.ResourceServer
	var scopes string
	if err := row.Scan(&resourceServer.Id, &resourceServer.Name, &resourceServer.Uri, &resourceServer.SigningAlgorithm, &scopes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrResourceServerNotFound
		}
		return nil, err
	}
	resourceServer.Scopes = strings.Split(scopes, " ")
	return &resourceServer, nil
}
