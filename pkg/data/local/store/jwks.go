package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/freekieb7/go-lock/pkg/data/local/model"
	"github.com/mattn/go-sqlite3"
)

var (
	ErrJwtsDuplicate = errors.New("jwt set already exists")
)

func NewJwksStore(db *sql.DB) *JwksStore {
	return &JwksStore{
		db,
	}
}

type JwksStore struct {
	db *sql.DB
}

func (store *JwksStore) Create(ctx context.Context, jwts model.Jwks) error {
	if _, err := store.db.ExecContext(
		ctx,
		"INSERT INTO tbl_jwks(id, public_key, private_key, public_key_modules, public_key_exponent) values(?,?,?,?,?)",
		jwts.Id, jwts.PublicKey, jwts.PrivateKey, jwts.PublicKeyModules, jwts.PublicKeyExponent,
	); err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) {
			if errors.Is(sqliteErr.ExtendedCode, sqlite3.ErrConstraintUnique) {
				return ErrJwtsDuplicate
			}
		}
		return err
	}

	return nil
}

func (store *JwksStore) All(ctx context.Context) ([]model.Jwks, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT * FROM tbl_jwks")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []model.Jwks
	for rows.Next() {
		var jwks model.Jwks
		if err := rows.Scan(&jwks.Id, &jwks.PublicKey, &jwks.PrivateKey, &jwks.PublicKeyModules, &jwks.PublicKeyExponent); err != nil {
			return nil, err
		}
		all = append(all, jwks)
	}
	return all, nil
}