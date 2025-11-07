package database

import (
	"context"

	"github.com/freekieb7/go-lock/internal/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNoRows = pgx.ErrNoRows
)

type Database struct {
	*pgxpool.Pool
}

func NewDatabase() Database {
	return Database{}
}

func (db *Database) Connect(ctx context.Context, cfg config.Database) error {
	pool, err := pgxpool.New(ctx, cfg.URL)
	if err != nil {
		return err
	}

	// Configure the connection pool
	pool.Config().MaxConns = cfg.MaxOpenConns
	pool.Config().MinConns = cfg.MaxIdleConns
	pool.Config().MaxConnIdleTime = cfg.ConnMaxIdleTime
	pool.Config().MaxConnLifetime = cfg.ConnMaxLifetime

	// Ping the database to ensure connection is valid
	if err := pool.Ping(ctx); err != nil {
		return err
	}

	db.Pool = pool
	return nil
}

func (db *Database) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}
