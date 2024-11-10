package migrator

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/local/migration"
)

const (
	MigrationTableName = "tbl_migration"
)

type Migrator struct {
	Database *sql.DB
}

func New(db *sql.DB) *Migrator {
	return &Migrator{
		db,
	}
}

func (migrator *Migrator) Up(ctx context.Context, migrations []migration.Migration) error {
	// Check if there is anything to do
	if len(migrations) < 1 {
		return nil
	}

	currentIdentifier, err := migrator.currentVersion(ctx)
	if err != nil {
		return errors.Join(errors.New("getting current migration version failed"), err)
	}

	scheduledMigrations := make([]migration.Migration, 0)
	for _, migration := range migrations {
		if migration.Identifier() > currentIdentifier {
			scheduledMigrations = append(scheduledMigrations, migration)
		}
	}

	// Check if there is anything to do
	if len(scheduledMigrations) < 1 {
		return nil
	}

	migrationsChronologicallyOrdered := slices.CompactFunc(scheduledMigrations, func(m1, m2 migration.Migration) bool {
		return m1.Identifier() > m2.Identifier()
	})

	// Start transaction
	transaction, err := migrator.Database.BeginTx(ctx, nil)
	if err != nil {
		errors.Join(errors.New("starting migration transaction failed"), err)
	}
	defer transaction.Rollback()

	for _, migration := range migrationsChronologicallyOrdered {
		query, args := migration.Up()
		if _, err := transaction.ExecContext(ctx, query, args...); err != nil {
			return errors.Join(fmt.Errorf("migration up failed for %s", migration.Identifier()), err)
		}

		transaction.ExecContext(ctx, `INSERT INTO tbl_migrations (id, performed_at) VALUES (?,?);`, migration.Identifier(), time.Now().UTC().Unix(), true)
	}

	if err = transaction.Commit(); err != nil {
		return err
	}

	return nil
}

func (migrator *Migrator) Down() {

}

// Return the identifier of the latest known successful migration
// If there is no migration history (i.e. first time), returns "" as the identifier
func (migrator *Migrator) currentVersion(ctx context.Context) (string, error) {
	exists, err := migrator.exists(ctx)
	if err != nil {
		return "", errors.Join(errors.New("migration exists check failed"), err)
	}

	if !exists {
		if err := migrator.setup(ctx); err != nil {
			return "", errors.Join(errors.New("migration setup failed"), err)
		}
	}

	var currentMigrationIdentifier string
	row := migrator.Database.QueryRowContext(ctx, `SELECT id FROM tbl_migrations ORDER BY id DESC LIMIT 1`)

	if err := row.Scan(&currentMigrationIdentifier); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}

		return "", errors.Join(errors.New("getting last successful migration failed"), err)
	}

	return currentMigrationIdentifier, nil
}

func (migrator *Migrator) exists(ctx context.Context) (bool, error) {
	row := migrator.Database.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?;`, MigrationTableName)

	var tableName string
	if err := row.Scan(&tableName); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return false, errors.Join(errors.New("existance check migration table failed"), err)
		}

		return false, nil
	}

	return true, nil
}

func (migrator *Migrator) setup(ctx context.Context) error {
	query := `
		CREATE TABLE tbl_migrations (
			id TEXT NOT NULL,
			performed_at INT NOT NULL,
			PRIMARY KEY (id)
		);
	`
	_, err := migrator.Database.ExecContext(ctx, query)
	if err != nil {
		return errors.Join(errors.New("migration setup failed"))
	}

	return nil
}
