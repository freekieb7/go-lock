package migration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"
)

var migrations map[string]Migration = make(map[string]Migration)

func Register(migration Migration) {
	_, found := migrations[migration.Identifier()]
	if found {
		panic(fmt.Errorf("migration already registered with id %s", migration.Identifier()))
	}

	migrations[migration.Identifier()] = migration
}

type Migrator struct {
	Database *sql.DB
}

func NewMigrator(db *sql.DB) *Migrator {
	return &Migrator{
		db,
	}
}

func (migrator *Migrator) Up(ctx context.Context) error {
	// Check if there is anything to do
	if len(migrations) < 1 {
		return nil
	}

	currentIdentifier, err := migrator.currentVersion(ctx)
	if err != nil {
		return errors.Join(errors.New("getting current migration version failed"), err)
	}

	scheduledMigrations := make([]Migration, 0)
	for _, migration := range migrations {
		if migration.Identifier() > currentIdentifier {
			scheduledMigrations = append(scheduledMigrations, migration)
		}
	}

	// Check if there is anything to do
	if len(scheduledMigrations) < 1 {
		return nil
	}

	migrationsChronologicallyOrdered := slices.CompactFunc(scheduledMigrations, func(m1, m2 Migration) bool {
		return m1.Identifier() > m2.Identifier()
	})

	// Start transaction
	transaction, err := migrator.Database.BeginTx(ctx, nil)
	if err != nil {
		errors.Join(errors.New("starting migration transaction failed"), err)
	}
	defer transaction.Rollback()

	for _, migration := range migrationsChronologicallyOrdered {
		log.Println("migrating: " + migration.Identifier() + " -> STARTING")

		statements := migration.Up()
		for _, statement := range statements {
			if _, err := transaction.ExecContext(ctx, statement.Query, statement.Arguments...); err != nil {
				return errors.Join(fmt.Errorf("migrating: %s -> FAILED", migration.Identifier()), fmt.Errorf("query: %s", statement.Query), err)
			}
		}

		transaction.ExecContext(ctx, `INSERT INTO tbl_migration (id, performed_at) VALUES (?,?);`, migration.Identifier(), time.Now().UTC().Unix(), true)
		log.Println("migrating: " + migration.Identifier() + " -> DONE")
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
	row := migrator.Database.QueryRowContext(ctx, `SELECT id FROM tbl_migration ORDER BY id DESC LIMIT 1`)

	if err := row.Scan(&currentMigrationIdentifier); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}

		return "", errors.Join(errors.New("getting last successful migration failed"), err)
	}

	return currentMigrationIdentifier, nil
}

func (migrator *Migrator) exists(ctx context.Context) (bool, error) {
	row := migrator.Database.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'tbl_migration';`)

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
		CREATE TABLE tbl_migration (
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
