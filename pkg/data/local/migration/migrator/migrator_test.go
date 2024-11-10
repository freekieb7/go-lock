package migrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/freekieb7/go-lock/pkg/container"
	"github.com/freekieb7/go-lock/pkg/data/local/migration"
	"github.com/freekieb7/go-lock/pkg/data/local/migration/migrator"
	migration_version "github.com/freekieb7/go-lock/pkg/data/local/migration/versions"
)

func TestUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	container := container.New(ctx)
	t.Logf("datadir located at : %s", container.Settings.DataDir)
	migrator := migrator.New(container.Database)

	migrationCreateTables := migration_version.NewMigrationCreateTables(container.Settings)
	migrations := []migration.Migration{
		migrationCreateTables,
	}
	if err := migrator.Up(ctx, migrations); err != nil {
		t.Fatal(err)
	}

	rows, err := container.Database.Query("SELECT * FROM tbl_migrations")
	if err != nil {
		t.Fatal(err)
	}

	var migrationEntity migration.MigrationEntity
	for rows.Next() {
		var timeUnix int
		if err := rows.Scan(&migrationEntity.Id, &timeUnix); err != nil {
			t.Fatal(err)
		}

		migrationEntity.PerformedAt = time.Unix(int64(timeUnix), 0)
	}

	if migrationCreateTables.Identifier() != migrationEntity.Id {
		t.Errorf("migrator stored unexpected migration: got %v want %v",
			migrationEntity.Id, migrationCreateTables.Identifier())
	}
}
