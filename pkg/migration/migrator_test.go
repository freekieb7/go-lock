package migration_test

import (
	"context"
	"testing"
	"time"

	"github.com/freekieb7/go-lock/pkg/container"
	"github.com/freekieb7/go-lock/pkg/migration"
	"github.com/freekieb7/go-lock/pkg/migration/entity"
)

func TestUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	container := container.New(ctx)
	t.Logf("datadir located at : %s", container.Settings.DataDir)
	migrator := migration.NewMigrator(container.Database)

	if err := migrator.Up(ctx); err != nil {
		t.Fatal(err)
	}

	rows, err := container.Database.Query("SELECT * FROM tbl_migration")
	if err != nil {
		t.Fatal(err)
	}

	var migrationEntity entity.Migration
	for rows.Next() {
		var timeUnix int
		if err := rows.Scan(&migrationEntity.Id, &timeUnix); err != nil {
			t.Fatal(err)
		}

		migrationEntity.PerformedAt = time.Unix(int64(timeUnix), 0)
	}
}
