package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/freekieb7/go-lock/internal/database"
)

type Migrator struct {
	DB            *database.Database
	MigrationsDir string
	Logger        *slog.Logger
}

func NewMigrator(db *database.Database, logger *slog.Logger) Migrator {
	return Migrator{
		DB:            db,
		MigrationsDir: "internal/database/migrations",
		Logger:        logger,
	}
}

func (m *Migrator) CreateMigrationTable(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS tbl_migration (
		id SERIAL PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TIMESTAMP NOT NULL
	);`

	if _, err := m.DB.Exec(ctx, query); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	return nil
}

func (m *Migrator) MigrateUp(ctx context.Context, step int) error {
	if err := m.CreateMigrationTable(ctx); err != nil {
		return fmt.Errorf("failed to ensure migrations table exists: %w", err)
	}

	migrations, err := m.getMigrationsFromDir()
	if err != nil {
		return fmt.Errorf("failed to get migrations: %w", err)
	}

	// Sort migrations by name (ascending - oldest first)
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Name < migrations[j].Name
	})

	count := 0
	for _, migration := range migrations {
		if step > 0 && count >= step {
			break
		}

		applied, err := m.MigrateUpMigration(ctx, migration)
		if err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration.Name, err)
		}

		if applied {
			count++
		}
	}

	if count > 0 {
		m.Logger.InfoContext(ctx, "Applied migrations successfully",
			slog.Int("count", count))
	} else {
		m.Logger.InfoContext(ctx, "No migrations to apply")
	}

	return nil
}

func (m *Migrator) MigrateUpMigration(ctx context.Context, migration database.Migration) (bool, error) {
	// Validate migration has SQL
	if migration.UpSQL == "" {
		return false, fmt.Errorf("migration %s missing up SQL", migration.Name)
	}

	tx, err := m.DB.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to begin transaction for migration %s: %w", migration.Name, err)
	}
	defer tx.Rollback(ctx)

	var applied bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM tbl_migration WHERE name=$1)", migration.Name).Scan(&applied); err != nil {
		return false, fmt.Errorf("failed to check migration %s: %w", migration.Name, err)
	}

	if applied {
		m.Logger.InfoContext(ctx, "Skipping migration (already applied)",
			slog.String("migration", migration.Name))
		return false, nil
	}

	if _, err := tx.Exec(ctx, migration.UpSQL); err != nil {
		return false, fmt.Errorf("failed to apply migration %s: %w", migration.Name, err)
	}

	if _, err := tx.Exec(ctx, "INSERT INTO tbl_migration (name, applied_at) VALUES ($1, NOW())", migration.Name); err != nil {
		return false, fmt.Errorf("failed to record applied migration %s: %w", migration.Name, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("failed to commit migration %s: %w", migration.Name, err)
	}

	m.Logger.InfoContext(ctx, "Applied migration successfully",
		slog.String("migration", migration.Name))

	return true, nil
}

func (m *Migrator) MigrateDown(ctx context.Context, step int) error {
	if err := m.CreateMigrationTable(ctx); err != nil {
		return fmt.Errorf("failed to ensure migrations table exists: %w", err)
	}

	// Get applied migrations from database in reverse order (newest first)
	rows, err := m.DB.Query(ctx, "SELECT name FROM tbl_migration ORDER BY name DESC")
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}
	defer rows.Close()

	var appliedNames []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("failed to scan migration name: %w", err)
		}
		appliedNames = append(appliedNames, name)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating migrations: %w", err)
	}

	// Roll back migrations in reverse order, reading only needed files
	count := 0
	for _, name := range appliedNames {
		if step > 0 && count >= step {
			break
		}

		// Read only the specific down migration file needed
		downFile := filepath.Join(m.MigrationsDir, name+"_down.sql")
		content, err := os.ReadFile(downFile)
		if err != nil {
			return fmt.Errorf("migration file not found for: %s", name)
		}

		migration := database.Migration{
			Name:    name,
			DownSQL: string(content),
		}

		rolledBack, err := m.MigrateDownMigration(ctx, migration)
		if err != nil {
			return fmt.Errorf("failed to rollback migration %s: %w", migration.Name, err)
		}

		if rolledBack {
			count++
		}
	}

	if count > 0 {
		m.Logger.InfoContext(ctx, "Rolled back migrations successfully",
			slog.Int("count", count))
	} else {
		m.Logger.InfoContext(ctx, "No migrations to rollback")
	}

	return nil
}

func (m *Migrator) MigrateDownMigration(ctx context.Context, migration database.Migration) (bool, error) {
	// Validate migration has SQL
	if migration.DownSQL == "" {
		return false, fmt.Errorf("migration %s missing down SQL", migration.Name)
	}

	tx, err := m.DB.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to begin transaction for migration %s: %w", migration.Name, err)
	}
	defer tx.Rollback(ctx)

	var applied bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM tbl_migration WHERE name=$1)", migration.Name).Scan(&applied); err != nil {
		return false, fmt.Errorf("failed to check migration %s: %w", migration.Name, err)
	}

	if !applied {
		m.Logger.InfoContext(ctx, "Skipping migration (not applied)",
			slog.String("migration", migration.Name))
		return false, nil
	}

	if _, err := tx.Exec(ctx, migration.DownSQL); err != nil {
		return false, fmt.Errorf("failed to rollback migration %s: %w", migration.Name, err)
	}

	if _, err := tx.Exec(ctx, "DELETE FROM tbl_migration WHERE name=$1", migration.Name); err != nil {
		return false, fmt.Errorf("failed to remove migration record %s: %w", migration.Name, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("failed to commit rollback for migration %s: %w", migration.Name, err)
	}

	m.Logger.InfoContext(ctx, "Rolled back migration successfully",
		slog.String("migration", migration.Name))

	return true, nil
}

func (m *Migrator) getMigrationsFromDir() ([]database.Migration, error) {
	files, err := os.ReadDir(m.MigrationsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	migrationsByName := make(map[string]database.Migration)
	for _, file := range files {
		if !file.IsDir() {
			// filename format: {timestamp}_{name}_[up|down].sql
			fileName := file.Name()
			timestamp, name, direction, err := m.ParseMigrationFileName(fileName)
			if err != nil {
				return nil, fmt.Errorf("failed to parse migration file name %s: %w", fileName, err)
			}

			content, err := os.ReadFile(filepath.Join(m.MigrationsDir, fileName))
			if err != nil {
				return nil, fmt.Errorf("failed to read migration file %s: %w", fileName, err)
			}

			fullName := fmt.Sprintf("%d_%s", timestamp, name)
			migration, exists := migrationsByName[fullName]
			if !exists {
				migration = database.Migration{
					Name: fullName,
				}
			}

			switch direction {
			case "up":
				migration.UpSQL = string(content)
			case "down":
				migration.DownSQL = string(content)
			}

			migrationsByName[fullName] = migration
		}
	}

	// Pre-allocate slice with correct capacity
	migrations := make([]database.Migration, 0, len(migrationsByName))
	for _, migration := range migrationsByName {
		// Validate that both up and down migrations exist
		if migration.UpSQL == "" || migration.DownSQL == "" {
			return nil, fmt.Errorf("migration %s missing up or down SQL file", migration.Name)
		}
		migrations = append(migrations, migration)
	}

	return migrations, nil
}

// Name format: {20140102150405}_{migration_name}_[up|down].sql
func (m *Migrator) ParseMigrationFileName(filename string) (uint64, string, string, error) {
	n := len(filename)
	if n < 23 {
		return 0, "", "", fmt.Errorf("invalid migration file name: %s", filename)
	}

	if filename[n-4:] != ".sql" {
		return 0, "", "", fmt.Errorf("invalid migration file name: %s", filename)
	}

	timestampStartPos := 0
	timestampEndPos := strings.IndexByte(filename, '_')
	if timestampEndPos == -1 {
		return 0, "", "", fmt.Errorf("invalid migration file name: %s", filename)
	}

	nameStartPos := timestampEndPos + 1
	nameEndPos := nameStartPos

	for {
		nextPos := strings.IndexByte(filename[nameEndPos:], '_')
		if nextPos == -1 {
			break
		}
		nameEndPos += nextPos + 1
	}
	nameEndPos-- // step back to remove last underscore

	timestamp := filename[timestampStartPos:timestampEndPos]
	name := filename[nameStartPos:nameEndPos]
	direction := filename[nameEndPos+1 : len(filename)-4] // remove .sql

	if _, err := time.Parse("20060102150405", timestamp); err != nil {
		return 0, "", "", fmt.Errorf("invalid timestamp in file: %s", filename)
	}

	if direction != "up" && direction != "down" {
		return 0, "", "", fmt.Errorf("invalid migration direction in file: %s", filename)
	}

	timestampUint64, err := strconv.ParseUint(timestamp, 10, 64)
	if err != nil {
		return 0, "", "", fmt.Errorf("invalid timestamp in file: %s", filename)
	}

	return timestampUint64, name, direction, nil
}
