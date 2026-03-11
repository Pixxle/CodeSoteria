package db

import (
	"database/sql"
	"embed"
	"fmt"
	"strings"

	_ "github.com/mattn/go-sqlite3"

	"github.com/CodeSoteria/soteria/internal/config"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps the sql.DB connection.
type DB struct {
	*sql.DB
}

// New opens a database connection and runs migrations.
func New(cfg config.DatabaseConfig) (*DB, error) {
	sqlDB, err := sql.Open(cfg.Driver, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	// Enable WAL mode and foreign keys for SQLite
	if cfg.Driver == "sqlite3" {
		if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
			return nil, fmt.Errorf("enable WAL: %w", err)
		}
		if _, err := sqlDB.Exec("PRAGMA foreign_keys=ON"); err != nil {
			return nil, fmt.Errorf("enable foreign keys: %w", err)
		}
	}

	d := &DB{sqlDB}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return d, nil
}

func (d *DB) migrate() error {
	// Create migrations tracking table
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return err
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		var applied int
		err := d.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", entry.Name()).Scan(&applied)
		if err != nil {
			return err
		}
		if applied > 0 {
			continue
		}

		content, err := migrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}

		if _, err := d.Exec(string(content)); err != nil {
			return fmt.Errorf("apply %s: %w", entry.Name(), err)
		}

		if _, err := d.Exec("INSERT INTO schema_migrations (version) VALUES (?)", entry.Name()); err != nil {
			return err
		}
	}

	return nil
}
