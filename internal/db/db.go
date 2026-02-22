package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	sqlc "bungleware/vault/internal/db/sqlc"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	*sql.DB
	*sqlc.Queries
	config Config
}

type Config struct {
	DataDir        string
	DBFile         string
	MigrationsPath string
}

func New(config Config) (*DB, error) {
	if err := os.MkdirAll(config.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(config.DataDir, config.DBFile)

	// WAL mode
	db, err := sql.Open("sqlite3", fmt.Sprintf("%s?_foreign_keys=on&_journal_mode=WAL", dbPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	wrapper := &DB{
		DB:      db,
		Queries: sqlc.New(db),
		config:  config,
	}

	if err := wrapper.runMigrations(config.MigrationsPath); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return wrapper, nil
}

func (db *DB) runMigrations(migrationsPath string) error {
	createTableSQL := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`
	if _, err := db.Exec(createTableSQL); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	entries, err := os.ReadDir(migrationsPath)
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}

		version := entry.Name()

		var exists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?)", version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("failed to check migration status: %w", err)
		}

		if exists {
			continue
		}

		content, err := os.ReadFile(filepath.Join(migrationsPath, entry.Name()))
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", version, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		if _, err := tx.Exec(string(content)); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to execute migration %s: %w", version, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES (?)", version); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to record migration %s: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %s: %w", version, err)
		}

		fmt.Printf("Applied migration: %s\n", version)
	}

	return nil
}

func (db *DB) Close() error {
	return db.DB.Close()
}

func (db *DB) ForceCheckpoint() error {
	_, err := db.Exec("PRAGMA wal_checkpoint(PASSIVE)")
	return err
}

func (db *DB) GetPath() string {
	return filepath.Join(db.config.DataDir, db.config.DBFile)
}

func (db *DB) Reconnect() error {
	if db.DB != nil {
		db.DB.Close()
	}

	dbPath := filepath.Join(db.config.DataDir, db.config.DBFile)
	newDB, err := sql.Open("sqlite3", fmt.Sprintf("%s?_foreign_keys=on&_journal_mode=WAL", dbPath))
	if err != nil {
		return fmt.Errorf("failed to reopen database: %w", err)
	}

	if err := newDB.Ping(); err != nil {
		newDB.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	newDB.SetMaxOpenConns(25)
	newDB.SetMaxIdleConns(5)

	db.DB = newDB
	db.Queries = sqlc.New(newDB)

	if err := db.runMigrations(db.config.MigrationsPath); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}
