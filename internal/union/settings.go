package union

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// SettingsStore persists Union runtime settings in SQLite.
type SettingsStore struct {
	db *sql.DB
}

// OpenSettingsStore opens the SQLite database at path and ensures the
// union_settings schema exists.
func OpenSettingsStore(path string) (*SettingsStore, error) {
	// Path comes from admin configuration; clean to guard against
	// malformed or relative paths that could resolve to "." or "/".
	if dir := filepath.Clean(filepath.Dir(path)); dir != "." && dir != "/" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create storage directory %q: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	db.SetMaxOpenConns(1)

	s, err := NewSettingsStore(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewSettingsStore wraps an existing *sql.DB and ensures the schema exists.
func NewSettingsStore(db *sql.DB) (*SettingsStore, error) {
	s := &SettingsStore{db: db}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SettingsStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS union_settings (
			key TEXT PRIMARY KEY,
			value TEXT,
			updated_at_ms INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create union_settings table: %w", err)
	}
	return nil
}

// Get returns the value for key. If the key is missing, it returns "" and a
// nil error.
func (s *SettingsStore) Get(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `
		SELECT value FROM union_settings WHERE key = ?
	`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get setting %q: %w", key, err)
	}
	return value, nil
}

// Set stores value under key, recording the current timestamp.
func (s *SettingsStore) Set(ctx context.Context, key, value string) error {
	now := time.Now().UTC().UnixMilli()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO union_settings (key, value, updated_at_ms)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			updated_at_ms = excluded.updated_at_ms
	`, key, value, now)
	if err != nil {
		return fmt.Errorf("set setting %q: %w", key, err)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *SettingsStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
