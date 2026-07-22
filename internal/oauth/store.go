package oauth

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

// TokenRow holds a single persisted OAuth token set.
type TokenRow struct {
	GrantID      string
	AccessToken  string
	RefreshToken string
	ExpiresAtMS  int64
	Scope        string
	CreatedAtMS  int64
}

// Store persists OAuth tokens in SQLite with single-active-row semantics.
type Store struct {
	db *sql.DB
}

// NewStore wraps an existing *sql.DB and ensures the schema exists.
func NewStore(db *sql.DB) (*Store, error) {
	s := &Store{db: db}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenStore opens a SQLite database at path, creating parent directories if
// needed, and ensures the schema exists.
func OpenStore(path string) (*Store, error) {
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
	s, err := NewStore(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS oauth_tokens (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			grant_id TEXT,
			access_token TEXT NOT NULL,
			refresh_token TEXT NOT NULL,
			expires_at_ms INTEGER NOT NULL,
			scope TEXT,
			created_at_ms INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create oauth_tokens table: %w", err)
	}
	return nil
}

// Save persists row as the single active token record, overwriting any
// previous token.
func (s *Store) Save(ctx context.Context, row TokenRow) error {
	now := time.Now().UTC().UnixMilli()
	if row.CreatedAtMS == 0 {
		row.CreatedAtMS = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_tokens
			(id, grant_id, access_token, refresh_token, expires_at_ms, scope, created_at_ms)
		VALUES (1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			grant_id = excluded.grant_id,
			access_token = excluded.access_token,
			refresh_token = excluded.refresh_token,
			expires_at_ms = excluded.expires_at_ms,
			scope = excluded.scope,
			created_at_ms = excluded.created_at_ms
	`, row.GrantID, row.AccessToken, row.RefreshToken, row.ExpiresAtMS, row.Scope, row.CreatedAtMS)
	if err != nil {
		return fmt.Errorf("save oauth token: %w", err)
	}
	return nil
}

// ErrNoToken is returned when no token has been stored yet.
var ErrNoToken = errors.New("no stored oauth token")

// Load returns the single active token row. If no token exists, it returns
// ErrNoToken.
func (s *Store) Load(ctx context.Context) (TokenRow, error) {
	var row TokenRow
	err := s.db.QueryRowContext(ctx, `
		SELECT grant_id, access_token, refresh_token, expires_at_ms, scope, created_at_ms
		FROM oauth_tokens
		WHERE id = 1
	`).Scan(&row.GrantID, &row.AccessToken, &row.RefreshToken, &row.ExpiresAtMS, &row.Scope, &row.CreatedAtMS)
	if errors.Is(err, sql.ErrNoRows) {
		return row, ErrNoToken
	}
	if err != nil {
		return row, fmt.Errorf("load oauth token: %w", err)
	}
	return row, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}
