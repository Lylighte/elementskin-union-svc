package union

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// NonceStore persists Union signature nonces for replay protection.
type NonceStore struct {
	db *sql.DB
}

// OpenNonceStore opens the SQLite database at path and ensures the
// union_nonces schema exists.
func OpenNonceStore(path string) (*NonceStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	db.SetMaxOpenConns(1)
	s, err := NewNonceStore(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewNonceStore wraps an existing *sql.DB and ensures the schema exists.
func NewNonceStore(db *sql.DB) (*NonceStore, error) {
	s := &NonceStore{db: db}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *NonceStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS union_nonces (
			nonce TEXT PRIMARY KEY,
			created_at_ms INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create union_nonces table: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_union_nonces_created_at
		ON union_nonces (created_at_ms)
	`)
	if err != nil {
		return fmt.Errorf("create union_nonces index: %w", err)
	}

	return nil
}

// IsUsed reports whether nonce has been logged within the replay window.
func (s *NonceStore) IsUsed(ctx context.Context, nonce string) (bool, error) {
	var createdAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT created_at_ms FROM union_nonces WHERE nonce = ?
	`, nonce).Scan(&createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query nonce: %w", err)
	}

	if time.Since(time.UnixMilli(createdAt)) >= nonceTTL {
		// Expired nonces are not considered used, and are cleaned up lazily.
		_ = s.deleteNonce(ctx, nonce)
		return false, nil
	}

	return true, nil
}

// LogNonce records nonce so that future calls to IsUsed report it as used.
// It also removes nonces that have fallen outside the replay window.
func (s *NonceStore) LogNonce(ctx context.Context, nonce string) error {
	now := time.Now().UTC().UnixMilli()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO union_nonces (nonce, created_at_ms) VALUES (?, ?)
		ON CONFLICT(nonce) DO NOTHING
	`, nonce, now)
	if err != nil {
		return fmt.Errorf("insert nonce: %w", err)
	}

	if err := s.cleanup(ctx); err != nil {
		return err
	}
	return nil
}

func (s *NonceStore) cleanup(ctx context.Context) error {
	cutoff := time.Now().UTC().Add(-nonceTTL).UnixMilli()
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM union_nonces WHERE created_at_ms < ?
	`, cutoff)
	if err != nil {
		return fmt.Errorf("cleanup expired nonces: %w", err)
	}
	return nil
}

func (s *NonceStore) deleteNonce(ctx context.Context, nonce string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM union_nonces WHERE nonce = ?`, nonce)
	if err != nil {
		return fmt.Errorf("delete expired nonce: %w", err)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *NonceStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// nonceTTL is how long a nonce remains in the replay window.
const nonceTTL = 60 * time.Second
