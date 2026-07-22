package session

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Store persists Union browser sessions in SQLite.
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
// needed, and ensures the union_sessions schema exists.
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
		CREATE TABLE IF NOT EXISTS union_sessions (
			session_id TEXT PRIMARY KEY,
			access_token TEXT NOT NULL,
			created_at_ms INTEGER NOT NULL,
			expires_at_ms INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create union_sessions table: %w", err)
	}
	return nil
}

// Create generates a new session ID, stores the access token with the given
// TTL, and returns the session ID.
func (s *Store) Create(ctx context.Context, accessToken string, ttl time.Duration) (string, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}

	now := time.Now().UnixMilli()
	expiresAt := now + ttl.Milliseconds()

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO union_sessions (session_id, access_token, created_at_ms, expires_at_ms)
		VALUES (?, ?, ?, ?)
	`, sessionID, accessToken, now, expiresAt)
	if err != nil {
		return "", fmt.Errorf("insert session: %w", err)
	}

	return sessionID, nil
}

// Lookup returns the access token for a valid, non-expired session ID.
// If the session is missing or expired, it returns "" and a nil error.
func (s *Store) Lookup(ctx context.Context, sessionID string) (string, error) {
	now := time.Now().UnixMilli()

	var accessToken string
	err := s.db.QueryRowContext(ctx, `
		SELECT access_token FROM union_sessions
		WHERE session_id = ? AND expires_at_ms > ?
	`, sessionID, now).Scan(&accessToken)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("lookup session: %w", err)
	}
	return accessToken, nil
}

// Delete removes the session with the given ID.
func (s *Store) Delete(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM union_sessions WHERE session_id = ?
	`, sessionID)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// CleanupExpired deletes all sessions whose expires_at_ms is in the past.
func (s *Store) CleanupExpired(ctx context.Context) error {
	now := time.Now().UnixMilli()
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM union_sessions WHERE expires_at_ms <= ?
	`, now)
	if err != nil {
		return fmt.Errorf("cleanup expired sessions: %w", err)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
