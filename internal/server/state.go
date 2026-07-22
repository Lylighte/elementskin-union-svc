package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const (
	// stateExpiry is how long an authorization state entry remains valid.
	stateExpiry = 10 * time.Minute

	// verifierLength is the PKCE code verifier length in characters.
	// RFC 7636 permits 43-128 unreserved URL characters.
	verifierLength = 64

	// verifierChars is the alphabet of unreserved URL characters.
	verifierChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

// State holds an authorization request state and its matching PKCE verifier.
type State struct {
	State       string
	Verifier    string
	RedirectURI string
	Scope       string
	ExpiresAtMS int64
}

// StateStore persists OAuth authorization states in SQLite.
type StateStore struct {
	db *sql.DB
}

// OpenStateStore opens a SQLite database at path and ensures the schema exists.
func OpenStateStore(path string) (*StateStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	db.SetMaxOpenConns(1)
	s, err := NewStateStore(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewStateStore wraps an existing *sql.DB and ensures the schema exists.
func NewStateStore(db *sql.DB) (*StateStore, error) {
	s := &StateStore{db: db}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *StateStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS oauth_states (
			state TEXT PRIMARY KEY,
			verifier TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT NOT NULL,
			expires_at_ms INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create oauth_states table: %w", err)
	}
	return nil
}

// ErrStateNotFound is returned when a state does not exist or has expired.
var ErrStateNotFound = errors.New("state not found or expired")

// Save persists a state entry, cleaning up expired entries first.
func (s *StateStore) Save(ctx context.Context, state State) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM oauth_states WHERE expires_at_ms < ?`, time.Now().UTC().UnixMilli()); err != nil {
		return fmt.Errorf("cleanup expired states: %w", err)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_states (state, verifier, redirect_uri, scope, expires_at_ms)
		VALUES (?, ?, ?, ?, ?)
	`, state.State, state.Verifier, state.RedirectURI, state.Scope, state.ExpiresAtMS)
	if err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	return nil
}

// Load returns the state entry for token. If it is missing or expired, it
// deletes the entry and returns ErrStateNotFound.
func (s *StateStore) Load(ctx context.Context, state string) (State, error) {
	var row State
	err := s.db.QueryRowContext(ctx, `
		SELECT state, verifier, redirect_uri, scope, expires_at_ms
		FROM oauth_states
		WHERE state = ?
	`, state).Scan(&row.State, &row.Verifier, &row.RedirectURI, &row.Scope, &row.ExpiresAtMS)
	if errors.Is(err, sql.ErrNoRows) {
		return row, ErrStateNotFound
	}
	if err != nil {
		return row, fmt.Errorf("load state: %w", err)
	}
	if time.Now().UTC().UnixMilli() >= row.ExpiresAtMS {
		_ = s.Delete(ctx, state)
		return row, ErrStateNotFound
	}
	return row, nil
}

// Delete removes a state entry.
func (s *StateStore) Delete(ctx context.Context, state string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oauth_states WHERE state = ?`, state)
	if err != nil {
		return fmt.Errorf("delete state: %w", err)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *StateStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// generateState returns a URL-safe random state string.
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateVerifier returns a random PKCE code verifier.
func generateVerifier() (string, error) {
	b := make([]byte, verifierLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate verifier: %w", err)
	}
	for i := range b {
		b[i] = verifierChars[int(b[i])%len(verifierChars)]
	}
	return string(b), nil
}

// challengeS256 returns the S256 code challenge for a verifier.
func challengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
