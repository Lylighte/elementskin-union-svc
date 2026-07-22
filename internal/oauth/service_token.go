package oauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/config"

	_ "modernc.org/sqlite"
)

// ServiceTokenRow holds a single persisted client_credentials access token.
type ServiceTokenRow struct {
	AccessToken string
	ExpiresAtMS int64
	Scope       string
	CreatedAtMS int64
}

// ServiceTokenStore persists a client_credentials token in a single-row SQLite
// table, mirroring the oauth_tokens store pattern.
type ServiceTokenStore struct {
	db *sql.DB
}

// NewServiceTokenStore wraps an existing *sql.DB and ensures the schema exists.
func NewServiceTokenStore(db *sql.DB) (*ServiceTokenStore, error) {
	s := &ServiceTokenStore{db: db}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenServiceTokenStore opens a SQLite database at path, creating parent
// directories if needed, and ensures the schema exists.
func OpenServiceTokenStore(path string) (*ServiceTokenStore, error) {
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
	s, err := NewServiceTokenStore(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *ServiceTokenStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS oauth_service_tokens (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			access_token TEXT NOT NULL,
			expires_at_ms INTEGER NOT NULL,
			scope TEXT,
			created_at_ms INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create oauth_service_tokens table: %w", err)
	}
	return nil
}

// Save persists row as the single active service token record, overwriting any
// previous token.
func (s *ServiceTokenStore) Save(ctx context.Context, row ServiceTokenRow) error {
	now := time.Now().UTC().UnixMilli()
	if row.CreatedAtMS == 0 {
		row.CreatedAtMS = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_service_tokens
			(id, access_token, expires_at_ms, scope, created_at_ms)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			access_token = excluded.access_token,
			expires_at_ms = excluded.expires_at_ms,
			scope = excluded.scope,
			created_at_ms = excluded.created_at_ms
	`, row.AccessToken, row.ExpiresAtMS, row.Scope, row.CreatedAtMS)
	if err != nil {
		return fmt.Errorf("save service token: %w", err)
	}
	return nil
}

// ErrNoServiceToken is returned when no service token has been stored yet.
var ErrNoServiceToken = errors.New("no stored service token")

// Load returns the single active service token row. If no token exists, it
// returns ErrNoServiceToken.
func (s *ServiceTokenStore) Load(ctx context.Context) (ServiceTokenRow, error) {
	var row ServiceTokenRow
	err := s.db.QueryRowContext(ctx, `
		SELECT access_token, expires_at_ms, scope, created_at_ms
		FROM oauth_service_tokens
		WHERE id = 1
	`).Scan(&row.AccessToken, &row.ExpiresAtMS, &row.Scope, &row.CreatedAtMS)
	if errors.Is(err, sql.ErrNoRows) {
		return row, ErrNoServiceToken
	}
	if err != nil {
		return row, fmt.Errorf("load service token: %w", err)
	}
	return row, nil
}

// Close closes the underlying database connection.
func (s *ServiceTokenStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// ServiceTokenManager coordinates storage and refresh of a client_credentials
// access token for service-to-service calls.
type ServiceTokenManager struct {
	cfg    config.Config
	store  *ServiceTokenStore
	client *ElementSkinClient
}

// NewServiceTokenManager creates a ServiceTokenManager from configuration,
// opening the SQLite store and constructing the upstream token client.
func NewServiceTokenManager(cfg config.Config, httpClient *http.Client) (*ServiceTokenManager, error) {
	store, err := OpenServiceTokenStore(cfg.Storage.Path)
	if err != nil {
		return nil, fmt.Errorf("open service token store: %w", err)
	}
	client := NewElementSkinClient(
		cfg.Elementskin.BaseURL,
		cfg.Elementskin.ServiceAccount.ClientID,
		cfg.Elementskin.ServiceAccount.ClientSecret,
		"",
		httpClient,
	)
	return &ServiceTokenManager{cfg: cfg, store: store, client: client}, nil
}

// NewServiceTokenManagerWithDeps is used by tests to inject a store and client
// directly.
func NewServiceTokenManagerWithDeps(cfg config.Config, store *ServiceTokenStore, client *ElementSkinClient) *ServiceTokenManager {
	return &ServiceTokenManager{cfg: cfg, store: store, client: client}
}

// ServiceAccessToken returns a valid client_credentials access token, fetching
// a new one automatically if none is stored or if the stored token has expired
// or is within refreshWindow of expiry.
func (m *ServiceTokenManager) ServiceAccessToken(ctx context.Context) (string, error) {
	row, err := m.store.Load(ctx)
	if err != nil && !errors.Is(err, ErrNoServiceToken) {
		return "", fmt.Errorf("load service token: %w", err)
	}
	if errors.Is(err, ErrNoServiceToken) || needsRefresh(row.ExpiresAtMS) {
		if err := m.fetch(ctx); err != nil {
			return "", fmt.Errorf("fetch service token: %w", err)
		}
		row, err = m.store.Load(ctx)
		if err != nil {
			return "", fmt.Errorf("load fetched service token: %w", err)
		}
	}
	return row.AccessToken, nil
}

func (m *ServiceTokenManager) fetch(ctx context.Context) error {
	scope := m.cfg.Elementskin.ServiceAccount.Scope
	resp, err := m.client.ClientCredentials(ctx, scope)
	if err != nil {
		return err
	}
	return m.persist(ctx, resp)
}

func (m *ServiceTokenManager) persist(ctx context.Context, resp *TokenResponse) error {
	expiresAtMS := time.Now().UTC().UnixMilli() + resp.ExpiresIn*1000
	row := ServiceTokenRow{
		AccessToken: resp.AccessToken,
		ExpiresAtMS: expiresAtMS,
		Scope:       resp.Scope,
		CreatedAtMS: time.Now().UTC().UnixMilli(),
	}
	if err := m.store.Save(ctx, row); err != nil {
		return fmt.Errorf("persist service token: %w", err)
	}
	return nil
}

// Close closes the underlying token store.
func (m *ServiceTokenManager) Close() error {
	if m.store == nil {
		return nil
	}
	return m.store.Close()
}
