package oauth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/config"
)

// refreshWindow is how far before expiry we proactively refresh.
const refreshWindow = 60 * time.Second

// Manager coordinates storage and refresh of Element-Skin OAuth tokens.
type Manager struct {
	cfg    config.Config
	store  *Store
	client *ElementSkinClient
}

// NewManager creates a Manager from configuration, opening the SQLite store
// and constructing the upstream token client.
func NewManager(cfg config.Config, httpClient *http.Client) (*Manager, error) {
	store, err := OpenStore(cfg.Storage.Path)
	if err != nil {
		return nil, fmt.Errorf("open token store: %w", err)
	}
	client := NewElementSkinClient(
		cfg.Elementskin.BaseURL,
		cfg.Elementskin.OAuth.ClientID,
		cfg.Elementskin.OAuth.ClientSecret,
		cfg.Elementskin.OAuth.RedirectURI,
		httpClient,
	)
	return &Manager{cfg: cfg, store: store, client: client}, nil
}

// NewManagerWithDeps is used by tests to inject a store and client directly.
func NewManagerWithDeps(cfg config.Config, store *Store, client *ElementSkinClient) *Manager {
	return &Manager{cfg: cfg, store: store, client: client}
}

// ExchangeCode exchanges an authorization code + PKCE verifier for tokens and
// persists the result.
func (m *Manager) ExchangeCode(ctx context.Context, code, verifier string) error {
	resp, err := m.client.ExchangeCode(ctx, code, verifier)
	if err != nil {
		return fmt.Errorf("exchange code: %w", err)
	}
	return m.persist(ctx, resp)
}

// AccessToken returns a valid access token, refreshing it automatically if it
// has expired or is within refreshWindow of expiry.
func (m *Manager) AccessToken(ctx context.Context) (string, error) {
	row, err := m.store.Load(ctx)
	if err != nil {
		return "", fmt.Errorf("load token: %w", err)
	}
	if needsRefresh(row.ExpiresAtMS) {
		if err := m.Refresh(ctx); err != nil {
			return "", fmt.Errorf("auto-refresh token: %w", err)
		}
		row, err = m.store.Load(ctx)
		if err != nil {
			return "", fmt.Errorf("load refreshed token: %w", err)
		}
	}
	return row.AccessToken, nil
}

// Refresh manually refreshes the stored access token using the refresh token.
func (m *Manager) Refresh(ctx context.Context) error {
	row, err := m.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("load token for refresh: %w", err)
	}
	resp, err := m.client.Refresh(ctx, row.RefreshToken)
	if err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}
	return m.persist(ctx, resp)
}

func (m *Manager) persist(ctx context.Context, resp *TokenResponse) error {
	expiresAtMS := time.Now().UTC().UnixMilli() + resp.ExpiresIn*1000
	row := TokenRow{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAtMS:  expiresAtMS,
		Scope:        resp.Scope,
		CreatedAtMS:  time.Now().UTC().UnixMilli(),
	}
	if err := m.store.Save(ctx, row); err != nil {
		return fmt.Errorf("persist token: %w", err)
	}
	return nil
}

func needsRefresh(expiresAtMS int64) bool {
	return time.Now().UTC().UnixMilli() >= expiresAtMS-int64(refreshWindow/time.Millisecond)
}

// Close closes the underlying token store.
func (m *Manager) Close() error {
	if m.store == nil {
		return nil
	}
	return m.store.Close()
}
