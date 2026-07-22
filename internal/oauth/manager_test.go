package oauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/config"
)

func testConfig(serverURL string) config.Config {
	var cfg config.Config
	cfg.Elementskin.BaseURL = serverURL
	cfg.Elementskin.OAuth.ClientID = "test-client-id"
	cfg.Elementskin.OAuth.ClientSecret = "test-client-secret"
	cfg.Elementskin.OAuth.RedirectURI = "http://127.0.0.1:8001/oauth/callback"
	cfg.Storage.Path = ""
	return cfg
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	return store
}

func TestManagerExchangeCodeSendsExactFieldsAndStoresToken(t *testing.T) {
	var captured url.Values
	var callCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/oauth/token" {
			t.Errorf("expected /oauth/token, got %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		captured = r.PostForm

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "access-1",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh-1",
			Scope:        "profile.create.owned",
			Permissions:  []string{"profile.create.owned"},
		})
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	store := openTestStore(t)
	defer store.Close()
	client := NewElementSkinClient(cfg.Elementskin.BaseURL, cfg.Elementskin.OAuth.ClientID, cfg.Elementskin.OAuth.ClientSecret, cfg.Elementskin.OAuth.RedirectURI, server.Client())
	mgr := NewManagerWithDeps(cfg, store, client)

	if err := mgr.ExchangeCode(context.Background(), "auth-code-123", "verifier-xyz"); err != nil {
		t.Fatalf("exchange code: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 token call, got %d", callCount)
	}
	want := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{"auth-code-123"},
		"redirect_uri":  []string{"http://127.0.0.1:8001/oauth/callback"},
		"client_id":     []string{"test-client-id"},
		"client_secret": []string{"test-client-secret"},
		"code_verifier": []string{"verifier-xyz"},
	}
	for key, vals := range want {
		if got := captured.Get(key); got != vals[0] {
			t.Errorf("form field %q = %q, want %q", key, got, vals[0])
		}
	}

	row, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load stored token: %v", err)
	}
	if row.AccessToken != "access-1" {
		t.Errorf("access token = %q, want access-1", row.AccessToken)
	}
	if row.RefreshToken != "refresh-1" {
		t.Errorf("refresh token = %q, want refresh-1", row.RefreshToken)
	}
	if row.Scope != "profile.create.owned" {
		t.Errorf("scope = %q, want profile.create.owned", row.Scope)
	}
	if !within(row.ExpiresAtMS, time.Now().UTC().UnixMilli()+3600*1000, 2000) {
		t.Errorf("expires_at_ms %d is not within 2s of expected", row.ExpiresAtMS)
	}
}

func TestManagerAccessTokenReturnsStoredTokenWithoutRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected token endpoint call for %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	store := openTestStore(t)
	defer store.Close()
	client := NewElementSkinClient(cfg.Elementskin.BaseURL, cfg.Elementskin.OAuth.ClientID, cfg.Elementskin.OAuth.ClientSecret, cfg.Elementskin.OAuth.RedirectURI, server.Client())
	mgr := NewManagerWithDeps(cfg, store, client)

	row := TokenRow{
		AccessToken:  "valid-access",
		RefreshToken: "valid-refresh",
		ExpiresAtMS:  time.Now().UTC().Add(5 * time.Minute).UnixMilli(),
		Scope:        "profile.read.owned",
		CreatedAtMS:  time.Now().UTC().UnixMilli(),
	}
	if err := store.Save(context.Background(), row); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	token, err := mgr.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("access token: %v", err)
	}
	if token != "valid-access" {
		t.Errorf("token = %q, want valid-access", token)
	}
}

func TestManagerAccessTokenAutoRefreshesNearExpiry(t *testing.T) {
	var callCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.URL.Path != "/oauth/token" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		grantType := r.PostFormValue("grant_type")
		if grantType != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", grantType)
		}
		if refresh := r.PostFormValue("refresh_token"); refresh != "old-refresh" {
			t.Errorf("refresh_token = %q, want old-refresh", refresh)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "refreshed-access",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "new-refresh",
			Scope:        "profile.create.owned",
		})
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	store := openTestStore(t)
	defer store.Close()
	client := NewElementSkinClient(cfg.Elementskin.BaseURL, cfg.Elementskin.OAuth.ClientID, cfg.Elementskin.OAuth.ClientSecret, cfg.Elementskin.OAuth.RedirectURI, server.Client())
	mgr := NewManagerWithDeps(cfg, store, client)

	row := TokenRow{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAtMS:  time.Now().UTC().Add(30 * time.Second).UnixMilli(),
		Scope:        "profile.create.owned",
		CreatedAtMS:  time.Now().UTC().Add(-time.Hour).UnixMilli(),
	}
	if err := store.Save(context.Background(), row); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	token, err := mgr.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("access token: %v", err)
	}
	if token != "refreshed-access" {
		t.Errorf("token = %q, want refreshed-access", token)
	}
	if callCount != 1 {
		t.Errorf("expected 1 refresh call, got %d", callCount)
	}

	stored, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load refreshed token: %v", err)
	}
	if stored.RefreshToken != "new-refresh" {
		t.Errorf("stored refresh token = %q, want new-refresh", stored.RefreshToken)
	}
}

func TestManagerRefreshSendsExactFields(t *testing.T) {
	var captured url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		captured = r.PostForm

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "after-refresh",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh-2",
			Scope:        "profile.update.owned",
		})
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	store := openTestStore(t)
	defer store.Close()
	client := NewElementSkinClient(cfg.Elementskin.BaseURL, cfg.Elementskin.OAuth.ClientID, cfg.Elementskin.OAuth.ClientSecret, cfg.Elementskin.OAuth.RedirectURI, server.Client())
	mgr := NewManagerWithDeps(cfg, store, client)

	if err := store.Save(context.Background(), TokenRow{
		AccessToken:  "before-refresh",
		RefreshToken: "refresh-1",
		ExpiresAtMS:  time.Now().UTC().Add(time.Hour).UnixMilli(),
		Scope:        "profile.update.owned",
		CreatedAtMS:  time.Now().UTC().UnixMilli(),
	}); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	if err := mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	want := url.Values{
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{"refresh-1"},
		"client_id":     []string{"test-client-id"},
		"client_secret": []string{"test-client-secret"},
	}
	for key, vals := range want {
		if got := captured.Get(key); got != vals[0] {
			t.Errorf("form field %q = %q, want %q", key, got, vals[0])
		}
	}

	row, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load token: %v", err)
	}
	if row.AccessToken != "after-refresh" {
		t.Errorf("access token = %q, want after-refresh", row.AccessToken)
	}
	if row.RefreshToken != "refresh-2" {
		t.Errorf("refresh token = %q, want refresh-2", row.RefreshToken)
	}
}

func within(got, want, delta int64) bool {
	diff := got - want
	if diff < 0 {
		diff = -diff
	}
	return diff <= delta
}
