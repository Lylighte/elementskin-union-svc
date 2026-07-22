package oauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/config"
)

func serviceTokenTestConfig(serverURL string) config.Config {
	var cfg config.Config
	cfg.Elementskin.BaseURL = serverURL
	cfg.Elementskin.ServiceAccount.ClientID = "svc-client-id"
	cfg.Elementskin.ServiceAccount.ClientSecret = "svc-client-secret"
	cfg.Elementskin.ServiceAccount.Scope = "profile.read.any"
	cfg.Storage.Path = ""
	return cfg
}

func openTestServiceTokenStore(t *testing.T) *ServiceTokenStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "service_tokens.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	store, err := NewServiceTokenStore(db)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	return store
}

func TestServiceTokenManagerAccessTokenSendsExactFieldsAndStoresToken(t *testing.T) {
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
			AccessToken: "service-access-1",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "profile.read.any",
		})
	}))
	defer server.Close()

	cfg := serviceTokenTestConfig(server.URL)
	store := openTestServiceTokenStore(t)
	defer store.Close()
	client := NewElementSkinClient(
		cfg.Elementskin.BaseURL,
		cfg.Elementskin.ServiceAccount.ClientID,
		cfg.Elementskin.ServiceAccount.ClientSecret,
		"",
		server.Client(),
	)
	mgr := NewServiceTokenManagerWithDeps(cfg, store, client)

	token, err := mgr.ServiceAccessToken(context.Background())
	if err != nil {
		t.Fatalf("service access token: %v", err)
	}

	if token != "service-access-1" {
		t.Errorf("token = %q, want service-access-1", token)
	}
	if callCount != 1 {
		t.Errorf("expected 1 token call, got %d", callCount)
	}
	want := url.Values{
		"grant_type":    []string{"client_credentials"},
		"client_id":     []string{"svc-client-id"},
		"client_secret": []string{"svc-client-secret"},
		"scope":         []string{"profile.read.any"},
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
	if row.AccessToken != "service-access-1" {
		t.Errorf("stored access token = %q, want service-access-1", row.AccessToken)
	}
	if row.Scope != "profile.read.any" {
		t.Errorf("stored scope = %q, want profile.read.any", row.Scope)
	}
	if !within(row.ExpiresAtMS, time.Now().UTC().UnixMilli()+3600*1000, 2000) {
		t.Errorf("expires_at_ms %d is not within 2s of expected", row.ExpiresAtMS)
	}
}

func TestServiceTokenManagerAccessTokenReturnsStoredTokenWithoutRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected token endpoint call for %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := serviceTokenTestConfig(server.URL)
	store := openTestServiceTokenStore(t)
	defer store.Close()
	client := NewElementSkinClient(
		cfg.Elementskin.BaseURL,
		cfg.Elementskin.ServiceAccount.ClientID,
		cfg.Elementskin.ServiceAccount.ClientSecret,
		"",
		server.Client(),
	)
	mgr := NewServiceTokenManagerWithDeps(cfg, store, client)

	row := ServiceTokenRow{
		AccessToken: "valid-service-access",
		ExpiresAtMS: time.Now().UTC().Add(5 * time.Minute).UnixMilli(),
		Scope:       "profile.read.any",
		CreatedAtMS: time.Now().UTC().UnixMilli(),
	}
	if err := store.Save(context.Background(), row); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	token, err := mgr.ServiceAccessToken(context.Background())
	if err != nil {
		t.Fatalf("service access token: %v", err)
	}
	if token != "valid-service-access" {
		t.Errorf("token = %q, want valid-service-access", token)
	}
}

func TestServiceTokenManagerAccessTokenAutoRefreshesWhenExpired(t *testing.T) {
	var callCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.URL.Path != "/oauth/token" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		grantType := r.PostFormValue("grant_type")
		if grantType != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials", grantType)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "refreshed-service-access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "profile.read.any",
		})
	}))
	defer server.Close()

	cfg := serviceTokenTestConfig(server.URL)
	store := openTestServiceTokenStore(t)
	defer store.Close()
	client := NewElementSkinClient(
		cfg.Elementskin.BaseURL,
		cfg.Elementskin.ServiceAccount.ClientID,
		cfg.Elementskin.ServiceAccount.ClientSecret,
		"",
		server.Client(),
	)
	mgr := NewServiceTokenManagerWithDeps(cfg, store, client)

	row := ServiceTokenRow{
		AccessToken: "expired-service-access",
		ExpiresAtMS: time.Now().UTC().Add(-time.Hour).UnixMilli(),
		Scope:       "profile.read.any",
		CreatedAtMS: time.Now().UTC().Add(-2 * time.Hour).UnixMilli(),
	}
	if err := store.Save(context.Background(), row); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	token, err := mgr.ServiceAccessToken(context.Background())
	if err != nil {
		t.Fatalf("service access token: %v", err)
	}
	if token != "refreshed-service-access" {
		t.Errorf("token = %q, want refreshed-service-access", token)
	}
	if callCount != 1 {
		t.Errorf("expected 1 refresh call, got %d", callCount)
	}

	stored, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load refreshed token: %v", err)
	}
	if stored.AccessToken != "refreshed-service-access" {
		t.Errorf("stored access token = %q, want refreshed-service-access", stored.AccessToken)
	}
}

func TestServiceTokenManagerAccessTokenReturnsErrorWithoutStoringOnFailure(t *testing.T) {
	var callCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
	}))
	defer server.Close()

	cfg := serviceTokenTestConfig(server.URL)
	store := openTestServiceTokenStore(t)
	defer store.Close()
	client := NewElementSkinClient(
		cfg.Elementskin.BaseURL,
		cfg.Elementskin.ServiceAccount.ClientID,
		cfg.Elementskin.ServiceAccount.ClientSecret,
		"",
		server.Client(),
	)
	mgr := NewServiceTokenManagerWithDeps(cfg, store, client)

	_, err := mgr.ServiceAccessToken(context.Background())
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if callCount != 1 {
		t.Errorf("expected 1 token call, got %d", callCount)
	}

	_, loadErr := store.Load(context.Background())
	if !errors.Is(loadErr, ErrNoServiceToken) {
		t.Errorf("expected no stored token, got err=%v", loadErr)
	}
}

func TestServiceTokenStoreGetMissingReturnsErrNoServiceToken(t *testing.T) {
	store := openTestServiceTokenStore(t)
	defer store.Close()

	_, err := store.Load(context.Background())
	if !errors.Is(err, ErrNoServiceToken) {
		t.Errorf("Load err = %v, want ErrNoServiceToken", err)
	}
}
