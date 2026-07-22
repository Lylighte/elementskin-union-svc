package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/config"
)

func testConfig(serverURL string) config.Config {
	var cfg config.Config
	cfg.Server.Addr = "127.0.0.1"
	cfg.Server.Port = 0
	cfg.Elementskin.BaseURL = serverURL
	cfg.Elementskin.OAuth.ClientID = "test-client-id"
	cfg.Elementskin.OAuth.ClientSecret = "test-client-secret"
	cfg.Elementskin.OAuth.RedirectURI = "http://127.0.0.1:8001/oauth/callback"
	cfg.Storage.Path = ""
	cfg.Log.Level = "info"
	return cfg
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func openTestStateStore(t *testing.T) *StateStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "states.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	store, err := NewStateStore(db)
	if err != nil {
		t.Fatalf("create test state store: %v", err)
	}
	return store
}

func TestPKCEChallengeMatchesVerifier(t *testing.T) {
	verifier, err := generateVerifier()
	if err != nil {
		t.Fatalf("generate verifier: %v", err)
	}
	if len(verifier) != verifierLength {
		t.Fatalf("verifier length = %d, want %d", len(verifier), verifierLength)
	}
	for _, r := range verifier {
		if !strings.ContainsRune(verifierChars, r) {
			t.Fatalf("verifier contains invalid character %q", r)
		}
	}

	challenge := challengeS256(verifier)
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("challenge = %q, want %q", challenge, want)
	}
}

func TestStateStoreSaveLoadAndDelete(t *testing.T) {
	store := openTestStateStore(t)
	defer store.Close()

	entry := State{
		State:       "state-abc",
		Verifier:    "verifier-xyz",
		RedirectURI: "http://127.0.0.1:8001/oauth/callback",
		Scope:       "profile.read.owned",
		ExpiresAtMS: time.Now().UTC().Add(10 * time.Minute).UnixMilli(),
	}
	if err := store.Save(context.Background(), entry); err != nil {
		t.Fatalf("save state: %v", err)
	}

	loaded, err := store.Load(context.Background(), entry.State)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if loaded.Verifier != entry.Verifier {
		t.Errorf("verifier = %q, want %q", loaded.Verifier, entry.Verifier)
	}
	if loaded.RedirectURI != entry.RedirectURI {
		t.Errorf("redirect_uri = %q, want %q", loaded.RedirectURI, entry.RedirectURI)
	}
	if loaded.Scope != entry.Scope {
		t.Errorf("scope = %q, want %q", loaded.Scope, entry.Scope)
	}

	if err := store.Delete(context.Background(), entry.State); err != nil {
		t.Fatalf("delete state: %v", err)
	}
	if _, err := store.Load(context.Background(), entry.State); err != ErrStateNotFound {
		t.Fatalf("expected ErrStateNotFound after delete, got %v", err)
	}
}

func TestStateStoreRejectsExpiredState(t *testing.T) {
	store := openTestStateStore(t)
	defer store.Close()

	entry := State{
		State:       "expired-state",
		Verifier:    "verifier",
		RedirectURI: "http://127.0.0.1:8001/oauth/callback",
		Scope:       "profile.read.owned",
		ExpiresAtMS: time.Now().UTC().Add(-time.Second).UnixMilli(),
	}
	if err := store.Save(context.Background(), entry); err != nil {
		t.Fatalf("save state: %v", err)
	}

	if _, err := store.Load(context.Background(), entry.State); err != ErrStateNotFound {
		t.Fatalf("expected ErrStateNotFound for expired state, got %v", err)
	}
}

func TestAuthorizeRedirectIncludesAllParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected upstream call to %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(ts.URL + "/oauth/authorize")
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}

	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if loc.Path != "/oauth/authorize" {
		t.Errorf("location path = %q, want /oauth/authorize", loc.Path)
	}
	if loc.Scheme+"://"+loc.Host != server.URL {
		t.Errorf("location host = %q, want %q", loc.Scheme+"://"+loc.Host, server.URL)
	}

	q := loc.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want code", q.Get("response_type"))
	}
	if q.Get("client_id") != cfg.Elementskin.OAuth.ClientID {
		t.Errorf("client_id = %q, want %q", q.Get("client_id"), cfg.Elementskin.OAuth.ClientID)
	}
	if q.Get("redirect_uri") != cfg.Elementskin.OAuth.RedirectURI {
		t.Errorf("redirect_uri = %q, want %q", q.Get("redirect_uri"), cfg.Elementskin.OAuth.RedirectURI)
	}
	if q.Get("scope") != defaultScope {
		t.Errorf("scope = %q, want %q", q.Get("scope"), defaultScope)
	}
	if q.Get("state") == "" {
		t.Errorf("state is empty")
	}
	if q.Get("code_challenge") == "" {
		t.Errorf("code_challenge is empty")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}

	// Verify the challenge matches the stored verifier.
	loaded, err := srv.stateStore.Load(context.Background(), q.Get("state"))
	if err != nil {
		t.Fatalf("load stored state: %v", err)
	}
	if challengeS256(loaded.Verifier) != q.Get("code_challenge") {
		t.Errorf("stored verifier does not match code_challenge")
	}
}

func TestCallbackExchangesCodeAndReturnsOK(t *testing.T) {
	var captured url.Values
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		captured = r.PostForm

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-1",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "refresh-1",
			"scope":         defaultScope,
		})
	}))
	defer tokenServer.Close()

	cfg := testConfig(tokenServer.URL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	// Seed a state entry.
	state := "callback-state"
	verifier := "callback-verifier"
	if err := srv.stateStore.Save(context.Background(), State{
		State:       state,
		Verifier:    verifier,
		RedirectURI: cfg.Elementskin.OAuth.RedirectURI,
		Scope:       defaultScope,
		ExpiresAtMS: time.Now().UTC().Add(10 * time.Minute).UnixMilli(),
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(ts.URL + "/oauth/callback?code=auth-code-123&state=" + state)
	if err != nil {
		t.Fatalf("get callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 302: %s", resp.StatusCode, string(body))
	}

	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("get Location header: %v", err)
	}
	if loc.Path != "/" || loc.RawQuery != "authorized=true" {
		t.Errorf("Location = %q, want /?authorized=true", loc.String())
	}

	// Verify the token endpoint received the correct verifier.
	if captured.Get("code_verifier") != verifier {
		t.Errorf("code_verifier = %q, want %q", captured.Get("code_verifier"), verifier)
	}
	if captured.Get("code") != "auth-code-123" {
		t.Errorf("code = %q, want auth-code-123", captured.Get("code"))
	}

	// State should be removed after successful callback.
	if _, err := srv.stateStore.Load(context.Background(), state); err != ErrStateNotFound {
		t.Errorf("expected state to be deleted, got err=%v", err)
	}
}

func TestCallbackRejectsMissingCodeOrState(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	cases := []string{
		"/oauth/callback?code=abc",
		"/oauth/callback?state=abc",
		"/oauth/callback",
	}
	for _, p := range cases {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatalf("get %s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s status = %d, want 400", p, resp.StatusCode)
		}
	}
}

func TestCallbackRejectsInvalidState(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/oauth/callback?code=auth-code-123&state=invalid")
	if err != nil {
		t.Fatalf("get callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestCallbackRejectsExpiredState(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	state := "expired-callback-state"
	if err := srv.stateStore.Save(context.Background(), State{
		State:       state,
		Verifier:    "verifier",
		RedirectURI: cfg.Elementskin.OAuth.RedirectURI,
		Scope:       defaultScope,
		ExpiresAtMS: time.Now().UTC().Add(-time.Second).UnixMilli(),
	}); err != nil {
		t.Fatalf("seed expired state: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/oauth/callback?code=auth-code-123&state=" + state)
	if err != nil {
		t.Fatalf("get callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHealthAndRootEndpointsStillWork(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("get health: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health status = %d, want 200", resp.StatusCode)
	}
	if string(body) != `{"status":"ok"}` {
		t.Errorf("health body = %q, want {\"status\":\"ok\"}", string(body))
	}

	resp, err = http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("get root: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("root status = %d, want 200", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("root Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	if !strings.Contains(string(body), "Union 角色查询") {
		t.Errorf("root body = %q, want it to contain 'Union 角色查询'", string(body))
	}
}

func TestRootReturns404ForNonRootPaths(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/nonexistent")
	if err != nil {
		t.Fatalf("get /nonexistent: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestOpenStateStoreSetsMaxOpenConnsToOne(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "states.db"))
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	defer store.Close()

	if got := store.db.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1", got)
	}
}

func TestStateStoreCloseOnNilDbIsSafe(t *testing.T) {
	s := &StateStore{}
	if err := s.Close(); err != nil {
		t.Fatalf("Close on nil db: %v", err)
	}
}

func TestStateStoreCloseOnClosedStoreIsSafe(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "states.db"))
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close on closed store: %v", err)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
