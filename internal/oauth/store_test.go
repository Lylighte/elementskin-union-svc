package oauth

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openStore creates a Store backed by a temporary SQLite file.
func openStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	s, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

// TestStoreLoadEmptyReturnsErrNoToken verifies that Load returns ErrNoToken
// when no token has been saved yet.
func TestStoreLoadEmptyReturnsErrNoToken(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	_, err := s.Load(context.Background())
	if !errors.Is(err, ErrNoToken) {
		t.Fatalf("Load on empty store: expected ErrNoToken, got %v", err)
	}
}

// TestStoreOverwriteToken verifies that saving a second token completely
// replaces the first one.
func TestStoreOverwriteToken(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	ctx := context.Background()
	now := time.Now().UTC().UnixMilli()

	// Save first token.
	first := TokenRow{
		GrantID:      "grant-1",
		AccessToken:  "access-first",
		RefreshToken: "refresh-first",
		ExpiresAtMS:  now + 3600_000,
		Scope:        "profile.read.owned",
		CreatedAtMS:  now,
	}
	if err := s.Save(ctx, first); err != nil {
		t.Fatalf("save first token: %v", err)
	}

	// Overwrite with a completely different token.
	second := TokenRow{
		GrantID:      "grant-2",
		AccessToken:  "access-second",
		RefreshToken: "refresh-second",
		ExpiresAtMS:  now + 7200_000,
		Scope:        "profile.create.owned",
		CreatedAtMS:  now + 1000,
	}
	if err := s.Save(ctx, second); err != nil {
		t.Fatalf("save second token: %v", err)
	}

	row, err := s.Load(ctx)
	if err != nil {
		t.Fatalf("load after overwrite: %v", err)
	}

	if row.GrantID != "grant-2" {
		t.Errorf("GrantID = %q, want grant-2", row.GrantID)
	}
	if row.AccessToken != "access-second" {
		t.Errorf("AccessToken = %q, want access-second", row.AccessToken)
	}
	if row.RefreshToken != "refresh-second" {
		t.Errorf("RefreshToken = %q, want refresh-second", row.RefreshToken)
	}
	if row.ExpiresAtMS != now+7200_000 {
		t.Errorf("ExpiresAtMS = %d, want %d", row.ExpiresAtMS, now+7200_000)
	}
	if row.Scope != "profile.create.owned" {
		t.Errorf("Scope = %q, want profile.create.owned", row.Scope)
	}
	if row.CreatedAtMS != now+1000 {
		t.Errorf("CreatedAtMS = %d, want %d", row.CreatedAtMS, now+1000)
	}

	// Verify only one row exists.
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_tokens`).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row after overwrite, got %d", count)
	}
}

// TestStoreOpenCreatesDirectory verifies that OpenStore creates the parent
// directory and the database file when they do not exist.
func TestStoreOpenCreatesDirectory(t *testing.T) {
	// Use a deep path inside a nonexistent directory.
	deepDir := filepath.Join(t.TempDir(), "nonexistent", "subdir")
	dbPath := filepath.Join(deepDir, "tokens.db")

	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore(%q): %v", dbPath, err)
	}
	defer store.Close()

	// Verify the directory was created.
	info, err := os.Stat(deepDir)
	if err != nil {
		t.Fatalf("stat created directory: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("expected %q to be a directory", deepDir)
	}

	// Verify the database file exists.
	info, err = os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat created db file: %v", err)
	}
	if info.Size() == 0 {
		t.Errorf("expected non-empty db file, got size %d", info.Size())
	}

	// Verify the store is functional.
	_, err = store.Load(context.Background())
	if !errors.Is(err, ErrNoToken) {
		t.Fatalf("expected ErrNoToken on fresh store, got %v", err)
	}
}

// TestStoreSaveSetsDefaultCreatedAtMS verifies that Save fills CreatedAtMS
// when it is zero.
func TestStoreOpenSetsMaxOpenConnsToOne(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	if got := store.db.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1", got)
	}
}

func TestStoreCloseOnNilDbIsSafe(t *testing.T) {
	s := &Store{}
	if err := s.Close(); err != nil {
		t.Fatalf("Close on nil db: %v", err)
	}
}

func TestServiceTokenStoreCloseOnNilDbIsSafe(t *testing.T) {
	s := &ServiceTokenStore{}
	if err := s.Close(); err != nil {
		t.Fatalf("Close on nil db: %v", err)
	}
}

func TestStoreSaveSetsDefaultCreatedAtMS(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	ctx := context.Background()
	before := time.Now().UTC().UnixMilli()

	row := TokenRow{
		AccessToken:  "test-access",
		RefreshToken: "test-refresh",
		ExpiresAtMS:  before + 3600_000,
		Scope:        "test",
		// CreatedAtMS is zero — should be set automatically.
	}
	if err := s.Save(ctx, row); err != nil {
		t.Fatalf("save: %v", err)
	}

	stored, err := s.Load(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if stored.CreatedAtMS < before {
		t.Errorf("CreatedAtMS = %d, should be >= %d", stored.CreatedAtMS, before)
	}
}
