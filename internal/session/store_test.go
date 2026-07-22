package session

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openStore creates a Store backed by a temporary SQLite file.
func openStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	s, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func TestStoreCreateAndLookup(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	ctx := context.Background()
	token := "test-access-token"

	sessionID, err := s.Create(ctx, token, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sessionID == "" {
		t.Fatal("Create returned empty sessionID")
	}

	got, err := s.Lookup(ctx, sessionID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != token {
		t.Errorf("Lookup = %q, want %q", got, token)
	}
}

func TestStoreLookupUnknownReturnsEmpty(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	got, err := s.Lookup(context.Background(), "nonexistent-session-id")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != "" {
		t.Errorf("Lookup = %q, want empty", got)
	}
}

func TestStoreLookupExpiredReturnsEmpty(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	ctx := context.Background()
	sessionID, err := s.Create(ctx, "expired-token", -time.Second)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Lookup(ctx, sessionID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != "" {
		t.Errorf("Lookup expired = %q, want empty", got)
	}
}

func TestStoreDeleteRemovesSession(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	ctx := context.Background()
	sessionID, err := s.Create(ctx, "delete-me", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Delete(ctx, sessionID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, err := s.Lookup(ctx, sessionID)
	if err != nil {
		t.Fatalf("Lookup after delete: %v", err)
	}
	if got != "" {
		t.Errorf("Lookup after delete = %q, want empty", got)
	}
}

func TestStoreCleanupExpiredRemovesOnlyExpiredRows(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	ctx := context.Background()

	expiredID, err := s.Create(ctx, "expired-token", -time.Second)
	if err != nil {
		t.Fatalf("Create expired: %v", err)
	}
	validID, err := s.Create(ctx, "valid-token", time.Hour)
	if err != nil {
		t.Fatalf("Create valid: %v", err)
	}

	if err := s.CleanupExpired(ctx); err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}

	gotExpired, err := s.Lookup(ctx, expiredID)
	if err != nil {
		t.Fatalf("Lookup expired: %v", err)
	}
	if gotExpired != "" {
		t.Errorf("expired lookup = %q, want empty", gotExpired)
	}

	gotValid, err := s.Lookup(ctx, validID)
	if err != nil {
		t.Fatalf("Lookup valid: %v", err)
	}
	if gotValid != "valid-token" {
		t.Errorf("valid lookup = %q, want valid-token", gotValid)
	}
}

func TestStoreOpenCreatesDirectory(t *testing.T) {
	deepDir := filepath.Join(t.TempDir(), "nonexistent", "subdir")
	dbPath := filepath.Join(deepDir, "sessions.db")

	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore(%q): %v", dbPath, err)
	}
	defer store.Close()

	info, err := os.Stat(deepDir)
	if err != nil {
		t.Fatalf("stat created directory: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("expected %q to be a directory", deepDir)
	}

	info, err = os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat created db file: %v", err)
	}
	if info.Size() == 0 {
		t.Errorf("expected non-empty db file, got size %d", info.Size())
	}
}

func TestStoreOpenSetsMaxOpenConnsToOne(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "sessions.db"))
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

func TestStoreCreateGeneratesUniqueSessionIDs(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	ctx := context.Background()
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := s.Create(ctx, "token", time.Hour)
		if err != nil {
			t.Fatalf("Create iteration %d: %v", i, err)
		}
		if seen[id] {
			t.Fatalf("duplicate session id generated: %q", id)
		}
		seen[id] = true
	}
}
