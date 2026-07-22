package union

import (
	"path/filepath"
	"testing"
)

func TestOpenNonceStoreSetsMaxOpenConnsToOne(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenNonceStore(filepath.Join(dir, "nonces.db"))
	if err != nil {
		t.Fatalf("OpenNonceStore: %v", err)
	}
	defer store.Close()

	if got := store.db.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1", got)
	}
}

func TestNonceStoreCloseOnNilDbIsSafe(t *testing.T) {
	s := &NonceStore{}
	if err := s.Close(); err != nil {
		t.Fatalf("Close on nil db: %v", err)
	}
}

func TestNonceStoreCloseOnClosedStoreIsSafe(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenNonceStore(filepath.Join(dir, "nonces.db"))
	if err != nil {
		t.Fatalf("OpenNonceStore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close on closed store: %v", err)
	}
}

func TestSettingsStoreCloseOnNilDbIsSafe(t *testing.T) {
	s := &SettingsStore{}
	if err := s.Close(); err != nil {
		t.Fatalf("Close on nil db: %v", err)
	}
}
