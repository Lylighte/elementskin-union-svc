package union

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSettingsStoreSetAndGet(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenSettingsStore(filepath.Join(dir, "settings.db"))
	if err != nil {
		t.Fatalf("open settings store: %v", err)
	}

	ctx := context.Background()
	if err := store.Set(ctx, "member_key", "abc"); err != nil {
		t.Fatalf("set member_key: %v", err)
	}

	got, err := store.Get(ctx, "member_key")
	if err != nil {
		t.Fatalf("get member_key: %v", err)
	}
	if got != "abc" {
		t.Fatalf("expected member_key %q, got %q", "abc", got)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
}

func TestSettingsStoreGetMissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenSettingsStore(filepath.Join(dir, "settings.db"))
	if err != nil {
		t.Fatalf("open settings store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	got, err := store.Get(ctx, "missing_key")
	if err != nil {
		t.Fatalf("get missing key: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty string for missing key, got %q", got)
	}
}

func TestSettingsStorePersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.db")

	ctx := context.Background()
	{
		store, err := OpenSettingsStore(path)
		if err != nil {
			t.Fatalf("open settings store: %v", err)
		}
		if err := store.Set(ctx, "server_list", `[{"name":"hub"}]`); err != nil {
			t.Fatalf("set server_list: %v", err)
		}
		if err := store.Set(ctx, "server_list_version", "3"); err != nil {
			t.Fatalf("set server_list_version: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}

	{
		store, err := OpenSettingsStore(path)
		if err != nil {
			t.Fatalf("reopen settings store: %v", err)
		}
		defer store.Close()

		gotList, err := store.Get(ctx, "server_list")
		if err != nil {
			t.Fatalf("get server_list: %v", err)
		}
		if gotList != `[{"name":"hub"}]` {
			t.Fatalf("expected server_list to persist, got %q", gotList)
		}

		gotVersion, err := store.Get(ctx, "server_list_version")
		if err != nil {
			t.Fatalf("get server_list_version: %v", err)
		}
		if gotVersion != "3" {
			t.Fatalf("expected server_list_version 3, got %q", gotVersion)
		}
	}
}

func TestSettingsStoreOverwrite(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenSettingsStore(filepath.Join(dir, "settings.db"))
	if err != nil {
		t.Fatalf("open settings store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.Set(ctx, "private_key_version", "1"); err != nil {
		t.Fatalf("set version 1: %v", err)
	}
	if err := store.Set(ctx, "private_key_version", "5"); err != nil {
		t.Fatalf("set version 5: %v", err)
	}

	got, err := store.Get(ctx, "private_key_version")
	if err != nil {
		t.Fatalf("get private_key_version: %v", err)
	}
	if got != "5" {
		t.Fatalf("expected version 5 after overwrite, got %q", got)
	}
}
