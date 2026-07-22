package union

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestNonceStoreLogsAndDetectsReplay(t *testing.T) {
	store := openTestNonceStore(t)

	ctx := context.Background()
	if used, err := store.IsUsed(ctx, "nonce-1"); err != nil {
		t.Fatalf("IsUsed failed: %v", err)
	} else if used {
		t.Fatal("fresh nonce should not be used")
	}

	if err := store.LogNonce(ctx, "nonce-1"); err != nil {
		t.Fatalf("LogNonce failed: %v", err)
	}

	if used, err := store.IsUsed(ctx, "nonce-1"); err != nil {
		t.Fatalf("IsUsed failed: %v", err)
	} else if !used {
		t.Fatal("logged nonce should be reported as used")
	}
}

func TestNonceStoreExpiresOldNonces(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open memory sqlite: %v", err)
	}
	defer db.Close()

	store, err := NewNonceStore(db)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	ctx := context.Background()
	old := time.Now().UTC().Add(-2 * nonceTTL).UnixMilli()
	if _, err := db.ExecContext(ctx, `INSERT INTO union_nonces (nonce, created_at_ms) VALUES (?, ?)`, "old-nonce", old); err != nil {
		t.Fatalf("insert old nonce: %v", err)
	}

	if used, err := store.IsUsed(ctx, "old-nonce"); err != nil {
		t.Fatalf("IsUsed failed: %v", err)
	} else if used {
		t.Fatal("expired nonce should not be reported as used")
	}
}
