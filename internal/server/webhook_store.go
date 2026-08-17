package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// webhookProcessedRetention is how long a processed-event record is kept
// before cleanup. Element-Skin retries for up to 72 hours, so we retain
// records slightly longer to cover the full retry window.
const webhookProcessedRetention = 7 * 24 * time.Hour

// ErrWebhookAlreadyProcessed is returned when a webhook event id has already
// been successfully processed.
var ErrWebhookAlreadyProcessed = errors.New("webhook event already processed")

// WebhookStore persists processed webhook event ids in SQLite for idempotent
// delivery handling. Element-Skin delivers webhooks at-least-once, so the
// receiver must deduplicate by Webhook-Id.
type WebhookStore struct {
	db *sql.DB
}

// NewWebhookStore wraps an existing *sql.DB and ensures the schema exists.
// It shares the same SQLite database file as the other stores.
func NewWebhookStore(db *sql.DB) (*WebhookStore, error) {
	s := &WebhookStore{db: db}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *WebhookStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS webhook_processed (
			event_id TEXT PRIMARY KEY,
			processed_at_ms INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create webhook_processed table: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_webhook_processed_at
		ON webhook_processed (processed_at_ms)
	`)
	if err != nil {
		return fmt.Errorf("create webhook_processed index: %w", err)
	}
	return nil
}

// Claim atomically records eventID as processed. If eventID was already
// recorded, it returns ErrWebhookAlreadyProcessed. Expired entries are
// cleaned up opportunistically.
func (s *WebhookStore) Claim(ctx context.Context, eventID string, now time.Time) error {
	// Opportunistic cleanup of expired entries.
	cutoff := now.Add(-webhookProcessedRetention).UnixMilli()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM webhook_processed WHERE processed_at_ms < ?`, cutoff); err != nil {
		return fmt.Errorf("cleanup expired webhook records: %w", err)
	}

	result, err := s.db.ExecContext(ctx, `INSERT INTO webhook_processed (event_id, processed_at_ms) VALUES (?, ?)`, eventID, now.UnixMilli())
	if err != nil {
		// SQLite returns a UNIQUE constraint violation for duplicate event_id.
		return ErrWebhookAlreadyProcessed
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check webhook claim rows affected: %w", err)
	}
	if n == 0 {
		return ErrWebhookAlreadyProcessed
	}
	return nil
}
