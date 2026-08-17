package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// webhookEnvelope is the standard Element-Skin webhook event payload.
type webhookEnvelope struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	CreatedAt int64           `json:"created_at"`
	Data      json.RawMessage `json:"data"`
}

// webhookEventData holds the data fields carried by profile events.
type webhookEventData struct {
	UserID    string `json:"user_id"`
	ProfileID string `json:"profile_id"`
}

// verifiedWebhook is the result of a successful webhook verification.
type verifiedWebhook struct {
	envelope webhookEnvelope
	data     webhookEventData
}

// webhook verification errors. They are surfaced as HTTP 401 or 400.
var (
	errWebhookMissingSignature = errors.New("missing or malformed Webhook-Signature header")
	errWebhookMissingTimestamp = errors.New("missing or malformed Webhook-Timestamp header")
	errWebhookInvalidSignature = errors.New("invalid Webhook signature")
	errWebhookStaleTimestamp   = errors.New("Webhook timestamp is outside the allowed tolerance")
	errWebhookIDMismatch       = errors.New("Webhook-Id does not match payload id")
	errWebhookUnknownType      = errors.New("unknown webhook event type")
)

// knownProfileEventTypes is the set of Element-Skin profile events that
// union-svc knows how to handle.
var knownProfileEventTypes = map[string]bool{
	"profile.created": true,
	"profile.updated": true,
	"profile.deleted": true,
}

// verifyWebhook authenticates and parses an Element-Skin standard webhook
// request. It reads the raw body, validates the HMAC-SHA256 signature,
// checks the timestamp freshness, and confirms the event id and type.
//
// The caller must provide the raw request body (already buffered) so that the
// signature is computed over the exact bytes received.
func verifyWebhook(r *http.Request, body []byte, secret string, tolerance time.Duration, now time.Time) (verifiedWebhook, error) {
	timestampStr := r.Header.Get("Webhook-Timestamp")
	if timestampStr == "" {
		return verifiedWebhook{}, errWebhookMissingTimestamp
	}
	timestampMs, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return verifiedWebhook{}, errWebhookMissingTimestamp
	}

	// Timestamp freshness check (millisecond resolution).
	diff := now.UnixMilli() - timestampMs
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance.Milliseconds() {
		return verifiedWebhook{}, errWebhookStaleTimestamp
	}

	// Signature verification: v1=hex(HMAC-SHA256(secret, timestamp + "." + body))
	provided := r.Header.Get("Webhook-Signature")
	expected, err := computeWebhookSignature(secret, timestampStr, body)
	if err != nil {
		return verifiedWebhook{}, err
	}
	if !hmac.Equal([]byte(provided), []byte(expected)) {
		return verifiedWebhook{}, errWebhookInvalidSignature
	}

	// Parse the envelope.
	var env webhookEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return verifiedWebhook{}, fmt.Errorf("decode webhook envelope: %w", err)
	}

	// Webhook-Id must match the payload id.
	headerID := r.Header.Get("Webhook-Id")
	if headerID == "" || headerID != env.ID {
		return verifiedWebhook{}, errWebhookIDMismatch
	}

	// Event type must be a known profile event.
	if !knownProfileEventTypes[env.Type] {
		return verifiedWebhook{}, errWebhookUnknownType
	}

	// Parse the event data.
	var data webhookEventData
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return verifiedWebhook{}, fmt.Errorf("decode webhook data: %w", err)
	}
	if data.ProfileID == "" {
		return verifiedWebhook{}, fmt.Errorf("webhook data missing profile_id")
	}

	return verifiedWebhook{envelope: env, data: data}, nil
}

// computeWebhookSignature returns the canonical "v1=<hex>" signature string
// for the given secret, timestamp, and raw body.
func computeWebhookSignature(secret, timestamp string, body []byte) (string, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(timestamp)); err != nil {
		return "", err
	}
	if _, err := mac.Write([]byte(".")); err != nil {
		return "", err
	}
	if _, err := mac.Write(body); err != nil {
		return "", err
	}
	return "v1=" + hex.EncodeToString(mac.Sum(nil)), nil
}

// signWebhookForTesting computes a webhook signature for use in tests.
func signWebhookForTesting(secret, timestamp string, body []byte) string {
	sig, err := computeWebhookSignature(secret, timestamp, body)
	if err != nil {
		panic(err)
	}
	return sig
}

// readRequestBody reads and returns the full request body, replacing r.Body
// with a buffered copy so downstream handlers can still read it.
func readRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}
