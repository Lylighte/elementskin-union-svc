package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// withWebhookVerify wraps a webhook handler with Element-Skin standard
// HMAC-SHA256 signature verification. It replaces the previous Bearer-token
// authentication so that union-svc can receive events from the Element-Skin
// outbound webhook system.
func (s *Server) withWebhookVerify(fn func(http.ResponseWriter, *http.Request, verifiedWebhook)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readRequestBody(r)
		if err != nil {
			writeWebhookError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		tolerance := time.Duration(s.cfg.Union.WebhookTimestampToleranceSeconds) * time.Second
		if tolerance <= 0 {
			tolerance = 5 * time.Minute
		}
		verified, err := verifyWebhook(r, body, s.cfg.Union.WebhookSecret, tolerance, time.Now())
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, errWebhookUnknownType) || errors.Is(err, errWebhookIDMismatch) {
				status = http.StatusBadRequest
			}
			writeWebhookError(w, status, err.Error())
			return
		}

		// Idempotency: deduplicate by Webhook-Id. Element-Skin delivers
		// at-least-once, so a repeated event must not re-sync to the Hub.
		if err := s.webhookStore.Claim(r.Context(), verified.envelope.ID, time.Now()); err != nil {
			if errors.Is(err, ErrWebhookAlreadyProcessed) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]string{"detail": "ok"})
				return
			}
			s.logger.Error("webhook idempotency claim failed", "event_id", verified.envelope.ID, "error", err)
			writeWebhookError(w, http.StatusInternalServerError, "idempotency check failed")
			return
		}

		fn(w, r, verified)
	}
}

func writeWebhookError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": detail})
}

// handleProfileSyncWebhook receives Element-Skin standard profile lifecycle
// events and forwards them to the Union Hub. The event type determines the
// Hub operation:
//
//   - profile.created  → POST /profile {id, name}   (name resolved by lookup)
//   - profile.updated  → PUT  /profile/{uuid} {name} (name resolved by lookup)
//   - profile.deleted  → DELETE /profile/{uuid}      (no lookup needed)
//
// The handler signature accepts the verified webhook payload injected by
// withWebhookVerify.
func (s *Server) handleProfileSyncWebhook(w http.ResponseWriter, r *http.Request, verified verifiedWebhook) {
	ctx := r.Context()
	profileID := verified.data.ProfileID

	switch verified.envelope.Type {
	case "profile.created":
		name, err := s.bridge.GetProfileNameByID(ctx, profileID)
		if err != nil {
			s.logger.Error("webhook profile.created: lookup failed", "profile_id", profileID, "error", err)
			writeWebhookError(w, http.StatusBadGateway, "failed to resolve profile name")
			return
		}
		if name == "" {
			// Profile no longer exists; let Element-Skin retry later.
			s.logger.Warn("webhook profile.created: profile not found", "profile_id", profileID)
			writeWebhookError(w, http.StatusNotFound, "profile not found")
			return
		}
		if err := s.unionClient.SyncProfileAdd(ctx, name, profileID); err != nil {
			s.logger.Error("webhook profile.created: hub sync failed", "profile_id", profileID, "error", err)
			writeWebhookError(w, http.StatusBadGateway, "failed to sync profile")
			return
		}

	case "profile.updated":
		name, err := s.bridge.GetProfileNameByID(ctx, profileID)
		if err != nil {
			s.logger.Error("webhook profile.updated: lookup failed", "profile_id", profileID, "error", err)
			writeWebhookError(w, http.StatusBadGateway, "failed to resolve profile name")
			return
		}
		if name == "" {
			// Profile was deleted between the event and the lookup; treat as
			// a deletion so the Hub stays consistent.
			s.logger.Info("webhook profile.updated: profile gone, treating as delete", "profile_id", profileID)
			if err := s.unionClient.SyncProfileDelete(ctx, profileID); err != nil {
				s.logger.Error("webhook profile.updated: hub delete failed", "profile_id", profileID, "error", err)
				writeWebhookError(w, http.StatusBadGateway, "failed to sync profile")
				return
			}
		} else {
			if err := s.unionClient.SyncProfileUpdate(ctx, profileID, name); err != nil {
				s.logger.Error("webhook profile.updated: hub sync failed", "profile_id", profileID, "error", err)
				writeWebhookError(w, http.StatusBadGateway, "failed to sync profile")
				return
			}
		}

	case "profile.deleted":
		if err := s.unionClient.SyncProfileDelete(ctx, profileID); err != nil {
			s.logger.Error("webhook profile.deleted: hub sync failed", "profile_id", profileID, "error", err)
			writeWebhookError(w, http.StatusBadGateway, "failed to sync profile")
			return
		}

	default:
		writeWebhookError(w, http.StatusBadRequest, "unknown event type")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": "ok"})
}
