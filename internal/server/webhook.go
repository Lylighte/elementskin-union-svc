package server

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
)

// withWebhookSecret wraps a webhook handler with Bearer token verification.
// The token is compared to cfg.Union.WebhookSecret using a constant-time
// comparison to avoid timing attacks.
func (s *Server) withWebhookSecret(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeWebhookUnauthorized(w)
			return
		}

		token := auth[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Union.WebhookSecret)) != 1 {
			writeWebhookUnauthorized(w)
			return
		}

		fn(w, r)
	}
}

func writeWebhookUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": "unauthorized"})
}

// handleProfileSyncWebhook receives profile lifecycle events from Element-Skin
// and forwards them to the Union Hub.
func (s *Server) handleProfileSyncWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		Action string `json:"action"`
		Name   string `json:"name"`
		UUID   string `json:"uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "invalid request body"})
		return
	}

	switch req.Action {
	case "add":
		if err := s.unionClient.SyncProfileAdd(ctx, req.Name, req.UUID); err != nil {
			s.logger.Error("failed to sync profile add", "error", err)
			writeWebhookSyncError(w)
			return
		}
	case "update":
		if err := s.unionClient.SyncProfileUpdate(ctx, req.UUID, req.Name); err != nil {
			s.logger.Error("failed to sync profile update", "error", err)
			writeWebhookSyncError(w)
			return
		}
	case "delete":
		if err := s.unionClient.SyncProfileDelete(ctx, req.UUID); err != nil {
			s.logger.Error("failed to sync profile delete", "error", err)
			writeWebhookSyncError(w)
			return
		}
	case "full_sync", "":
		profiles, err := s.bridge.ListAllProfilesForSync(ctx)
		if err != nil {
			s.logger.Error("failed to query local profiles for sync", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "failed to query local profiles"})
			return
		}

		profileList := make(map[string]string, len(profiles))
		for _, p := range profiles {
			profileList[p.Name] = p.ID
		}

		if err := s.unionClient.SyncProfiles(ctx, profileList); err != nil {
			if hubErr := passThroughHubError(err); hubErr != nil {
				w.WriteHeader(hubErr.Status)
				return
			}
			s.logger.Error("failed to sync profiles with hub", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "failed to sync profiles with hub"})
			return
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "unknown action"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": "ok"})
}

func writeWebhookSyncError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": "failed to sync profile"})
}
