package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/union"
)

// handleUnionHello is the public hello endpoint for the Union Hub. It returns
// the member API version, current list/key versions, and enabled features.
func (s *Server) handleUnionHello(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	store := s.settingsStore()

	serverListVersion := 0
	if store != nil {
		if v, err := store.Get(ctx, "server_list_version"); err == nil && v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				serverListVersion = n
			}
		}
	}

	privateKeyVersion := 0
	if store != nil {
		if v, err := store.Get(ctx, "private_key_version"); err == nil && v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				privateKeyVersion = n
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if s.cfg.Union.CORSAllowOrigin != "" {
		w.Header().Set("Access-Control-Allow-Origin", s.cfg.Union.CORSAllowOrigin)
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"yggdrasilApiVersion": "union-svc/1.0",
		"serverListVersion":   serverListVersion,
		"privateKeyVersion":   privateKeyVersion,
		"enabledFeatures":     []string{"unionBlacklist"},
	})
}

// handleUpdateList receives an updated server list from the Union Hub,
// fetches the current list, and stores it together with its version.
func (s *Server) handleUpdateList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	servers, version, err := s.unionClient.FetchServerList(ctx)
	if err != nil {
		if hubErr := passThroughHubError(err); hubErr != nil {
			w.WriteHeader(hubErr.Status)
			return
		}
		s.logger.Error("failed to fetch server list", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "failed to fetch server list"})
		return
	}

	store := s.settingsStore()
	if err := store.Set(ctx, "server_list", string(servers)); err != nil {
		s.logger.Error("failed to store server list", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "failed to store server list"})
		return
	}
	if err := store.Set(ctx, "server_list_version", strconv.Itoa(version)); err != nil {
		s.logger.Error("failed to store server list version", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "failed to store server list version"})
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleUpdatePrivateKey receives a new private-key version from the Union Hub,
// records the version, and logs a reminder that the PEM must be replaced manually.
func (s *Server) handleUpdatePrivateKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, version, err := s.unionClient.FetchPrivateKey(ctx)
	if err != nil {
		if hubErr := passThroughHubError(err); hubErr != nil {
			w.WriteHeader(hubErr.Status)
			return
		}
		s.logger.Error("failed to fetch private key", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "failed to fetch private key"})
		return
	}

	store := s.settingsStore()
	if err := store.Set(ctx, "private_key_version", strconv.Itoa(version)); err != nil {
		s.logger.Error("failed to store private key version", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "failed to store private key version"})
		return
	}

	s.logger.Warn(fmt.Sprintf("Union private key updated to version %d. Admin must manually replace PEM in skin-backend.", version))
	w.WriteHeader(http.StatusOK)
}

// handleUpdateBackendKey receives a new member key from the Union Hub and
// persists it to the runtime settings store.
func (s *Server) handleUpdateBackendKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "invalid request body"})
		return
	}

	if err := s.settingsStore().Set(r.Context(), "member_key", req.Key); err != nil {
		s.logger.Error("failed to update member key", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "failed to update member key"})
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleSync triggers a profile synchronization with the Union Hub. The Hub
// may supply a profileList hint in the request body, but it is ignored: the
// member reports its actual local profiles queried via the admin API.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		ProfileList map[string]string `json:"profileList"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "invalid request body"})
		return
	}

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

	w.WriteHeader(http.StatusOK)
}

// handleQueryEmail resolves a profile name to an email address for the Union Hub.
// The username query parameter is the profile/player name, not the user account
// name. Results are not cached.
func (s *Server) handleQueryEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	username := r.URL.Query().Get("username")
	if username == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "username is required"})
		return
	}

	email, err := s.bridge.GetUserEmailByProfileName(ctx, username)
	if err != nil {
		s.logger.Error("failed to query email by profile name", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "failed to query email"})
		return
	}

	if email == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"email": email})
}

// handleDiagnose answers a Hub diagnostic request with the echoed nonce and
// the current Unix timestamp.
func (s *Server) handleDiagnose(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "invalid request body"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"nonce":     req.Nonce,
		"timestamp": float64(time.Now().Unix()),
	})
}

// passThroughHubError extracts a *union.HubError from a wrapped error so that
// inbound handlers can mirror the Hub's HTTP status without adding their own body.
func passThroughHubError(err error) *union.HubError {
	var hubErr *union.HubError
	if errors.As(err, &hubErr) {
		return hubErr
	}
	return nil
}
