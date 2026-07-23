package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"github.com/Lylighte/elementskin-union-svc/internal/union"
)

func (s *Server) handleAdminSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	profiles, err := s.bridge.ListAllProfilesForSync(ctx)
	if err != nil {
		s.logger.Error("admin sync: failed to list profiles", "error", err)
		writeJSONError(w, http.StatusBadGateway, "failed to query local profiles")
		return
	}

	profileList := make(map[string]string, len(profiles))
	for _, p := range profiles {
		profileList[p.Name] = p.ID
	}

	if err := s.unionClient.SyncProfiles(ctx, profileList); err != nil {
		s.logger.Error("admin sync: failed to sync with hub", "error", err)
		writeJSONError(w, http.StatusBadGateway, "failed to sync profiles with hub")
		return
	}

	s.logger.Info("admin sync", "count", len(profiles), "ip", clientIP(r))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"synced": len(profiles), "detail": "ok"})
}

func (s *Server) handleAdminUpdateList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, version, err := s.unionClient.FetchServerList(ctx)
	if err != nil {
		s.logger.Error("admin update-list: fetch failed", "error", err)
		writeJSONError(w, http.StatusBadGateway, "failed to fetch server list")
		return
	}

	_ = s.settingsStore().Set(ctx, "server_list_version", strconv.Itoa(version))
	s.logger.Info("admin update-list", "version", version, "ip", clientIP(r))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"version": version})
}

func (s *Server) handleAdminUpdateKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, version, err := s.unionClient.FetchPrivateKey(ctx)
	if err != nil {
		s.logger.Error("admin update-key: fetch failed", "error", err)
		writeJSONError(w, http.StatusBadGateway, "failed to fetch private key")
		return
	}

	_ = s.settingsStore().Set(ctx, "private_key_version", strconv.Itoa(version))
	s.logger.Info("admin update-key", "version", version, "ip", clientIP(r))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"version": version})
}

func (s *Server) handleAdminDiagnose(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	body, status, err := s.unionClient.ProxyToHub(ctx, http.MethodPost, "/diagnose", nil)
	if err != nil {
		s.logger.Error("admin diagnose: failed", "error", err)
		writeJSONError(w, http.StatusBadGateway, "failed to diagnose")
		return
	}
	s.logger.Info("admin diagnose", "ip", clientIP(r))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	settings := s.settingsStore()

	memberKey := ""
	if settings != nil {
		if v, err := settings.Get(ctx, "member_key"); err == nil {
			memberKey = v
		}
	}

	serverlistVersion := 0
	if settings != nil {
		if v, err := settings.Get(ctx, "server_list_version"); err == nil {
			if n, err := strconv.Atoi(v); err == nil {
				serverlistVersion = n
			}
		}
	}

	privatekeyVersion := 0
	if settings != nil {
		if v, err := settings.Get(ctx, "private_key_version"); err == nil {
			if n, err := strconv.Atoi(v); err == nil {
				privatekeyVersion = n
			}
		}
	}

	hubReachable := false
	if _, _, err := s.unionClient.FetchServerList(ctx); err == nil {
		hubReachable = true
	}

	resp := map[string]any{
		"member_key_configured": memberKey != "",
		"serverlist_version":    serverlistVersion,
		"privatekey_version":    privatekeyVersion,
		"hub_reachable":         hubReachable,
		"oauth2_enabled":        s.cfg.Union.EnableOAuth2,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleAdminKeypairFingerprint(w http.ResponseWriter, r *http.Request) {
	pubPath := s.cfg.Union.OAuth2SigPublicKeyPath
	data, err := os.ReadFile(pubPath)
	if err != nil {
		s.logger.Error("admin keypair-fingerprint: read failed", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "failed to read public key")
		return
	}

	hash := sha256.Sum256(data)
	fingerprint := "sha256:" + hex.EncodeToString(hash[:])
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"fingerprint": fingerprint})
}

func (s *Server) handleAdminRegenerateKeypair(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Confirm bool `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !req.Confirm {
		writeJSONError(w, http.StatusBadRequest, "confirm is required to regenerate keypair")
		return
	}

	privPath := s.cfg.Union.OAuth2SigPrivateKeyPath
	pubPath := s.cfg.Union.OAuth2SigPublicKeyPath

	oldPriv, privErr := os.ReadFile(privPath)
	oldPub, pubErr := os.ReadFile(pubPath)
	hadOld := privErr == nil && pubErr == nil

	_ = os.Remove(privPath)
	_ = os.Remove(pubPath)

	ctx := r.Context()
	if _, _, err := union.EnsureSigKeyPair(ctx, privPath, pubPath); err != nil {
		s.logger.Error("admin regenerate-keypair: generation failed", "error", err)
		if hadOld {
			_ = os.WriteFile(privPath, oldPriv, 0600)
			_ = os.WriteFile(pubPath, oldPub, 0644)
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to regenerate keypair")
		return
	}

	data, err := os.ReadFile(pubPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to read new public key")
		return
	}
	hash := sha256.Sum256(data)
	fingerprint := "sha256:" + hex.EncodeToString(hash[:])

	s.logger.Warn("admin regenerate-keypair", "ip", clientIP(r), "success", true)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"fingerprint": fingerprint})
}
