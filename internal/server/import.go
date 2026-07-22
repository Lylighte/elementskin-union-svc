package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Lylighte/elementskin-union-svc/internal/union"
)

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		writeDetail(w, http.StatusBadRequest, "username is required")
		return
	}

	items, err := s.bridge.ListProfiles(r.Context(), username)
	if err != nil {
		s.logger.Error("failed to list union profiles", "error", err)
		if errors.Is(err, union.ErrUnionNotConfigured) {
			writeDetail(w, http.StatusServiceUnavailable, "union hub is not configured")
			return
		}
		writeDetail(w, http.StatusBadGateway, "failed to list union profiles")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
}

func writeDetail(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"detail": detail})
}
