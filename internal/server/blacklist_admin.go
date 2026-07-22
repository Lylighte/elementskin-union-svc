package server

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// withAdminAPIKey wraps a handler so it is only invoked when the request
// carries an "Authorization: Bearer {token}" header that matches the
// configured admin API key. The comparison uses crypto/subtle to avoid
// timing side-channels.
func (s *Server) withAdminAPIKey(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeAdminUnauthorized(w)
			return
		}

		token := auth[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Union.AdminAPIKey)) != 1 {
			writeAdminUnauthorized(w)
			return
		}

		fn(w, r)
	}
}

func writeAdminUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": "unauthorized"})
}

// handleBlacklistList proxies GET /api/union/admin/blacklist to the Hub's
// /blacklist/query endpoint, preserving the original query string.
func (s *Server) handleBlacklistList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := "/blacklist/query"
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}

	body, status, err := s.unionClient.ProxyToHub(ctx, http.MethodGet, path, nil)
	if err != nil {
		writeProxyError(w, http.StatusBadGateway, err)
		return
	}
	writeProxyResponse(w, body, status)
}

// handleBlacklistCreate proxies POST /api/union/admin/blacklist to the Hub's
// /blacklist/restful endpoint, forwarding the request body unchanged.
func (s *Server) handleBlacklistCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeProxyError(w, http.StatusBadRequest, err)
		return
	}

	respBody, status, err := s.unionClient.ProxyToHub(ctx, http.MethodPost, "/blacklist/restful", body)
	if err != nil {
		writeProxyError(w, http.StatusBadGateway, err)
		return
	}
	writeProxyResponse(w, respBody, status)
}

// handleBlacklistInvalidate proxies PUT
// /api/union/admin/blacklist/invalidate/{id} to the Hub's
// /blacklist/invalidate/{id} endpoint.
func (s *Server) handleBlacklistInvalidate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	path := "/blacklist/invalidate/" + url.PathEscape(id)

	body, status, err := s.unionClient.ProxyToHub(ctx, http.MethodPut, path, nil)
	if err != nil {
		writeProxyError(w, http.StatusBadGateway, err)
		return
	}
	writeProxyResponse(w, body, status)
}

// handleBlacklistDelete proxies DELETE /api/union/admin/blacklist/{id} to the
// Hub's /blacklist/restful/{id} endpoint.
func (s *Server) handleBlacklistDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	path := "/blacklist/restful/" + url.PathEscape(id)

	body, status, err := s.unionClient.ProxyToHub(ctx, http.MethodDelete, path, nil)
	if err != nil {
		writeProxyError(w, http.StatusBadGateway, err)
		return
	}
	writeProxyResponse(w, body, status)
}

func writeProxyResponse(w http.ResponseWriter, body []byte, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeProxyError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": err.Error()})
}
