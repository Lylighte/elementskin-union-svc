package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Lylighte/elementskin-union-svc/internal/bridge"
)

type ctxKey int

const userInfoKey ctxKey = 0

// UserInfoFromContext returns the authenticated Element-Skin user stored by
// withBearerToken. The second result reports whether a user was present.
func UserInfoFromContext(ctx context.Context) (*bridge.UserInfo, bool) {
	ui, ok := ctx.Value(userInfoKey).(*bridge.UserInfo)
	return ui, ok
}

// withBearerToken validates the Authorization: Bearer header against
// Element-Skin and, on success, stores the resulting *bridge.UserInfo in the
// request context before calling next.
func (s *Server) withBearerToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		token := strings.TrimPrefix(auth, prefix)

		client := bridge.NewElementSkinClient(s.cfg.Elementskin.BaseURL, s.httpClient)
		userInfo, err := client.GetUserInfo(r.Context(), token)
		if err != nil {
			var apiErr *bridge.APIError
			if errors.As(err, &apiErr) {
				if apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden {
					writeJSONError(w, http.StatusUnauthorized, "unauthorized")
					return
				}
				writeJSONError(w, http.StatusInternalServerError, "failed to validate token")
				return
			}
			writeJSONError(w, http.StatusBadGateway, "upstream unavailable")
			return
		}

		ctx := context.WithValue(r.Context(), userInfoKey, userInfo)
		next(w, r.WithContext(ctx))
	}
}

// handleProfileBind proxies a bearer-authenticated bind request to the Union
// Hub. The request body must contain a non-empty uuid.
func (s *Server) handleProfileBind(w http.ResponseWriter, r *http.Request) {
	uuid, ok := decodeUUID(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "uuid is required")
		return
	}

	body, status, err := s.unionClient.ProfileBind(r.Context(), uuid)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "upstream unavailable")
		return
	}
	writeRawResponse(w, body, status)
}

// handleProfileUnbind proxies a bearer-authenticated unbind request to the
// Union Hub. The request body must contain a non-empty uuid.
func (s *Server) handleProfileUnbind(w http.ResponseWriter, r *http.Request) {
	uuid, ok := decodeUUID(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "uuid is required")
		return
	}

	body, status, err := s.unionClient.ProfileUnbind(r.Context(), uuid)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "upstream unavailable")
		return
	}
	writeRawResponse(w, body, status)
}

// handleProfileBindTo proxies a bearer-authenticated bindto request to the
// Union Hub. The request body must contain a non-empty uuid and token.
func (s *Server) handleProfileBindTo(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UUID  string `json:"uuid"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "uuid is required")
		return
	}
	if req.UUID == "" {
		writeJSONError(w, http.StatusBadRequest, "uuid is required")
		return
	}
	if req.Token == "" {
		writeJSONError(w, http.StatusBadRequest, "token is required")
		return
	}

	body, status, err := s.unionClient.ProfileBindTo(r.Context(), req.UUID, req.Token)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "upstream unavailable")
		return
	}
	writeRawResponse(w, body, status)
}

// handleSecurityLevel returns the Union security level for the authenticated
// Element-Skin user, using DisplayName as the username.
func (s *Server) handleSecurityLevel(w http.ResponseWriter, r *http.Request) {
	userInfo, ok := UserInfoFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "failed to get security level")
		return
	}

	level, err := s.unionClient.GetSecurityLevel(r.Context(), userInfo.DisplayName)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to get security level")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"level": level})
}

func decodeUUID(r *http.Request) (string, bool) {
	var req struct {
		UUID string `json:"uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return "", false
	}
	if req.UUID == "" {
		return "", false
	}
	return req.UUID, true
}

func writeJSONError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": detail})
}

func writeRawResponse(w http.ResponseWriter, body []byte, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}
