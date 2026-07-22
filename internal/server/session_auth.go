package server

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Lylighte/elementskin-union-svc/internal/bridge"
	"github.com/Lylighte/elementskin-union-svc/internal/session"
)

func (s *Server) withSessionCookie(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := session.GetSessionCookie(r)
		if sessionID == "" {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		accessToken, err := s.sessionStore.Lookup(r.Context(), sessionID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to lookup session")
			return
		}
		if accessToken == "" {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		client := bridge.NewElementSkinClient(s.cfg.Elementskin.BaseURL, s.httpClient)
		userInfo, err := client.GetUserInfo(r.Context(), accessToken)
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
		ctx = context.WithValue(ctx, accessTokenKey, accessToken)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) withBearerOrSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			s.withBearerToken(next)(w, r)
			return
		}
		s.withSessionCookie(next)(w, r)
	}
}