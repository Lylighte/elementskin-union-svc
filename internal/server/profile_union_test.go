package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/bridge"
	"github.com/Lylighte/elementskin-union-svc/internal/config"
	"github.com/Lylighte/elementskin-union-svc/internal/union"
)

func newProfileUnionTestServer(t *testing.T, esHandler, hubHandler http.HandlerFunc) (*Server, *httptest.Server, *httptest.Server) {
	t.Helper()
	if esHandler == nil {
		esHandler = func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected Element-Skin call to %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
	if hubHandler == nil {
		hubHandler = func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected Hub call to %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}

	es := httptest.NewServer(esHandler)
	t.Cleanup(es.Close)
	hub := httptest.NewServer(hubHandler)
	t.Cleanup(hub.Close)

	var cfg config.Config
	cfg.Elementskin.BaseURL = es.URL
	s := &Server{
		cfg:         cfg,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
		unionClient: union.NewClientWithDeps(hub.URL, "member-key", 5, &http.Client{Timeout: 5 * time.Second}, nil, nil),
	}
	return s, es, hub
}

func assertStatus(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Errorf("status = %d, want %d, body = %s", rr.Code, want, rr.Body.String())
	}
}

func assertDetailResponse(t *testing.T, rr *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body["detail"] != want {
		t.Errorf("detail = %q, want %q", body["detail"], want)
	}
}

func assertJSONField(t *testing.T, rr *httptest.ResponseRecorder, key string, want any) {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body[key] != want {
		t.Errorf("%s = %v, want %v", key, body[key], want)
	}
}

func validElementSkinHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(bridge.UserInfo{DisplayName: "alice"})
	}
}

func TestProfileBindRejectsMissingAuthorization(t *testing.T) {
	s, _, _ := newProfileUnionTestServer(t, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/union/profile/bind", strings.NewReader(`{"uuid":"u1"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.withBearerToken(s.handleProfileBind)(rr, req)

	assertStatus(t, rr, http.StatusUnauthorized)
	assertDetailResponse(t, rr, "unauthorized")
}

func TestProfileBindWithValidTokenCallsProfileBindAndReturnsHubResponse(t *testing.T) {
	var capturedUUID string
	hubHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/profile/bind" {
			t.Errorf("hub path = %q, want /profile/bind", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("hub method = %q, want POST", r.Method)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		capturedUUID = body["uuid"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"hub-token-123"}`))
	}

	s, _, _ := newProfileUnionTestServer(t, validElementSkinHandler(), hubHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/union/profile/bind", strings.NewReader(`{"uuid":"profile-uuid"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	s.withBearerToken(s.handleProfileBind)(rr, req)

	assertStatus(t, rr, http.StatusOK)
	assertJSONField(t, rr, "token", "hub-token-123")
	if capturedUUID != "profile-uuid" {
		t.Errorf("captured uuid = %q, want profile-uuid", capturedUUID)
	}
}

func TestProfileBindWithInvalidTokenReturnsUnauthorized(t *testing.T) {
	esHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "invalid token"})
	}

	s, _, _ := newProfileUnionTestServer(t, esHandler, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/union/profile/bind", strings.NewReader(`{"uuid":"u1"}`))
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()

	s.withBearerToken(s.handleProfileBind)(rr, req)

	assertStatus(t, rr, http.StatusUnauthorized)
	assertDetailResponse(t, rr, "unauthorized")
}

func TestProfileUnbindCallsProfileUnbind(t *testing.T) {
	var capturedUUID string
	hubHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/profile/unbind" {
			t.Errorf("hub path = %q, want /profile/unbind", r.URL.Path)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		capturedUUID = body["uuid"]
		w.WriteHeader(http.StatusNoContent)
	}

	s, _, _ := newProfileUnionTestServer(t, validElementSkinHandler(), hubHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/union/profile/unbind", strings.NewReader(`{"uuid":"unbind-uuid"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	s.withBearerToken(s.handleProfileUnbind)(rr, req)

	assertStatus(t, rr, http.StatusNoContent)
	if capturedUUID != "unbind-uuid" {
		t.Errorf("captured uuid = %q, want unbind-uuid", capturedUUID)
	}
}

func TestProfileBindToForwardsUUIDAndToken(t *testing.T) {
	var capturedUUID, capturedToken string
	hubHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/profile/bindto" {
			t.Errorf("hub path = %q, want /profile/bindto", r.URL.Path)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		capturedUUID = body["uuid"]
		capturedToken = body["token"]
		_, _ = w.Write([]byte(`{"ok":true}`))
	}

	s, _, _ := newProfileUnionTestServer(t, validElementSkinHandler(), hubHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/union/profile/bindto", strings.NewReader(`{"uuid":"bindto-uuid","token":"bindto-token"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	s.withBearerToken(s.handleProfileBindTo)(rr, req)

	assertStatus(t, rr, http.StatusOK)
	assertJSONField(t, rr, "ok", true)
	if capturedUUID != "bindto-uuid" {
		t.Errorf("captured uuid = %q, want bindto-uuid", capturedUUID)
	}
	if capturedToken != "bindto-token" {
		t.Errorf("captured token = %q, want bindto-token", capturedToken)
	}
}

func TestSecurityLevelReturnsLevel(t *testing.T) {
	hubHandler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/code":
			_, _ = w.Write([]byte(`{"code":"sec-code-123"}`))
		case "/backend/sec-code-123/security/level":
			_, _ = w.Write([]byte(`3`))
		default:
			t.Errorf("unexpected hub path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}

	s, _, _ := newProfileUnionTestServer(t, validElementSkinHandler(), hubHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/union/security/level", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	s.withBearerToken(s.handleSecurityLevel)(rr, req)

	assertStatus(t, rr, http.StatusOK)
	assertJSONField(t, rr, "level", float64(3))
}

func TestProfileBindRejectsMissingUUID(t *testing.T) {
	s, _, _ := newProfileUnionTestServer(t, validElementSkinHandler(), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/union/profile/bind", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	s.withBearerToken(s.handleProfileBind)(rr, req)

	assertStatus(t, rr, http.StatusBadRequest)
	assertDetailResponse(t, rr, "uuid is required")
}

func TestProfileBindPassesThroughHubErrorStatus(t *testing.T) {
	hubHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"hub exploded"}`))
	}

	s, _, _ := newProfileUnionTestServer(t, validElementSkinHandler(), hubHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/union/profile/bind", strings.NewReader(`{"uuid":"u1"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	s.withBearerToken(s.handleProfileBind)(rr, req)

	assertStatus(t, rr, http.StatusInternalServerError)
	assertDetailResponse(t, rr, "hub exploded")
}

func TestProfileBindWithElementSkin500ReturnsTokenValidationError(t *testing.T) {
	esHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "database error"})
	}

	s, _, _ := newProfileUnionTestServer(t, esHandler, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/union/profile/bind", strings.NewReader(`{"uuid":"u1"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	s.withBearerToken(s.handleProfileBind)(rr, req)

	assertStatus(t, rr, http.StatusInternalServerError)
	assertDetailResponse(t, rr, "failed to validate token")
}

func TestProfileBindToRejectsMissingToken(t *testing.T) {
	s, _, _ := newProfileUnionTestServer(t, validElementSkinHandler(), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/union/profile/bindto", strings.NewReader(`{"uuid":"u1"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	s.withBearerToken(s.handleProfileBindTo)(rr, req)

	assertStatus(t, rr, http.StatusBadRequest)
	assertDetailResponse(t, rr, "token is required")
}

func TestSecurityLevelReturnsErrorWhenHubFails(t *testing.T) {
	hubHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}

	s, _, _ := newProfileUnionTestServer(t, validElementSkinHandler(), hubHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/union/security/level", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	s.withBearerToken(s.handleSecurityLevel)(rr, req)

	assertStatus(t, rr, http.StatusInternalServerError)
	assertDetailResponse(t, rr, "failed to get security level")
}

func TestProfileBindWithElementSkinTransportErrorReturnsBadGateway(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	es.Close()

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected hub call to %s", r.URL.Path)
	}))
	defer hub.Close()

	var cfg config.Config
	cfg.Elementskin.BaseURL = es.URL
	s := &Server{
		cfg:         cfg,
		httpClient:  &http.Client{Timeout: 100 * time.Millisecond},
		unionClient: union.NewClientWithDeps(hub.URL, "member-key", 5, &http.Client{Timeout: 5 * time.Second}, nil, nil),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/union/profile/bind", strings.NewReader(`{"uuid":"u1"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	s.withBearerToken(s.handleProfileBind)(rr, req)

	assertStatus(t, rr, http.StatusBadGateway)
	assertDetailResponse(t, rr, "upstream unavailable")
}
