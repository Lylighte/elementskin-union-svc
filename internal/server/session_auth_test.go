package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Lylighte/elementskin-union-svc/internal/bridge"
)

func TestSessionCookieValidSession(t *testing.T) {
	wantUser := bridge.UserInfo{
		ID:          "session-user-id",
		DisplayName: "SessionUser",
		Email:       "session@example.com",
	}
	elementskin := newMockElementSkinUserInfo(t, wantUser)
	defer elementskin.Close()

	cfg := testConfig(elementskin.URL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	token := "session-valid-token"
	sessionID := createSession(t, srv, token)
	cookie := &http.Cookie{Name: testCookieName, Value: sessionID}

	var capturedUser *bridge.UserInfo
	var capturedToken string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, ok := UserInfoFromContext(r.Context())
		if !ok {
			t.Fatal("user info not in context")
		}
		capturedUser = userInfo
		capturedToken = accessTokenFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	rr := serveGet(t, srv.withSessionCookie(next), "/test", []*http.Cookie{cookie})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if capturedUser.ID != wantUser.ID {
		t.Errorf("user id = %q, want %q", capturedUser.ID, wantUser.ID)
	}
	if capturedUser.DisplayName != wantUser.DisplayName {
		t.Errorf("display name = %q, want %q", capturedUser.DisplayName, wantUser.DisplayName)
	}
	if capturedUser.Email != wantUser.Email {
		t.Errorf("email = %q, want %q", capturedUser.Email, wantUser.Email)
	}
	if capturedToken != token {
		t.Errorf("token = %q, want %q", capturedToken, token)
	}
}

func TestSessionCookieNoCookie(t *testing.T) {
	// No element-skin call needed since request should be rejected before any
	// upstream call.
	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected elementskin call to %s", r.URL.Path)
	}))
	defer elementskin.Close()

	cfg := testConfig(elementskin.URL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})

	rr := serveGet(t, srv.withSessionCookie(next), "/test", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rr.Code, rr.Body.String())
	}
	assertDetail(t, rr.Body.String(), "unauthorized")
}

func TestSessionCookieExpiredSession(t *testing.T) {
	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected elementskin call to %s", r.URL.Path)
	}))
	defer elementskin.Close()

	cfg := testConfig(elementskin.URL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	// Use a non-existent session ID — Lookup returns "".
	cookie := &http.Cookie{Name: testCookieName, Value: "non-existent-session-id"}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})

	rr := serveGet(t, srv.withSessionCookie(next), "/test", []*http.Cookie{cookie})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rr.Code, rr.Body.String())
	}
	assertDetail(t, rr.Body.String(), "unauthorized")
}

func TestBearerOrSessionWithBearerToken(t *testing.T) {
	wantUser := bridge.UserInfo{
		ID:          "bearer-user-id",
		DisplayName: "BearerUser",
		Email:       "bearer@example.com",
	}
	elementskin := newMockElementSkinUserInfo(t, wantUser)
	defer elementskin.Close()

	cfg := testConfig(elementskin.URL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	var capturedUser *bridge.UserInfo
	var capturedToken string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, ok := UserInfoFromContext(r.Context())
		if !ok {
			t.Fatal("user info not in context")
		}
		capturedUser = userInfo
		capturedToken = accessTokenFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer bearer-valid-token")
	rr := httptest.NewRecorder()
	srv.withBearerOrSession(next)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if capturedUser.ID != wantUser.ID {
		t.Errorf("user id = %q, want %q", capturedUser.ID, wantUser.ID)
	}
	if capturedUser.DisplayName != wantUser.DisplayName {
		t.Errorf("display name = %q, want %q", capturedUser.DisplayName, wantUser.DisplayName)
	}
	if capturedToken != "bearer-valid-token" {
		t.Errorf("token = %q, want %q", capturedToken, "bearer-valid-token")
	}
}

func TestBearerOrSessionWithCookie(t *testing.T) {
	wantUser := bridge.UserInfo{
		ID:          "bearer-session-user",
		DisplayName: "BearerSessionUser",
		Email:       "bearersession@example.com",
	}
	elementskin := newMockElementSkinUserInfo(t, wantUser)
	defer elementskin.Close()

	cfg := testConfig(elementskin.URL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	token := "bearer-session-token"
	sessionID := createSession(t, srv, token)
	cookie := &http.Cookie{Name: testCookieName, Value: sessionID}

	var capturedUser *bridge.UserInfo
	var capturedToken string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, ok := UserInfoFromContext(r.Context())
		if !ok {
			t.Fatal("user info not in context")
		}
		capturedUser = userInfo
		capturedToken = accessTokenFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	rr := serveGet(t, srv.withBearerOrSession(next), "/test", []*http.Cookie{cookie})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if capturedUser.ID != wantUser.ID {
		t.Errorf("user id = %q, want %q", capturedUser.ID, wantUser.ID)
	}
	if capturedToken != token {
		t.Errorf("token = %q, want %q", capturedToken, token)
	}
}

func TestBearerOrSessionNoAuth(t *testing.T) {
	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected elementskin call to %s", r.URL.Path)
	}))
	defer elementskin.Close()

	cfg := testConfig(elementskin.URL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})

	rr := serveGet(t, srv.withBearerOrSession(next), "/test", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rr.Code, rr.Body.String())
	}
	assertDetail(t, rr.Body.String(), "unauthorized")
}
