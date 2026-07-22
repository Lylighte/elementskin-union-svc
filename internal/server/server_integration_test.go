package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// TestHealthEndpointReturnsStatusOk verifies that GET /health returns HTTP 200
// with the expected JSON body.
func TestHealthEndpointReturnsStatusOk(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("get /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var got map[string]string
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got["status"] != "ok" {
		t.Errorf(`status = %q, want "ok"`, got["status"])
	}

	// Verify exact JSON for consistency.
	if string(body) != `{"status":"ok"}` {
		t.Errorf("body = %q, want {\"status\":\"ok\"}", string(body))
	}
}

// TestListProfilesEndpointWorksWithoutOAuthToken verifies that /api/profiles
// does not require an OAuth token — it queries the Union Hub directly.
func TestListProfilesEndpointWorksWithoutOAuthToken(t *testing.T) {
	// Start a fake Union Hub that returns profiles.
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"uuid":"u1","name":"Steve"}]`))
	}))
	defer hub.Close()

	cfg := testConfig("http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")
	cfg.Union.HubURL = hub.URL
	cfg.Union.MemberKey = "test-key"

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// No OAuth token seeded — the endpoint should still work.
	resp, err := http.Get(ts.URL + "/api/profiles?username=Steve")
	if err != nil {
		t.Fatalf("get /api/profiles: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, string(body))
	}
}

// TestListProfilesEndpointReturns503WhenUnionNotConfigured verifies that
// /api/profiles returns 503 when the Union Hub URL and member key are not set.
func TestListProfilesEndpointReturns503WhenUnionNotConfigured(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")
	// Union.HubURL and Union.MemberKey remain empty — not configured.

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/profiles?username=Steve")
	if err != nil {
		t.Fatalf("get /api/profiles: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 503: %s", resp.StatusCode, string(body))
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["detail"] != "union hub is not configured" {
		t.Errorf("detail = %q, want 'union hub is not configured'", body["detail"])
	}
}
