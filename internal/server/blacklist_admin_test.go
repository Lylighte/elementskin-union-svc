package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

const adminAPIKey = "admin-secret-key"

func setupBlacklistAdminServer(t *testing.T, hubHandler http.HandlerFunc) *httptest.Server {
	t.Helper()

	hub := httptest.NewServer(hubHandler)
	t.Cleanup(hub.Close)

	cfg := testConfig("http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")
	cfg.Union.HubURL = hub.URL
	cfg.Union.MemberKey = "member-key"
	cfg.Union.AdminAPIKey = adminAPIKey
	cfg.Union.WebhookSecret = "webhook-secret"

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/union/admin/blacklist", srv.withAdminAPIKey(srv.handleBlacklistList))
	mux.HandleFunc("POST /api/union/admin/blacklist", srv.withAdminAPIKey(srv.handleBlacklistCreate))
	mux.HandleFunc("PUT /api/union/admin/blacklist/invalidate/{id}", srv.withAdminAPIKey(srv.handleBlacklistInvalidate))
	mux.HandleFunc("DELETE /api/union/admin/blacklist/{id}", srv.withAdminAPIKey(srv.handleBlacklistDelete))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestBlacklistListRejectsMissingAuthorization(t *testing.T) {
	ts := setupBlacklistAdminServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected hub call to %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})

	resp, err := http.Get(ts.URL + "/api/union/admin/blacklist")
	if err != nil {
		t.Fatalf("get blacklist: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	assertDetailBody(t, resp.Body, "unauthorized")
}

func TestBlacklistListForwardsQueryParamsAndReturnsRawResponse(t *testing.T) {
	var gotMethod, gotPath, gotRawQuery, gotMemberKey string
	ts := setupBlacklistAdminServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotRawQuery = r.URL.RawQuery
		gotMemberKey = r.Header.Get("X-Union-Member-Key")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[{"id":1}],"has_next":false}`))
	})

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/union/admin/blacklist?status=active&page_size=10", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminAPIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get blacklist: %v", err)
	}
	defer resp.Body.Close()

	if gotMethod != http.MethodGet {
		t.Errorf("hub method = %q, want GET", gotMethod)
	}
	if gotPath != "/blacklist/query" {
		t.Errorf("hub path = %q, want /blacklist/query", gotPath)
	}
	if gotRawQuery != "status=active&page_size=10" {
		t.Errorf("hub query = %q, want status=active&page_size=10", gotRawQuery)
	}
	if gotMemberKey != "member-key" {
		t.Errorf("hub member key = %q, want member-key", gotMemberKey)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, string(body))
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"items":[{"id":1}],"has_next":false}` {
		t.Errorf("body = %q, want raw hub response", string(body))
	}
}

func TestBlacklistCreateForwardsBodyToHub(t *testing.T) {
	var gotMethod, gotPath, gotMemberKey string
	var gotBody []byte
	ts := setupBlacklistAdminServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotMemberKey = r.Header.Get("X-Union-Member-Key")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":42}`))
	})

	reqBody := `{"type":"email","value":"bad@example.com","reason":"spam"}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/union/admin/blacklist", bytes.NewReader([]byte(reqBody)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post blacklist: %v", err)
	}
	defer resp.Body.Close()

	if gotMethod != http.MethodPost {
		t.Errorf("hub method = %q, want POST", gotMethod)
	}
	if gotPath != "/blacklist/restful" {
		t.Errorf("hub path = %q, want /blacklist/restful", gotPath)
	}
	if gotMemberKey != "member-key" {
		t.Errorf("hub member key = %q, want member-key", gotMemberKey)
	}
	if string(gotBody) != reqBody {
		t.Errorf("hub body = %q, want %q", string(gotBody), reqBody)
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 201: %s", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"id":42}` {
		t.Errorf("body = %q, want raw hub response", string(body))
	}
}

func TestBlacklistInvalidateForwardsID(t *testing.T) {
	var gotMethod, gotPath string
	ts := setupBlacklistAdminServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"invalidated":true}`))
	})

	req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/union/admin/blacklist/invalidate/42", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminAPIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put invalidate: %v", err)
	}
	defer resp.Body.Close()

	if gotMethod != http.MethodPut {
		t.Errorf("hub method = %q, want PUT", gotMethod)
	}
	if gotPath != "/blacklist/invalidate/42" {
		t.Errorf("hub path = %q, want /blacklist/invalidate/42", gotPath)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, string(body))
	}
}

func TestBlacklistDeleteForwardsID(t *testing.T) {
	var gotMethod, gotPath string
	ts := setupBlacklistAdminServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})

	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/union/admin/blacklist/42", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminAPIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete blacklist: %v", err)
	}
	defer resp.Body.Close()

	if gotMethod != http.MethodDelete {
		t.Errorf("hub method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/blacklist/restful/42" {
		t.Errorf("hub path = %q, want /blacklist/restful/42", gotPath)
	}
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 204: %s", resp.StatusCode, string(body))
	}
}

func TestBlacklistRejectsWrongAPIKey(t *testing.T) {
	ts := setupBlacklistAdminServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected hub call to %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/union/admin/blacklist", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer wrong-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get blacklist: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	assertDetailBody(t, resp.Body, "unauthorized")
}

func TestBlacklistHubErrorPassedThrough(t *testing.T) {
	ts := setupBlacklistAdminServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"hub database error"}`))
	})

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/union/admin/blacklist", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminAPIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get blacklist: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"detail":"hub database error"}` {
		t.Errorf("body = %q, want raw hub error body", string(body))
	}
}

func assertDetailBody(t *testing.T, body io.Reader, want string) {
	t.Helper()
	var got map[string]string
	if err := json.NewDecoder(body).Decode(&got); err != nil {
		t.Fatalf("decode detail body: %v", err)
	}
	if got["detail"] != want {
		t.Errorf("detail = %q, want %q", got["detail"], want)
	}
}
