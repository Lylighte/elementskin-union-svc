package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const webhookSecret = "test-webhook-secret"

// newWebhookTestServer creates a Server wired to mock Hub and Element-Skin
// servers with the webhook secret configured. The webhook route is registered
// manually because server.go wiring belongs to Todo 10.
func newWebhookTestServer(t *testing.T, hub, elementskin *httptest.Server) *Server {
	t.Helper()

	cfg := testConfig(elementskin.URL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")
	cfg.Union.HubURL = hub.URL
	cfg.Union.MemberKey = "test-member-key"
	cfg.Union.WebhookSecret = webhookSecret
	cfg.Elementskin.ServiceAccount.ClientID = "svc-client-id"
	cfg.Elementskin.ServiceAccount.ClientSecret = "svc-client-secret"

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	return srv
}

func postWebhook(t *testing.T, ts *httptest.Server, auth, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/union/webhook/profile-sync", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func assertWebhookDetail(t *testing.T, body io.Reader, want string) {
	t.Helper()

	var got map[string]string
	if err := json.NewDecoder(body).Decode(&got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got["detail"] != want {
		t.Errorf("detail = %q, want %q", got["detail"], want)
	}
}

func TestWebhookNoAuthorizationReturns401(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("hub should not be called without authorization")
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called without authorization")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, "", `{"action":"add","name":"Steve","uuid":"uuid-1"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 401: %s", resp.StatusCode, string(body))
	}
	assertWebhookDetail(t, resp.Body, "unauthorized")
}

func TestWebhookWrongSecretReturns401(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("hub should not be called with wrong secret")
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called with wrong secret")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, "Bearer wrong-secret", `{"action":"add","name":"Steve","uuid":"uuid-1"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 401: %s", resp.StatusCode, string(body))
	}
	assertWebhookDetail(t, resp.Body, "unauthorized")
}

func TestWebhookAddCallsSyncProfileAdd(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]string

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode hub body: %v", err)
		}
		if got := r.Header.Get("X-Union-Member-Key"); got != "test-member-key" {
			t.Errorf("member key = %q, want test-member-key", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called for add action")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, "Bearer "+webhookSecret, `{"action":"add","name":"Steve","uuid":"uuid-1"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, string(body))
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/profile" {
		t.Errorf("path = %q, want /profile", gotPath)
	}
	if gotBody["id"] != "uuid-1" || gotBody["name"] != "Steve" {
		t.Errorf("body = %v, want id=uuid-1 name=Steve", gotBody)
	}
	assertWebhookDetail(t, resp.Body, "ok")
}

func TestWebhookUpdateCallsSyncProfileUpdate(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]string

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode hub body: %v", err)
		}
		if got := r.Header.Get("X-Union-Member-Key"); got != "test-member-key" {
			t.Errorf("member key = %q, want test-member-key", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called for update action")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, "Bearer "+webhookSecret, `{"action":"update","name":"SteveNew","uuid":"uuid-1"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, string(body))
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/profile/uuid-1" {
		t.Errorf("path = %q, want /profile/uuid-1", gotPath)
	}
	if gotBody["name"] != "SteveNew" {
		t.Errorf("body name = %q, want SteveNew", gotBody["name"])
	}
	assertWebhookDetail(t, resp.Body, "ok")
}

func TestWebhookDeleteCallsSyncProfileDelete(t *testing.T) {
	var gotMethod, gotPath string

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if got := r.Header.Get("X-Union-Member-Key"); got != "test-member-key" {
			t.Errorf("member key = %q, want test-member-key", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called for delete action")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, "Bearer "+webhookSecret, `{"action":"delete","uuid":"uuid-1"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, string(body))
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/profile/uuid-1" {
		t.Errorf("path = %q, want /profile/uuid-1", gotPath)
	}
	assertWebhookDetail(t, resp.Body, "ok")
}

func TestWebhookFullSyncQueriesElementSkinAndSyncsProfiles(t *testing.T) {
	profiles := []map[string]any{
		{"id": "uuid-1", "name": "Steve", "user_id": "u1", "owner_email": "steve@example.com"},
		{"id": "uuid-2", "name": "Alex", "user_id": "u2", "owner_email": "alex@example.com"},
	}

	var gotHubBody map[string]any
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sync" {
			t.Errorf("hub path = %q, want /sync", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("X-Union-Member-Key"); got != "test-member-key" {
			t.Errorf("member key = %q, want test-member-key", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotHubBody); err != nil {
			t.Errorf("decode hub body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hub.Close()

	elementskin := elementskinAdminServer(t, profiles, http.StatusOK)
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, "Bearer "+webhookSecret, `{"action":"full_sync"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, string(body))
	}

	profileList, ok := gotHubBody["profileList"].(map[string]any)
	if !ok {
		t.Fatalf("profileList = %v, want map", gotHubBody["profileList"])
	}
	if len(profileList) != 2 || profileList["Steve"] != "uuid-1" || profileList["Alex"] != "uuid-2" {
		t.Errorf("profileList = %v, want Steve=uuid-1 Alex=uuid-2", profileList)
	}
	assertWebhookDetail(t, resp.Body, "ok")
}

func TestWebhookEmptyActionTriggersFullSync(t *testing.T) {
	profiles := []map[string]any{
		{"id": "uuid-1", "name": "Steve", "user_id": "u1", "owner_email": "steve@example.com"},
	}

	var gotHubBody map[string]any
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sync" {
			t.Errorf("hub path = %q, want /sync", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotHubBody); err != nil {
			t.Errorf("decode hub body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hub.Close()

	elementskin := elementskinAdminServer(t, profiles, http.StatusOK)
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, "Bearer "+webhookSecret, `{"name":"ignored","uuid":"ignored"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, string(body))
	}

	profileList, ok := gotHubBody["profileList"].(map[string]any)
	if !ok {
		t.Fatalf("profileList = %v, want map", gotHubBody["profileList"])
	}
	if len(profileList) != 1 || profileList["Steve"] != "uuid-1" {
		t.Errorf("profileList = %v, want Steve=uuid-1", profileList)
	}
	assertWebhookDetail(t, resp.Body, "ok")
}

func TestWebhookUnknownActionReturns400(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("hub should not be called for unknown action")
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called for unknown action")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, "Bearer "+webhookSecret, `{"action":"unknown","name":"Steve","uuid":"uuid-1"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400: %s", resp.StatusCode, string(body))
	}
	assertWebhookDetail(t, resp.Body, "unknown action")
}

func TestWebhookSyncFailureReturns500(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/profile" {
			t.Errorf("hub path = %q, want /profile", r.URL.Path)
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"hub error"}`))
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called for add action")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, "Bearer "+webhookSecret, `{"action":"add","name":"Steve","uuid":"uuid-1"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 500: %s", resp.StatusCode, string(body))
	}
	assertWebhookDetail(t, resp.Body, "failed to sync profile")
}
