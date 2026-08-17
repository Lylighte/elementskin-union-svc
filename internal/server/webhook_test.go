package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const webhookSecret = "test-webhook-secret"

// newWebhookTestServer creates a Server wired to mock Hub and Element-Skin
// servers with the webhook secret configured.
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

// webhookRequest builds an Element-Skin standard signed webhook request.
// When secret is empty, the signature headers are omitted entirely.
func webhookRequest(t *testing.T, ts *httptest.Server, secret, eventID, eventType, profileID string) *http.Request {
	t.Helper()

	body := `{"id":"` + eventID + `","type":"` + eventType + `","created_at":` +
		strconv.FormatInt(time.Now().UnixMilli(), 10) +
		`,"data":{"user_id":"user-1","profile_id":"` + profileID + `"}}`

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/union/webhook/profile-sync", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Webhook-Id", eventID)
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	req.Header.Set("Webhook-Timestamp", timestamp)
	if secret != "" {
		req.Header.Set("Webhook-Signature", signWebhookForTesting(secret, timestamp, []byte(body)))
	}
	return req
}

// postWebhook sends an Element-Skin standard signed webhook request.
func postWebhook(t *testing.T, ts *httptest.Server, secret, eventID, eventType, profileID string) *http.Response {
	t.Helper()
	req := webhookRequest(t, ts, secret, eventID, eventType, profileID)
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

func TestWebhookMissingSignatureReturns401(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("hub should not be called without signature")
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called without signature")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, "", "evt_1", "profile.created", "uuid-1")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 401: %s", resp.StatusCode, string(body))
	}
	assertWebhookDetail(t, resp.Body, "invalid Webhook signature")
}

func TestWebhookWrongSignatureReturns401(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("hub should not be called with wrong signature")
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called with wrong signature")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Sign with a different secret than the server expects.
	resp := postWebhook(t, ts, "wrong-secret", "evt_1", "profile.created", "uuid-1")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 401: %s", resp.StatusCode, string(body))
	}
	assertWebhookDetail(t, resp.Body, "invalid Webhook signature")
}

func TestWebhookStaleTimestampReturns401(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("hub should not be called with stale timestamp")
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called with stale timestamp")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := `{"id":"evt_stale","type":"profile.created","created_at":` +
		strconv.FormatInt(time.Now().Add(-10*time.Minute).UnixMilli(), 10) +
		`,"data":{"user_id":"user-1","profile_id":"uuid-1"}}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/union/webhook/profile-sync", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Webhook-Id", "evt_stale")
	staleTimestamp := strconv.FormatInt(time.Now().Add(-10*time.Minute).UnixMilli(), 10)
	req.Header.Set("Webhook-Timestamp", staleTimestamp)
	req.Header.Set("Webhook-Signature", signWebhookForTesting(webhookSecret, staleTimestamp, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 401: %s", resp.StatusCode, string(body))
	}
	assertWebhookDetail(t, resp.Body, "Webhook timestamp is outside the allowed tolerance")
}

func TestWebhookIDMismatchReturns400(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("hub should not be called when id mismatches")
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called when id mismatches")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Header id differs from the body id.
	req := webhookRequest(t, ts, webhookSecret, "evt_body_id", "profile.created", "uuid-1")
	req.Header.Set("Webhook-Id", "evt_different")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400: %s", resp.StatusCode, string(body))
	}
	assertWebhookDetail(t, resp.Body, "Webhook-Id does not match payload id")
}

func TestWebhookUnknownTypeReturns400(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("hub should not be called for unknown type")
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called for unknown type")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, webhookSecret, "evt_unknown", "texture.created", "uuid-1")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400: %s", resp.StatusCode, string(body))
	}
	assertWebhookDetail(t, resp.Body, "unknown webhook event type")
}

// elementskinWebhookServer mocks the Element-Skin endpoints the webhook
// handler calls: /oauth/token for the service account and
// /v2/minecraft/profiles/{id} for name lookup. When name is empty, the
// profile lookup returns 404.
func elementskinWebhookServer(t *testing.T, name string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/token":
			if r.Method != http.MethodPost {
				t.Errorf("token method = %s, want POST", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "service-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"scope":        "profile.read.any minecraft_profile.read.public",
			})
		case strings.HasPrefix(r.URL.Path, "/v2/minecraft/profiles/"):
			if got := r.Header.Get("Authorization"); got != "Bearer service-token" {
				t.Errorf("minecraft authorization = %q, want Bearer service-token", got)
			}
			w.Header().Set("Content-Type", "application/json")
			if name == "" {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": "minecraft profile not found"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":   "uuid-1",
				"name": name,
			})
		default:
			t.Errorf("unexpected elementskin path %s", r.URL.Path)
		}
	}))
}

func TestWebhookCreatedLooksUpNameAndSyncsAdd(t *testing.T) {
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

	elementskin := elementskinWebhookServer(t, "Steve")
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, webhookSecret, "evt_created", "profile.created", "uuid-1")
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

func TestWebhookCreatedMissingProfileReturns404(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("hub should not be called when profile lookup misses")
	}))
	defer hub.Close()

	elementskin := elementskinWebhookServer(t, "")
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, webhookSecret, "evt_created_missing", "profile.created", "uuid-1")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 404: %s", resp.StatusCode, string(body))
	}
	assertWebhookDetail(t, resp.Body, "profile not found")
}

func TestWebhookUpdatedLooksUpNameAndSyncsUpdate(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]string

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode hub body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hub.Close()

	elementskin := elementskinWebhookServer(t, "SteveNew")
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, webhookSecret, "evt_updated", "profile.updated", "uuid-1")
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

func TestWebhookUpdatedMissingProfileSyncsDelete(t *testing.T) {
	var gotMethod, gotPath string

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer hub.Close()

	elementskin := elementskinWebhookServer(t, "")
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, webhookSecret, "evt_updated_missing", "profile.updated", "uuid-1")
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

func TestWebhookDeletedSyncsDelete(t *testing.T) {
	var gotMethod, gotPath string

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called for delete event")
	}))
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, webhookSecret, "evt_deleted", "profile.deleted", "uuid-1")
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

func TestWebhookRepeatedIDIsIdempotent(t *testing.T) {
	var hubCalls int

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hubCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer hub.Close()

	elementskin := elementskinWebhookServer(t, "Steve")
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// First delivery processes the event.
	resp1 := postWebhook(t, ts, webhookSecret, "evt_repeat", "profile.created", "uuid-1")
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp1.Body)
		t.Fatalf("first status = %d, want 200: %s", resp1.StatusCode, string(body))
	}

	// Second delivery with the same Webhook-Id must be deduplicated.
	resp2 := postWebhook(t, ts, webhookSecret, "evt_repeat", "profile.created", "uuid-1")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("repeat status = %d, want 200: %s", resp2.StatusCode, string(body))
	}

	if hubCalls != 1 {
		t.Errorf("hub calls = %d, want 1 (idempotent)", hubCalls)
	}
	assertWebhookDetail(t, resp2.Body, "ok")
}

func TestWebhookHubFailureReturns502(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"hub error"}`))
	}))
	defer hub.Close()

	elementskin := elementskinWebhookServer(t, "Steve")
	defer elementskin.Close()

	srv := newWebhookTestServer(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postWebhook(t, ts, webhookSecret, "evt_hub_fail", "profile.created", "uuid-1")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 502: %s", resp.StatusCode, string(body))
	}
	assertWebhookDetail(t, resp.Body, "failed to sync profile")
}
