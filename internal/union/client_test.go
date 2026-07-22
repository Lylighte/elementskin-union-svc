package union

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/config"
)

type methodRecord struct {
	method  string
	path    string
	query   string
	body    string
	headers http.Header
}

func record(r *http.Request) methodRecord {
	body, _ := io.ReadAll(r.Body)
	return methodRecord{
		method:  r.Method,
		path:    r.URL.Path,
		query:   r.URL.RawQuery,
		body:    string(body),
		headers: r.Header.Clone(),
	}
}

func openTestNonceStore(t *testing.T) *NonceStore {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open memory sqlite: %v", err)
	}
	s, err := NewNonceStore(db)
	if err != nil {
		t.Fatalf("create nonce store: %v", err)
	}
	return s
}

func openTestSettingsStore(t *testing.T) *SettingsStore {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open memory sqlite: %v", err)
	}
	s, err := NewSettingsStore(db)
	if err != nil {
		t.Fatalf("create settings store: %v", err)
	}
	return s
}

func newTestClient(t *testing.T, hubURL string) *Client {
	t.Helper()
	return NewClientWithDeps(hubURL, "test-member-key", 5, nil, openTestNonceStore(t), openTestSettingsStore(t))
}

func assertMethod(t *testing.T, got methodRecord, wantMethod, wantPath string) {
	t.Helper()
	if got.method != wantMethod {
		t.Fatalf("expected method %s, got %s", wantMethod, got.method)
	}
	if got.path != wantPath {
		t.Fatalf("expected path %s, got %s", wantPath, got.path)
	}
}

func assertHeader(t *testing.T, got methodRecord, key, want string) {
	t.Helper()
	if got.headers.Get(key) != want {
		t.Fatalf("expected header %s=%q, got %q", key, want, got.headers.Get(key))
	}
}

func assertQuery(t *testing.T, got methodRecord, key, want string) {
	t.Helper()
	values, err := url.ParseQuery(got.query)
	if err != nil {
		t.Fatalf("parse query %q: %v", got.query, err)
	}
	if values.Get(key) != want {
		t.Fatalf("expected query %s=%q, got %q", key, want, values.Get(key))
	}
}

func assertJSONField(t *testing.T, body, key, want string) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("decode body %q: %v", body, err)
	}
	if m[key] != want {
		t.Fatalf("expected body field %s=%q, got %v", key, want, m[key])
	}
}

func TestNewClientUsesDefaultTimeout(t *testing.T) {
	cfg := config.Config{}
	cfg.Storage.Path = filepath.Join(t.TempDir(), "test.db")

	client, err := NewClient(cfg, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	if client.timeout != 30*time.Second {
		t.Fatalf("expected default timeout 30s, got %v", client.timeout)
	}
}

func TestSyncProfileAdd(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	if err := client.SyncProfileAdd(context.Background(), "Steve", "uuid-1"); err != nil {
		t.Fatalf("SyncProfileAdd failed: %v", err)
	}

	assertMethod(t, got, http.MethodPost, "/profile")
	assertHeader(t, got, memberKeyHeader, "test-member-key")
	assertJSONField(t, got.body, "id", "uuid-1")
	assertJSONField(t, got.body, "name", "Steve")
}

func TestSyncProfileUpdate(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	if err := client.SyncProfileUpdate(context.Background(), "uuid-2", "Alex"); err != nil {
		t.Fatalf("SyncProfileUpdate failed: %v", err)
	}

	assertMethod(t, got, http.MethodPut, "/profile/uuid-2")
	assertJSONField(t, got.body, "name", "Alex")
}

func TestSyncProfileDelete(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	if err := client.SyncProfileDelete(context.Background(), "uuid-3"); err != nil {
		t.Fatalf("SyncProfileDelete failed: %v", err)
	}

	assertMethod(t, got, http.MethodDelete, "/profile/uuid-3")
}

func TestSyncProfiles(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	profileList := map[string]string{
		"Steve": "uuid-1",
		"Alex":  "uuid-2",
	}
	if err := client.SyncProfiles(context.Background(), profileList); err != nil {
		t.Fatalf("SyncProfiles failed: %v", err)
	}

	assertMethod(t, got, http.MethodPost, "/sync")
	assertHeader(t, got, memberKeyHeader, "test-member-key")

	var body struct {
		ProfileList map[string]string `json:"profileList"`
	}
	if err := json.Unmarshal([]byte(got.body), &body); err != nil {
		t.Fatalf("decode sync body: %v", err)
	}
	if len(body.ProfileList) != 2 {
		t.Fatalf("profileList length = %d, want 2", len(body.ProfileList))
	}
	if body.ProfileList["Steve"] != "uuid-1" || body.ProfileList["Alex"] != "uuid-2" {
		t.Errorf("profileList = %v, want Steve=uuid-1 Alex=uuid-2", body.ProfileList)
	}
}

func TestSyncProfilesPassesThroughHubError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"hub error"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	err := client.SyncProfiles(context.Background(), map[string]string{"Steve": "uuid-1"})
	if err == nil {
		t.Fatal("expected error")
	}
	var hubErr *HubError
	if !errors.As(err, &hubErr) {
		t.Fatalf("expected *HubError, got %T", err)
	}
	if hubErr.Status != http.StatusInternalServerError {
		t.Errorf("hub error status = %d, want 500", hubErr.Status)
	}
	if hubErr.Detail == "" {
		t.Errorf("hub error detail is empty, should contain body snippet")
	}
	if !strings.Contains(hubErr.Detail, `{"detail":"hub error"}`) {
		t.Errorf("hub error detail = %q, want it to contain response body", hubErr.Detail)
	}
	if !strings.Contains(hubErr.Detail, "HTTP 500") {
		t.Errorf("hub error detail = %q, want it to contain HTTP status", hubErr.Detail)
	}
}

func TestGetProfiles(t *testing.T) {
	profiles := []Profile{
		{UUID: "uuid-a", Name: "Steve", InternalID: "internal-a"},
		{UUID: "uuid-b", Name: "Steve", InternalID: "internal-b"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/profile/unmapped/byname/Steve" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(profiles)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	got, err := client.GetProfiles(context.Background(), "Steve")
	if err != nil {
		t.Fatalf("GetProfiles failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(got))
	}
	if got[0].InternalID != "internal-a" {
		t.Fatalf("unexpected profile: %+v", got[0])
	}
}

func TestGetSecurityLevel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/code":
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "secret-code"})
		case "/backend/secret-code/security/level":
			_, _ = w.Write([]byte("3"))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	level, err := client.GetSecurityLevel(context.Background(), "ignored")
	if err != nil {
		t.Fatalf("GetSecurityLevel failed: %v", err)
	}
	if level != 3 {
		t.Fatalf("expected security level 3, got %d", level)
	}
}

func TestSearchBlacklist(t *testing.T) {
	entries := []BlacklistEntry{
		{ID: "1", Email: "bad@example.com", Source: "manual", Reason: "spam", CreatedAt: "2024-01-01", ValidUntil: "2025-01-01"},
		{ID: "2", Email: "worse@example.com", Source: "sync", Reason: "abuse", CreatedAt: "2024-02-01", ValidUntil: "2025-02-01"},
	}

	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	gotEntries, err := client.SearchBlacklist(context.Background(), "bad")
	if err != nil {
		t.Fatalf("SearchBlacklist failed: %v", err)
	}

	assertMethod(t, got, http.MethodGet, "/blacklist/query")
	assertQuery(t, got, "q", "bad")
	assertHeader(t, got, memberKeyHeader, "test-member-key")

	if len(gotEntries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(gotEntries))
	}
	if gotEntries[0].ID != "1" || gotEntries[0].Email != "bad@example.com" {
		t.Fatalf("unexpected first entry: %+v", gotEntries[0])
	}
	if gotEntries[1].ID != "2" || gotEntries[1].Email != "worse@example.com" {
		t.Fatalf("unexpected second entry: %+v", gotEntries[1])
	}
}

func TestCreateBlacklist(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	if err := client.CreateBlacklist(context.Background(), BlacklistEntry{
		Email:  "bad@example.com",
		Reason: "spam",
	}); err != nil {
		t.Fatalf("CreateBlacklist failed: %v", err)
	}

	assertMethod(t, got, http.MethodPost, "/blacklist/restful")
	assertJSONField(t, got.body, "email", "bad@example.com")
	assertJSONField(t, got.body, "reason", "spam")
}

func TestDeleteBlacklist(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	if err := client.DeleteBlacklist(context.Background(), "42"); err != nil {
		t.Fatalf("DeleteBlacklist failed: %v", err)
	}

	assertMethod(t, got, http.MethodDelete, "/blacklist/restful/42")
	assertHeader(t, got, memberKeyHeader, "test-member-key")
}

func TestInvalidateBlacklist(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	if err := client.InvalidateBlacklist(context.Background(), "42"); err != nil {
		t.Fatalf("InvalidateBlacklist failed: %v", err)
	}

	assertMethod(t, got, http.MethodPut, "/blacklist/invalidate/42")
	assertHeader(t, got, memberKeyHeader, "test-member-key")
}

func TestFetchServerList(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"servers":[{"name":"hub1"}],"version":3}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	servers, version, err := client.FetchServerList(context.Background())
	if err != nil {
		t.Fatalf("FetchServerList failed: %v", err)
	}

	assertMethod(t, got, http.MethodGet, "/serverlist")
	assertHeader(t, got, memberKeyHeader, "test-member-key")
	if version != 3 {
		t.Fatalf("expected version 3, got %d", version)
	}
	wantServers := `[{"name":"hub1"}]`
	if string(servers) != wantServers {
		t.Fatalf("expected servers %q, got %q", wantServers, string(servers))
	}
}

func TestFetchServerListReturnsHubError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"forbidden"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	_, _, err := client.FetchServerList(context.Background())
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	var hubErr *HubError
	if !errors.As(err, &hubErr) {
		t.Fatalf("expected *HubError, got %T", err)
	}
	if hubErr.Status != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", hubErr.Status)
	}
	if !strings.Contains(hubErr.Detail, `{"detail":"forbidden"}`) {
		t.Errorf("hub error detail = %q, want it to contain response body", hubErr.Detail)
	}
	if !strings.Contains(hubErr.Detail, "HTTP 403") {
		t.Errorf("hub error detail = %q, want it to contain HTTP 403", hubErr.Detail)
	}
}

func TestFetchPrivateKey(t *testing.T) {
	var got methodRecord
	pemData := "-----BEGIN RSA PRIVATE KEY-----\nMIIBOg==\n-----END RSA PRIVATE KEY-----"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(map[string]any{
			"privateKey":        pemData,
			"privateKeyVersion": 5,
		})
		_, _ = w.Write(resp)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	gotPEM, version, err := client.FetchPrivateKey(context.Background())
	if err != nil {
		t.Fatalf("FetchPrivateKey failed: %v", err)
	}

	assertMethod(t, got, http.MethodGet, "/privatekey")
	assertHeader(t, got, memberKeyHeader, "test-member-key")
	if version != 5 {
		t.Fatalf("expected version 5, got %d", version)
	}
	if gotPEM != pemData {
		t.Fatalf("expected PEM %q, got %q", pemData, gotPEM)
	}
}

func TestDynamicMemberKeyFromSettings(t *testing.T) {
	var gotKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get(memberKeyHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"servers":[],"version":1}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	ctx := context.Background()
	if err := client.settings.Set(ctx, "member_key", "runtime-key"); err != nil {
		t.Fatalf("set runtime member_key: %v", err)
	}

	if _, _, err := client.FetchServerList(ctx); err != nil {
		t.Fatalf("FetchServerList failed: %v", err)
	}
	if gotKey != "runtime-key" {
		t.Fatalf("expected runtime member key %q, got %q", "runtime-key", gotKey)
	}
}

func TestProxyToHubHitsCorrectPathAndMethod(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	body, status, err := client.ProxyToHub(context.Background(), http.MethodPatch, "/custom/path", nil)
	if err != nil {
		t.Fatalf("ProxyToHub failed: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}
	if string(body) != "ok" {
		t.Fatalf("expected body %q, got %q", "ok", string(body))
	}

	assertMethod(t, got, http.MethodPatch, "/custom/path")
}

func TestProxyToHubSetsMemberKeyHeader(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	if _, _, err := client.ProxyToHub(context.Background(), http.MethodGet, "/ping", nil); err != nil {
		t.Fatalf("ProxyToHub failed: %v", err)
	}

	assertHeader(t, got, memberKeyHeader, "test-member-key")
}

func TestProxyToHubReturnsRawBodyAndStatusOn200And500(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		wantBody   string
		wantStatus int
	}{
		{"success", http.StatusOK, `{"ok":true}`, http.StatusOK},
		{"server error", http.StatusInternalServerError, `{"detail":"boom"}`, http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.wantBody))
			}))
			defer server.Close()

			client := newTestClient(t, server.URL)
			defer client.Close()

			body, status, err := client.ProxyToHub(context.Background(), http.MethodGet, "/", nil)
			if err != nil {
				t.Fatalf("ProxyToHub failed: %v", err)
			}
			if status != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, status)
			}
			if string(body) != tc.wantBody {
				t.Fatalf("expected body %q, got %q", tc.wantBody, string(body))
			}

			var hubErr *HubError
			if errors.As(err, &hubErr) {
				t.Fatal("ProxyToHub must not wrap HTTP errors as HubError")
			}
		})
	}
}

func TestProxyToHubReturnsTransportError(t *testing.T) {
	client := newTestClient(t, "http://localhost:1")
	defer client.Close()

	client.http = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("boom")
		}),
	}

	body, status, err := client.ProxyToHub(context.Background(), http.MethodGet, "/", nil)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if body != nil {
		t.Fatalf("expected nil body, got %q", string(body))
	}
	if status != 0 {
		t.Fatalf("expected status 0, got %d", status)
	}
}

func TestProxyToHubSendsRawBytes(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	raw := []byte(`{"binary":"data"}`)
	if _, _, err := client.ProxyToHub(context.Background(), http.MethodPost, "/raw", raw); err != nil {
		t.Fatalf("ProxyToHub failed: %v", err)
	}

	if got.body != string(raw) {
		t.Fatalf("expected raw body %q, got %q", string(raw), got.body)
	}
	if got.headers.Get("Content-Type") != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", got.headers.Get("Content-Type"))
	}
}

func TestGetOAuth2BackendPublicKey(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/oauth2/backend" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"publicKey":"-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	key, err := client.GetOAuth2BackendPublicKey(context.Background())
	if err != nil {
		t.Fatalf("GetOAuth2BackendPublicKey failed: %v", err)
	}
	if key == "" {
		t.Fatal("expected non-empty public key")
	}
	if calls != 1 {
		t.Fatalf("expected 1 hub call, got %d", calls)
	}

	key2, err := client.GetOAuth2BackendPublicKey(context.Background())
	if err != nil {
		t.Fatalf("GetOAuth2BackendPublicKey failed: %v", err)
	}
	if key2 != key {
		t.Fatalf("expected cached key %q, got %q", key, key2)
	}
	if calls != 1 {
		t.Fatalf("expected cached call, got %d hub calls", calls)
	}
}

func TestGetOAuth2BackendPublicKeyUsesSeparateCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`{"union_host_signature_public_key":"sig-key"}`))
		case "/oauth2/backend":
			_, _ = w.Write([]byte(`{"publicKey":"oauth2-key"}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	sigKey, err := client.fetchHubPublicKey(context.Background())
	if err != nil {
		t.Fatalf("fetchHubPublicKey failed: %v", err)
	}
	if sigKey != "sig-key" {
		t.Fatalf("expected sig key %q, got %q", "sig-key", sigKey)
	}

	oauth2Key, err := client.GetOAuth2BackendPublicKey(context.Background())
	if err != nil {
		t.Fatalf("GetOAuth2BackendPublicKey failed: %v", err)
	}
	if oauth2Key != "oauth2-key" {
		t.Fatalf("expected oauth2 key %q, got %q", "oauth2-key", oauth2Key)
	}

	if client.oauth2PubKey == client.pubKey {
		t.Fatal("oauth2 and signature public key caches must be separate")
	}
}

func TestProfileBind(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"bound":true}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	body, status, err := client.ProfileBind(context.Background(), "uuid-bind")
	if err != nil {
		t.Fatalf("ProfileBind failed: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}
	if string(body) != `{"bound":true}` {
		t.Fatalf("expected raw body, got %q", string(body))
	}

	assertMethod(t, got, http.MethodPost, "/profile/bind")
	assertJSONField(t, got.body, "uuid", "uuid-bind")
}

func TestProfileUnbind(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	if _, _, err := client.ProfileUnbind(context.Background(), "uuid-unbind"); err != nil {
		t.Fatalf("ProfileUnbind failed: %v", err)
	}

	assertMethod(t, got, http.MethodPost, "/profile/unbind")
	assertJSONField(t, got.body, "uuid", "uuid-unbind")
}

func TestProfileBindTo(t *testing.T) {
	var got methodRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	if _, _, err := client.ProfileBindTo(context.Background(), "uuid-bindto", "target-token"); err != nil {
		t.Fatalf("ProfileBindTo failed: %v", err)
	}

	assertMethod(t, got, http.MethodPost, "/profile/bindto")
	assertJSONField(t, got.body, "uuid", "uuid-bindto")
	assertJSONField(t, got.body, "token", "target-token")
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
