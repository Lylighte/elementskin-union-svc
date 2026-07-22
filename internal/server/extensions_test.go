package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/bridge"
)

func TestE2EOAuthCallbackCreatesSessionAndGrantRedirectsToHub(t *testing.T) {
	hubPrivKey, hubPubPEM := generateRSAKeyPair(t, 2048)

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "test-access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "test-refresh-token",
				"scope":         defaultScope,
			})
		case "/v1/users/me":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				t.Errorf("missing bearer authorization: %q", r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(bridge.UserInfo{
				ID:          "user-123",
				DisplayName: "TestUser",
				Email:       "test@example.com",
			})
		default:
			t.Errorf("unexpected elementskin path %s", r.URL.Path)
		}
	}))
	defer elementskin.Close()

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/backend" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"publicKey": hubPubPEM})
			return
		}
		t.Errorf("unexpected hub path %s", r.URL.Path)
	}))
	defer hub.Close()

	cfg := testConfig(elementskin.URL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")
	cfg.Union.HubURL = hub.URL
	cfg.Union.MemberKey = "test-member-key"
	cfg.Union.EnableOAuth2 = true
	cfg.Union.CORSAllowOrigin = ""
	cfg.Union.OAuth2SigPrivateKeyPath = filepath.Join(t.TempDir(), "oauth2_sig_private.pem")
	cfg.Union.OAuth2SigPublicKeyPath = filepath.Join(t.TempDir(), "oauth2_sig_public.pem")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	state := "e2e-callback-state"
	verifier := "e2e-callback-verifier"
	if err := srv.stateStore.Save(context.Background(), State{
		State:       state,
		Verifier:    verifier,
		RedirectURI: cfg.Elementskin.OAuth.RedirectURI,
		Scope:       defaultScope,
		ExpiresAtMS: time.Now().UTC().Add(10 * time.Minute).UnixMilli(),
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(ts.URL + "/oauth/callback?code=auth-code-123&state=" + state)
	if err != nil {
		t.Fatalf("get callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback status = %d, want 302: %s", resp.StatusCode, string(body))
	}

	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("parse callback location: %v", err)
	}
	if loc.Path != "/" || loc.RawQuery != "authorized=true" {
		t.Errorf("callback location = %q, want /?authorized=true", loc.String())
	}

	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == testCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie not set after callback")
	}
	if sessionCookie.Value == "" {
		t.Fatal("session cookie value is empty")
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/union/member/oauth2/grant?state=grant-state", nil)
	if err != nil {
		t.Fatalf("build grant request: %v", err)
	}
	req.AddCookie(sessionCookie)

	grantResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	defer grantResp.Body.Close()

	if grantResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(grantResp.Body)
		t.Fatalf("grant status = %d, want 302: %s", grantResp.StatusCode, string(body))
	}

	grantLoc, err := grantResp.Location()
	if err != nil {
		t.Fatalf("parse grant location: %v", err)
	}
	if grantLoc.Path != "/oauth2/continue" {
		t.Errorf("grant location path = %q, want /oauth2/continue", grantLoc.Path)
	}
	if grantLoc.Scheme+"://"+grantLoc.Host != hub.URL {
		t.Errorf("grant location host = %q, want %q", grantLoc.Scheme+"://"+grantLoc.Host, hub.URL)
	}

	q := grantLoc.Query()
	if q.Get("state") != "grant-state" {
		t.Errorf("state = %q, want grant-state", q.Get("state"))
	}

	encryptedB64 := q.Get("userInfoToken")
	if encryptedB64 == "" {
		t.Fatal("userInfoToken is empty")
	}

	tokenJSON := decryptUserInfoToken(t, hubPrivKey, encryptedB64)
	var token struct {
		UserInfo  string `json:"userInfo"`
		Mac       string `json:"mac"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(tokenJSON, &token); err != nil {
		t.Fatalf("decode token json: %v", err)
	}

	userInfoPayload, err := base64.StdEncoding.DecodeString(token.UserInfo)
	if err != nil {
		t.Fatalf("decode userInfo: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(userInfoPayload, &payload); err != nil {
		t.Fatalf("decode userInfo payload: %v", err)
	}
	if payload["uid"] != "user-123" {
		t.Errorf("uid = %v, want user-123", payload["uid"])
	}
	if payload["nickname"] != "TestUser" {
		t.Errorf("nickname = %v, want TestUser", payload["nickname"])
	}
	if payload["email"] != "test@example.com" {
		t.Errorf("email = %v, want test@example.com", payload["email"])
	}
}

func TestE2EBlacklistListWithAdminKey(t *testing.T) {
	var gotMethod, gotPath, gotRawQuery, gotMemberKey string
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotRawQuery = r.URL.RawQuery
		gotMemberKey = r.Header.Get("X-Union-Member-Key")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[{"id":1}],"has_next":false}`))
	}))
	defer hub.Close()

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
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

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
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"items":[{"id":1}],"has_next":false}` {
		t.Errorf("body = %q, want raw hub response", string(body))
	}
}

func TestE2EProfileBindWithUserToken(t *testing.T) {
	var capturedUUID string
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/users/me" {
			t.Errorf("elementskin path = %q, want /v1/users/me", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing bearer authorization: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bridge.UserInfo{
			ID:          "user-456",
			DisplayName: "Alice",
			Email:       "alice@example.com",
		})
	}))
	defer elementskin.Close()

	cfg := testConfig(elementskin.URL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")
	cfg.Union.HubURL = hub.URL
	cfg.Union.MemberKey = "member-key"

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	reqBody := `{"uuid":"profile-uuid-abc"}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/union/profile/bind", bytes.NewReader([]byte(reqBody)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer valid-user-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post bind: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, string(body))
	}

	if capturedUUID != "profile-uuid-abc" {
		t.Errorf("captured uuid = %q, want profile-uuid-abc", capturedUUID)
	}

	body, _ := io.ReadAll(resp.Body)
	var respBody map[string]string
	if err := json.Unmarshal(body, &respBody); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respBody["token"] != "hub-token-123" {
		t.Errorf("token = %q, want hub-token-123", respBody["token"])
	}
}

func TestE2EWebhookProfileSyncFullSync(t *testing.T) {
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
			t.Errorf("hub method = %q, want POST", r.Method)
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
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/union/webhook/profile-sync", strings.NewReader(`{"action":"full_sync"}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+webhookSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post webhook: %v", err)
	}
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

	var respBody map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respBody["detail"] != "ok" {
		t.Errorf("detail = %q, want ok", respBody["detail"])
	}
}
