package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lylighte/elementskin-union-svc/internal/union"
)

func TestIntegrationFullSignedRequestFlow(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := `{"nonce":"integration-nonce"}`
	resp := signedPost(t, ts.URL+"/api/union/member/diagnose", body, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("diagnose status = %d, want 200: %s", resp.StatusCode, string(b))
	}

	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got["nonce"] != "integration-nonce" {
		t.Errorf("nonce = %q, want integration-nonce", got["nonce"])
	}
}

func TestIntegrationSyncEndToEnd(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	profiles := []map[string]any{
		{"id": "uuid-1", "name": "Steve", "user_id": "u1", "owner_email": "steve@example.com"},
	}

	var gotBody map[string]any
	hub := hubServer(t, pubPEM, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sync" {
			t.Errorf("unexpected hub path %s", r.URL.Path)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("sync method = %s, want POST", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode hub sync body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})
	defer hub.Close()

	elementskin := elementskinAdminServer(t, profiles, http.StatusOK)
	defer elementskin.Close()

	srv := newTestServerWithBackends(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := signedPost(t, ts.URL+"/api/union/member/sync", `{"profileList":{"Steve":"ignored"}}`, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("sync status = %d, want 200: %s", resp.StatusCode, string(b))
	}

	profileList, ok := gotBody["profileList"].(map[string]any)
	if !ok {
		t.Fatalf("profileList = %v, want map", gotBody["profileList"])
	}
	if len(profileList) != 1 || profileList["Steve"] != "uuid-1" {
		t.Errorf("hub profileList = %v, want Steve=uuid-1", profileList)
	}
}

func TestIntegrationQueryEmailEndToEnd(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	profiles := []map[string]any{
		{"id": "uuid-1", "name": "Steve", "user_id": "u1", "owner_email": "steve@example.com"},
	}

	hub := hubServer(t, pubPEM, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected hub call to %s", r.URL.Path)
	})
	defer hub.Close()

	elementskin := elementskinAdminServer(t, profiles, http.StatusOK)
	defer elementskin.Close()

	srv := newTestServerWithBackends(t, hub, elementskin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := signedGet(t, ts.URL+"/api/union/member/queryemail?username=Steve", privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("queryemail status = %d, want 200: %s", resp.StatusCode, string(b))
	}

	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got["email"] != "steve@example.com" {
		t.Errorf("email = %q, want steve@example.com", got["email"])
	}
}

func TestIntegrationUpdateBackendKeyUpdatesOutboundKey(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	var gotMemberKey string
	hub := hubServer(t, pubPEM, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/serverlist" {
			t.Errorf("unexpected hub path %s", r.URL.Path)
			return
		}
		gotMemberKey = r.Header.Get("X-Union-Member-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"servers":[],"version":1}`))
	})
	defer hub.Close()

	cfg := testConfig("http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")
	cfg.Union.HubURL = hub.URL
	cfg.Union.MemberKey = "old-member-key"

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := signedPost(t, ts.URL+"/api/union/member/updatebackendkey", `{"key":"new-member-key"}`, privPEM)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("updatebackendkey status = %d, want 200: %s", resp.StatusCode, string(b))
	}

	got, err := srv.settingsStore().Get(context.Background(), "member_key")
	if err != nil {
		t.Fatalf("get member_key: %v", err)
	}
	if got != "new-member-key" {
		t.Errorf("member_key = %q, want new-member-key", got)
	}

	resp = signedPost(t, ts.URL+"/api/union/member/updatelist", `{}`, privPEM)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("updatelist status = %d, want 200: %s", resp.StatusCode, string(b))
	}
	if gotMemberKey != "new-member-key" {
		t.Errorf("outbound X-Union-Member-Key = %q, want new-member-key", gotMemberKey)
	}
}

func TestIntegrationNonceReplayReturns401(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := `{"nonce":"replay-nonce"}`
	sig, tsVal, nonce := signInboundRequestWithPEM(t, body, privPEM)

	doReq := func() *http.Response {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/union/member/diagnose", strings.NewReader(body))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(signatureHeader, sig)
		req.Header.Set(timestampHeader, tsVal)
		req.Header.Set(nonceHeader, nonce)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		return resp
	}

	resp := doReq()
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", resp.StatusCode)
	}

	resp = doReq()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("replay status = %d, want 401: %s", resp.StatusCode, string(b))
	}
}

func TestIntegrationExpiredTimestampReturns401(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := `{"nonce":"expired-nonce"}`
	sig, nonce := signWithTimestamp(t, body, privPEM, "1")

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/union/member/diagnose", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(signatureHeader, sig)
	req.Header.Set(timestampHeader, "1")
	req.Header.Set(nonceHeader, nonce)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expired status = %d, want 401: %s", resp.StatusCode, string(b))
	}
}

func TestIntegrationUnsignedRequestReturns401(t *testing.T) {
	_, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/union/member/sync", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post sync: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unsigned status = %d, want 401: %s", resp.StatusCode, string(b))
	}
}
