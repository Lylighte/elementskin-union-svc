package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lylighte/elementskin-union-svc/internal/union"
)

const (
	signatureHeader = "X-Message-Signature"
	timestampHeader = "X-Message-Timestamp"
	nonceHeader     = "X-Message-Nonce"
)

// setupInboundTestServer creates a Server configured to talk to a mock Union
// Hub that advertises the given public key.
func setupInboundTestServer(t *testing.T, pubPEM string) (*Server, *httptest.Server) {
	t.Helper()

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"union_host_signature_public_key": pubPEM,
		})
	}))
	t.Cleanup(hub.Close)

	cfg := testConfig("http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")
	cfg.Union.HubURL = hub.URL
	cfg.Union.MemberKey = "test-member-key"

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	return srv, hub
}

// signInboundRequestWithPEM signs a request body using the PEM-encoded private
// key and returns the signature headers.
func signInboundRequestWithPEM(t *testing.T, body, privPEM string) (sig, ts, nonce string) {
	t.Helper()

	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		t.Fatal("failed to decode private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	sig, ts, nonce, err = union.SignInboundRequest(body, key)
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}
	return sig, ts, nonce
}

func TestInboundRoutesHelloIsPublic(t *testing.T) {
	_, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp, err := http.Get(testServer.URL + "/api/union/member/")
	if err != nil {
		t.Fatalf("get hello: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("hello status = %d, want 200: %s", resp.StatusCode, string(body))
	}
}

func TestInboundRoutesUnsignedRequestReturns401(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp, err := http.Post(testServer.URL+"/api/union/member/sync", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post sync: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("sync status = %d, want 401: %s", resp.StatusCode, string(body))
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["detail"] == "" {
		t.Errorf("expected non-empty detail in 401 body")
	}

	_ = privPEM
}

func signedGet(t *testing.T, url, privPEM string) *http.Response {
	t.Helper()

	sig, ts, nonce := signInboundRequestWithPEM(t, "", privPEM)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set(signatureHeader, sig)
	req.Header.Set(timestampHeader, ts)
	req.Header.Set(nonceHeader, nonce)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func TestQueryEmailReturns200WhenProfileFound(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
			return
		}
		t.Errorf("unexpected hub path %s", r.URL.Path)
	}))
	defer hub.Close()

	profiles := []map[string]any{
		{"id": "uuid-1", "name": "Steve", "user_id": "u1", "owner_email": "steve@example.com"},
	}
	elementskin := elementskinAdminServer(t, profiles, http.StatusOK)
	defer elementskin.Close()

	srv := newTestServerWithBackends(t, hub, elementskin)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp := signedGet(t, testServer.URL+"/api/union/member/queryemail?username=Steve", privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("queryemail status = %d, want 200: %s", resp.StatusCode, string(body))
	}

	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got["email"] != "steve@example.com" {
		t.Errorf("email = %q, want steve@example.com", got["email"])
	}
}

func TestQueryEmailReturns204WhenProfileNotFound(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
			return
		}
		t.Errorf("unexpected hub path %s", r.URL.Path)
	}))
	defer hub.Close()

	elementskin := elementskinAdminServer(t, nil, http.StatusOK)
	defer elementskin.Close()

	srv := newTestServerWithBackends(t, hub, elementskin)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp := signedGet(t, testServer.URL+"/api/union/member/queryemail?username=Unknown", privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("queryemail status = %d, want 204: %s", resp.StatusCode, string(body))
	}
	if resp.ContentLength != 0 {
		t.Errorf("response body length = %d, want 0", resp.ContentLength)
	}
}

func TestQueryEmailReturns400WhenUsernameMissing(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
			return
		}
		t.Errorf("unexpected hub path %s", r.URL.Path)
	}))
	defer hub.Close()

	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("elementskin should not be called when username is missing")
	}))
	defer elementskin.Close()

	srv := newTestServerWithBackends(t, hub, elementskin)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp := signedGet(t, testServer.URL+"/api/union/member/queryemail", privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("queryemail status = %d, want 400: %s", resp.StatusCode, string(body))
	}

	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got["detail"] != "username is required" {
		t.Errorf("detail = %q, want username is required", got["detail"])
	}
}

func TestQueryEmailReturns500WhenAdminAPIFails(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
			return
		}
		t.Errorf("unexpected hub path %s", r.URL.Path)
	}))
	defer hub.Close()

	elementskin := elementskinAdminServer(t, nil, http.StatusInternalServerError)
	defer elementskin.Close()

	srv := newTestServerWithBackends(t, hub, elementskin)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp := signedGet(t, testServer.URL+"/api/union/member/queryemail?username=Steve", privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("queryemail status = %d, want 500: %s", resp.StatusCode, string(body))
	}

	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got["detail"] != "failed to query email" {
		t.Errorf("detail = %q, want failed to query email", got["detail"])
	}
}

func TestInboundRoutesSignedDiagnoseReturns200(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	body := `{"nonce":"test-nonce"}`
	sig, ts, nonce := signInboundRequestWithPEM(t, body, privPEM)

	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/api/union/member/diagnose", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(signatureHeader, sig)
	req.Header.Set(timestampHeader, ts)
	req.Header.Set(nonceHeader, nonce)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post diagnose: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("diagnose status = %d, want 200: %s", resp.StatusCode, string(respBody))
	}
}

func TestInboundRoutesInvalidSignatureReturns401(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	body := `{"nonce":"test-nonce"}`
	_, ts, nonce := signInboundRequestWithPEM(t, body, privPEM)

	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/api/union/member/diagnose", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(signatureHeader, "dGVzdA==")
	req.Header.Set(timestampHeader, ts)
	req.Header.Set(nonceHeader, nonce)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post diagnose: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("diagnose status = %d, want 401: %s", resp.StatusCode, string(respBody))
	}
}

func TestInboundRoutesExpiredTimestampReturns401(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	body := `{"nonce":"test-nonce"}`
	sig, _, nonce := signInboundRequestWithPEM(t, body, privPEM)

	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/api/union/member/diagnose", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(signatureHeader, sig)
	req.Header.Set(timestampHeader, "1")
	req.Header.Set(nonceHeader, nonce)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post diagnose: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("diagnose status = %d, want 401: %s", resp.StatusCode, string(respBody))
	}
}

func TestInboundRoutesExistingRoutesNotVerified(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp, err := http.Get(testServer.URL + "/health")
	if err != nil {
		t.Fatalf("get health: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health status = %d, want 200", resp.StatusCode)
	}

	resp, err = http.Get(testServer.URL + "/")
	if err != nil {
		t.Fatalf("get root: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("root status = %d, want 200", resp.StatusCode)
	}

	_ = privPEM
}

func newTestServerWithHub(t *testing.T, hub *httptest.Server, logger *slog.Logger) *Server {
	t.Helper()

	cfg := testConfig("http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")
	cfg.Union.HubURL = hub.URL
	cfg.Union.MemberKey = "test-member-key"

	srv, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	return srv
}

func signedPost(t *testing.T, url, body, privPEM string) *http.Response {
	t.Helper()

	sig, ts, nonce := signInboundRequestWithPEM(t, body, privPEM)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(signatureHeader, sig)
	req.Header.Set(timestampHeader, ts)
	req.Header.Set(nonceHeader, nonce)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func TestHelloReturnsVersionAndFeatures(t *testing.T) {
	_, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp, err := http.Get(testServer.URL + "/api/union/member/")
	if err != nil {
		t.Fatalf("get hello: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("hello status = %d, want 200: %s", resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty (no CORS configured)", got)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["yggdrasilApiVersion"] != "union-svc/1.0" {
		t.Errorf("yggdrasilApiVersion = %q, want union-svc/1.0", body["yggdrasilApiVersion"])
	}
	if body["serverListVersion"] != float64(0) {
		t.Errorf("serverListVersion = %v, want 0", body["serverListVersion"])
	}
	if body["privateKeyVersion"] != float64(0) {
		t.Errorf("privateKeyVersion = %v, want 0", body["privateKeyVersion"])
	}
	features, ok := body["enabledFeatures"].([]any)
	if !ok || len(features) != 1 || features[0] != "unionBlacklist" {
		t.Errorf("enabledFeatures = %v, want [unionBlacklist]", body["enabledFeatures"])
	}
}

func TestHelloEmitsCORSWhenConfigured(t *testing.T) {
	_, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	srv.cfg.Union.CORSAllowOrigin = "https://example.com"
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp, err := http.Get(testServer.URL + "/api/union/member/")
	if err != nil {
		t.Fatalf("get hello: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want https://example.com", got)
	}
}

func TestHelloReturnsSeededVersions(t *testing.T) {
	_, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	ctx := context.Background()
	if err := srv.settingsStore().Set(ctx, "server_list_version", "3"); err != nil {
		t.Fatalf("seed server_list_version: %v", err)
	}
	if err := srv.settingsStore().Set(ctx, "private_key_version", "5"); err != nil {
		t.Fatalf("seed private_key_version: %v", err)
	}

	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp, err := http.Get(testServer.URL + "/api/union/member/")
	if err != nil {
		t.Fatalf("get hello: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("hello status = %d, want 200: %s", resp.StatusCode, string(body))
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["serverListVersion"] != float64(3) {
		t.Errorf("serverListVersion = %v, want 3", body["serverListVersion"])
	}
	if body["privateKeyVersion"] != float64(5) {
		t.Errorf("privateKeyVersion = %v, want 5", body["privateKeyVersion"])
	}
}

func TestDiagnoseEchoesNonceAndTimestamp(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	body := `{"nonce":"test-nonce"}`
	resp := signedPost(t, testServer.URL+"/api/union/member/diagnose", body, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("diagnose status = %d, want 200: %s", resp.StatusCode, string(respBody))
	}

	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got["nonce"] != "test-nonce" {
		t.Errorf("nonce = %q, want test-nonce", got["nonce"])
	}
	ts, ok := got["timestamp"].(float64)
	if !ok {
		t.Fatalf("timestamp = %v, want float64", got["timestamp"])
	}
	if ts <= 0 {
		t.Errorf("timestamp = %v, want positive value", ts)
	}
}

func TestUpdateBackendKeyStoresMemberKey(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	srv, _ := setupInboundTestServer(t, pubPEM)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	body := `{"key":"new-member-key"}`
	resp := signedPost(t, testServer.URL+"/api/union/member/updatebackendkey", body, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("updatebackendkey status = %d, want 200: %s", resp.StatusCode, string(respBody))
	}

	got, err := srv.settingsStore().Get(context.Background(), "member_key")
	if err != nil {
		t.Fatalf("get member_key: %v", err)
	}
	if got != "new-member-key" {
		t.Errorf("member_key = %q, want new-member-key", got)
	}
}

func TestUpdateListStoresServerListAndVersion(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
		case "/serverlist":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"servers":[{"name":"hub"}],"version":3}`))
		default:
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
	}))
	defer hub.Close()

	srv := newTestServerWithHub(t, hub, testLogger())
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp := signedPost(t, testServer.URL+"/api/union/member/updatelist", `{}`, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("updatelist status = %d, want 200: %s", resp.StatusCode, string(respBody))
	}

	ctx := context.Background()
	list, err := srv.settingsStore().Get(ctx, "server_list")
	if err != nil {
		t.Fatalf("get server_list: %v", err)
	}
	if list != `[{"name":"hub"}]` {
		t.Errorf("server_list = %q, want [{\"name\":\"hub\"}]", list)
	}
	version, err := srv.settingsStore().Get(ctx, "server_list_version")
	if err != nil {
		t.Fatalf("get server_list_version: %v", err)
	}
	if version != "3" {
		t.Errorf("server_list_version = %q, want 3", version)
	}
}

func TestUpdateListPassesThroughHubError(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
		case "/serverlist":
			w.WriteHeader(http.StatusForbidden)
		default:
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
	}))
	defer hub.Close()

	srv := newTestServerWithHub(t, hub, testLogger())
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp := signedPost(t, testServer.URL+"/api/union/member/updatelist", `{}`, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("updatelist status = %d, want 403: %s", resp.StatusCode, string(respBody))
	}
}

func TestUpdatePrivateKeyStoresVersionAndNotPEM(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
		case "/privatekey":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"privateKey":"-----BEGIN RSA PRIVATE KEY-----","privateKeyVersion":5}`))
		default:
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
	}))
	defer hub.Close()

	srv := newTestServerWithHub(t, hub, logger)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp := signedPost(t, testServer.URL+"/api/union/member/updateprivatekey", `{}`, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("updateprivatekey status = %d, want 200: %s", resp.StatusCode, string(respBody))
	}

	ctx := context.Background()
	version, err := srv.settingsStore().Get(ctx, "private_key_version")
	if err != nil {
		t.Fatalf("get private_key_version: %v", err)
	}
	if version != "5" {
		t.Errorf("private_key_version = %q, want 5", version)
	}

	pem, err := srv.settingsStore().Get(ctx, "private_key")
	if err != nil {
		t.Fatalf("get private_key: %v", err)
	}
	if pem != "" {
		t.Errorf("private_key must not be stored, got %q", pem)
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "Union private key updated to version 5") {
		t.Errorf("log does not contain version update message: %q", logs)
	}
	if !strings.Contains(logs, "Admin must manually replace PEM in skin-backend") {
		t.Errorf("log does not contain manual replacement reminder: %q", logs)
	}
}

func TestUpdatePrivateKeyPassesThroughHubError(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
		case "/privatekey":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
	}))
	defer hub.Close()

	srv := newTestServerWithHub(t, hub, testLogger())
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp := signedPost(t, testServer.URL+"/api/union/member/updateprivatekey", `{}`, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("updateprivatekey status = %d, want 500: %s", resp.StatusCode, string(respBody))
	}

	ctx := context.Background()
	version, err := srv.settingsStore().Get(ctx, "private_key_version")
	if err != nil {
		t.Fatalf("get private_key_version: %v", err)
	}
	if version != "" {
		t.Errorf("private_key_version = %q, want empty on Hub error", version)
	}
}

// newTestServerWithBackends creates a Server that talks to the supplied mock
// Hub and Element-Skin servers. The Element-Skin server must handle the
// service-account token endpoint and any admin API routes used by the test.
func newTestServerWithBackends(t *testing.T, hub, elementskin *httptest.Server) *Server {
	t.Helper()

	cfg := testConfig(elementskin.URL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "store.db")
	cfg.Union.HubURL = hub.URL
	cfg.Union.MemberKey = "test-member-key"
	cfg.Elementskin.ServiceAccount.ClientID = "svc-client-id"
	cfg.Elementskin.ServiceAccount.ClientSecret = "svc-client-secret"

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	return srv
}

// elementskinAdminServer returns a mock Element-Skin server that serves a
// client_credentials token endpoint and a paginated admin profiles list.
func elementskinAdminServer(t *testing.T, profiles []map[string]any, status int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
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
		case "/v2/admin/profiles":
			if r.Method != http.MethodGet {
				t.Errorf("profiles method = %s, want GET", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer service-token" {
				t.Errorf("authorization = %q, want Bearer service-token", got)
			}
			w.Header().Set("Content-Type", "application/json")
			if status != http.StatusOK {
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": "admin api error"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items":     profiles,
				"has_next":  false,
				"page_size": 100,
			})
		default:
			t.Errorf("unexpected elementskin path %s", r.URL.Path)
		}
	}))
}

func TestSyncReportsLocalProfilesToHub(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	profiles := []map[string]any{
		{"id": "uuid-1", "name": "Steve", "user_id": "u1", "owner_email": "steve@example.com"},
	}

	var gotHubBody map[string]any
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
		case "/sync":
			if r.Method != http.MethodPost {
				t.Errorf("sync method = %s, want POST", r.Method)
			}
			if got := r.Header.Get("X-Union-Member-Key"); got != "test-member-key" {
				t.Errorf("member key = %q, want test-member-key", got)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotHubBody); err != nil {
				t.Errorf("decode hub sync body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
	}))
	defer hub.Close()

	elementskin := elementskinAdminServer(t, profiles, http.StatusOK)
	defer elementskin.Close()

	srv := newTestServerWithBackends(t, hub, elementskin)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	body := `{"profileList":{"Steve":"ignored-uuid"}}`
	resp := signedPost(t, testServer.URL+"/api/union/member/sync", body, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("sync status = %d, want 200: %s", resp.StatusCode, string(respBody))
	}

	profileList, ok := gotHubBody["profileList"].(map[string]any)
	if !ok {
		t.Fatalf("profileList = %v, want map", gotHubBody["profileList"])
	}
	if len(profileList) != 1 || profileList["Steve"] != "uuid-1" {
		t.Errorf("hub profileList = %v, want Steve=uuid-1", profileList)
	}
}

func TestSyncIgnoresHubProfileListHint(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	profiles := []map[string]any{
		{"id": "uuid-1", "name": "Steve", "user_id": "u1", "owner_email": "steve@example.com"},
	}

	var gotHubBody map[string]any
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
		case "/sync":
			if err := json.NewDecoder(r.Body).Decode(&gotHubBody); err != nil {
				t.Errorf("decode hub sync body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
	}))
	defer hub.Close()

	elementskin := elementskinAdminServer(t, profiles, http.StatusOK)
	defer elementskin.Close()

	srv := newTestServerWithBackends(t, hub, elementskin)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	body := `{"profileList":{"Steve":"ignored","Alex":"also-ignored"}}`
	resp := signedPost(t, testServer.URL+"/api/union/member/sync", body, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("sync status = %d, want 200: %s", resp.StatusCode, string(respBody))
	}

	profileList, ok := gotHubBody["profileList"].(map[string]any)
	if !ok {
		t.Fatalf("profileList = %v, want map", gotHubBody["profileList"])
	}
	if len(profileList) != 1 || profileList["Steve"] != "uuid-1" {
		t.Errorf("hub profileList = %v, want only Steve=uuid-1", profileList)
	}
}

func TestSyncEmptyBodyUsesLocalProfiles(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	profiles := []map[string]any{
		{"id": "uuid-1", "name": "Steve", "user_id": "u1", "owner_email": "steve@example.com"},
		{"id": "uuid-2", "name": "Alex", "user_id": "u2", "owner_email": "alex@example.com"},
	}

	var gotHubBody map[string]any
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
		case "/sync":
			if err := json.NewDecoder(r.Body).Decode(&gotHubBody); err != nil {
				t.Errorf("decode hub sync body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
	}))
	defer hub.Close()

	elementskin := elementskinAdminServer(t, profiles, http.StatusOK)
	defer elementskin.Close()

	srv := newTestServerWithBackends(t, hub, elementskin)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp := signedPost(t, testServer.URL+"/api/union/member/sync", `{}`, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("sync status = %d, want 200: %s", resp.StatusCode, string(respBody))
	}

	profileList, ok := gotHubBody["profileList"].(map[string]any)
	if !ok {
		t.Fatalf("profileList = %v, want map", gotHubBody["profileList"])
	}
	if len(profileList) != 2 || profileList["Steve"] != "uuid-1" || profileList["Alex"] != "uuid-2" {
		t.Errorf("hub profileList = %v, want Steve=uuid-1 Alex=uuid-2", profileList)
	}
}

func TestSyncEmptyLocalProfilesSendsEmptyMap(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	var gotHubBody map[string]any
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
		case "/sync":
			if err := json.NewDecoder(r.Body).Decode(&gotHubBody); err != nil {
				t.Errorf("decode hub sync body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
	}))
	defer hub.Close()

	elementskin := elementskinAdminServer(t, nil, http.StatusOK)
	defer elementskin.Close()

	srv := newTestServerWithBackends(t, hub, elementskin)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp := signedPost(t, testServer.URL+"/api/union/member/sync", `{}`, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("sync status = %d, want 200: %s", resp.StatusCode, string(respBody))
	}

	profileList, ok := gotHubBody["profileList"].(map[string]any)
	if !ok {
		t.Fatalf("profileList = %v, want map", gotHubBody["profileList"])
	}
	if len(profileList) != 0 {
		t.Errorf("hub profileList = %v, want empty", profileList)
	}
}

func TestSyncReturns500WhenAdminAPIFails(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
		case "/sync":
			t.Errorf("hub /sync should not be called when admin API fails")
		default:
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
	}))
	defer hub.Close()

	elementskin := elementskinAdminServer(t, nil, http.StatusForbidden)
	defer elementskin.Close()

	srv := newTestServerWithBackends(t, hub, elementskin)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp := signedPost(t, testServer.URL+"/api/union/member/sync", `{}`, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("sync status = %d, want 500: %s", resp.StatusCode, string(respBody))
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["detail"] != "failed to query local profiles" {
		t.Errorf("detail = %q, want failed to query local profiles", body["detail"])
	}
}

func TestSyncPassesThroughHubError(t *testing.T) {
	privPEM, pubPEM, err := union.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	profiles := []map[string]any{
		{"id": "uuid-1", "name": "Steve", "user_id": "u1", "owner_email": "steve@example.com"},
	}

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
		case "/sync":
			w.WriteHeader(http.StatusBadGateway)
		default:
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
	}))
	defer hub.Close()

	elementskin := elementskinAdminServer(t, profiles, http.StatusOK)
	defer elementskin.Close()

	srv := newTestServerWithBackends(t, hub, elementskin)
	testServer := httptest.NewServer(srv.Handler())
	defer testServer.Close()

	resp := signedPost(t, testServer.URL+"/api/union/member/sync", `{}`, privPEM)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("sync status = %d, want 502: %s", resp.StatusCode, string(respBody))
	}
}
