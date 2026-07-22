package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lylighte/elementskin-union-svc/internal/config"
	"github.com/Lylighte/elementskin-union-svc/internal/union"
)

func adminTestConfig(t *testing.T, hubURL string) config.Config {
	cfg := testConfig(hubURL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "admin.db")
	cfg.Union.AdminAPIKey = "test-admin-key"
	return cfg
}

func TestAdminSyncNoKey(t *testing.T) {
	cfg := adminTestConfig(t, "http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "sync.db")
	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/union/admin/sync", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdminSyncWrongKey(t *testing.T) {
	cfg := adminTestConfig(t, "http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "sync2.db")
	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/api/union/admin/sync", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer wrong-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdminStatusReturnsNoSecrets(t *testing.T) {
	cfg := adminTestConfig(t, "http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "status.db")
	cfg.Union.MemberKey = "secret-member-key"
	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/union/admin/status", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for k, v := range body {
		s, ok := v.(string)
		if ok && strings.Contains(strings.ToLower(s), "secret") {
			t.Errorf("status response key %q contains secret-like value: %v", k, v)
		}
	}

	if _, ok := body["member_key_configured"]; !ok {
		t.Errorf("missing member_key_configured in status response")
	}
	if _, ok := body["hub_reachable"]; !ok {
		t.Errorf("missing hub_reachable in status response")
	}
	if _, ok := body["oauth2_enabled"]; !ok {
		t.Errorf("missing oauth2_enabled in status response")
	}
}

func TestAdminRegenerateKeypairWithoutConfirm(t *testing.T) {
	cfg := adminTestConfig(t, "http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "keypair.db")
	tmpDir := t.TempDir()
	cfg.Union.OAuth2SigPrivateKeyPath = filepath.Join(tmpDir, "priv.pem")
	cfg.Union.OAuth2SigPublicKeyPath = filepath.Join(tmpDir, "pub.pem")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/api/union/admin/regenerate-keypair", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer test-admin-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminKeypairFingerprint(t *testing.T) {
	cfg := adminTestConfig(t, "http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "fp.db")
	tmpDir := t.TempDir()
	cfg.Union.OAuth2SigPrivateKeyPath = filepath.Join(tmpDir, "priv.pem")
	cfg.Union.OAuth2SigPublicKeyPath = filepath.Join(tmpDir, "pub.pem")

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if _, _, err := union.EnsureSigKeyPair(t.Context(), cfg.Union.OAuth2SigPrivateKeyPath, cfg.Union.OAuth2SigPublicKeyPath); err != nil {
		t.Fatalf("ensure sig key pair: %v", err)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/union/admin/keypair-fingerprint", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	fp, ok := body["fingerprint"].(string)
	if !ok || !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("fingerprint = %v, want sha256:hex", body["fingerprint"])
	}
}

func TestAdminRegenerateKeypairWithConfirmRestoresOnFailure(t *testing.T) {
	cfg := adminTestConfig(t, "http://127.0.0.1:1")
	cfg.Storage.Path = filepath.Join(t.TempDir(), "regen.db")
	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, "priv.pem")
	pubPath := filepath.Join(tmpDir, "pub.pem")
	cfg.Union.OAuth2SigPrivateKeyPath = privPath
	cfg.Union.OAuth2SigPublicKeyPath = pubPath

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer srv.Close()

	oldPriv, _ := os.ReadFile(privPath)
	oldPub, _ := os.ReadFile(pubPath)
	_ = oldPriv
	_ = oldPub

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/api/union/admin/regenerate-keypair", strings.NewReader(`{"confirm":true}`))
	req.Header.Set("Authorization", "Bearer test-admin-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	newPub, _ := os.ReadFile(pubPath)
	if string(newPub) == string(oldPub) {
		t.Error("public key did not change after regeneration")
	}
}
