package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/bridge"
	"github.com/Lylighte/elementskin-union-svc/internal/config"
)

const testCookieName = "union_svc_session"

func newOAuth2TestConfig(t *testing.T, hubURL, elementskinURL string) config.Config {
	t.Helper()
	cfg := testConfig(elementskinURL)
	cfg.Storage.Path = filepath.Join(t.TempDir(), "settings.db")
	cfg.Union.HubURL = hubURL
	cfg.Union.MemberKey = "test-member-key"
	cfg.Union.EnableOAuth2 = true
	cfg.Union.CORSAllowOrigin = ""
	cfg.Union.OAuth2SigPrivateKeyPath = filepath.Join(t.TempDir(), "oauth2_sig_private.pem")
	cfg.Union.OAuth2SigPublicKeyPath = filepath.Join(t.TempDir(), "oauth2_sig_public.pem")
	return cfg
}

func newOAuth2TestServer(t *testing.T, cfg config.Config) *Server {
	t.Helper()
	srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func createSession(t *testing.T, srv *Server, accessToken string) string {
	t.Helper()
	sessionID, err := srv.sessionStore.Create(context.Background(), accessToken, time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return sessionID
}

func serveGet(t *testing.T, handler http.HandlerFunc, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

func TestOAuth2GetSigPublicKeyReturnsKey(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected hub call to %s", r.URL.Path)
	}))
	defer hub.Close()

	cfg := newOAuth2TestConfig(t, hub.URL, "http://127.0.0.1:1")
	srv := newOAuth2TestServer(t, cfg)

	rr := serveGet(t, srv.handleOAuth2GetSigPublicKey, "/api/union/member/oauth2/", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	pubPEM := body["signaturePublicKey"]
	if pubPEM == "" {
		t.Fatal("signaturePublicKey is empty")
	}

	// The PEM must be parseable as a 4096-bit RSA public key.
	pub, err := parseOAuth2RSAPublicKey([]byte(pubPEM))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if pub.Size()*8 != 4096 {
		t.Fatalf("public key size = %d bits, want 4096", pub.Size()*8)
	}
}

func TestOAuth2GetSigPublicKeyDisabled(t *testing.T) {
	cfg := newOAuth2TestConfig(t, "http://127.0.0.1:1", "http://127.0.0.1:1")
	cfg.Union.EnableOAuth2 = false
	srv := newOAuth2TestServer(t, cfg)

	rr := serveGet(t, srv.handleOAuth2GetSigPublicKey, "/api/union/member/oauth2/", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	assertDetail(t, rr.Body.String(), "oauth2 not enabled")
}

func TestOAuth2GetSigPublicKeyCORS(t *testing.T) {
	cfg := newOAuth2TestConfig(t, "http://127.0.0.1:1", "http://127.0.0.1:1")
	cfg.Union.CORSAllowOrigin = "https://union.example.com"
	srv := newOAuth2TestServer(t, cfg)

	rr := serveGet(t, srv.handleOAuth2GetSigPublicKey, "/api/union/member/oauth2/", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != cfg.Union.CORSAllowOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, cfg.Union.CORSAllowOrigin)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want true", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST" {
		t.Errorf("Access-Control-Allow-Methods = %q, want GET, POST", got)
	}
}

func TestOAuth2GrantDisabled(t *testing.T) {
	cfg := newOAuth2TestConfig(t, "http://127.0.0.1:1", "http://127.0.0.1:1")
	cfg.Union.EnableOAuth2 = false
	srv := newOAuth2TestServer(t, cfg)

	rr := serveGet(t, srv.handleOAuth2Grant, "/api/union/member/oauth2/grant", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	assertDetail(t, rr.Body.String(), "oauth2 not enabled")
}

func TestOAuth2GrantWithoutSessionRedirectsToAuthorize(t *testing.T) {
	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected elementskin call to %s", r.URL.Path)
	}))
	defer elementskin.Close()

	cfg := newOAuth2TestConfig(t, "http://127.0.0.1:1", elementskin.URL)
	srv := newOAuth2TestServer(t, cfg)

	rr := serveGet(t, srv.handleOAuth2Grant, "/api/union/member/oauth2/grant", nil)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", rr.Code, rr.Body.String())
	}

	loc, err := rr.Result().Location()
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if loc.Path != "/oauth/authorize" {
		t.Errorf("location path = %q, want /oauth/authorize", loc.Path)
	}
	if loc.Scheme+"://"+loc.Host != elementskin.URL {
		t.Errorf("location host = %q, want %q", loc.Scheme+"://"+loc.Host, elementskin.URL)
	}
	q := loc.Query()
	if q.Get("scope") != "account.read.self profile.read.owned" {
		t.Errorf("scope = %q, want account.read.self profile.read.owned", q.Get("scope"))
	}
	if q.Get("redirect_uri") != cfg.Elementskin.OAuth.RedirectURI {
		t.Errorf("redirect_uri = %q, want %q", q.Get("redirect_uri"), cfg.Elementskin.OAuth.RedirectURI)
	}
}

func TestOAuth2GrantWithValidSession(t *testing.T) {
	hubPrivKey, hubPubPEM := generateRSAKeyPair(t, 2048)
	hub := newMockHubOAuth2(t, hubPubPEM)
	defer hub.Close()

	wantUser := bridge.UserInfo{
		ID:          "user-abc",
		DisplayName: "Alice",
		Email:       "alice@example.com",
	}
	elementskin := newMockElementSkinUserInfo(t, wantUser)
	defer elementskin.Close()

	cfg := newOAuth2TestConfig(t, hub.URL, elementskin.URL)
	srv := newOAuth2TestServer(t, cfg)

	sessionID := createSession(t, srv, "valid-access-token")
	cookie := &http.Cookie{Name: testCookieName, Value: sessionID}

	rr := serveGet(t, srv.handleOAuth2Grant, "/api/union/member/oauth2/grant?state=xyz", []*http.Cookie{cookie})
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", rr.Code, rr.Body.String())
	}

	loc, err := rr.Result().Location()
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if loc.Path != "/oauth2/continue" {
		t.Errorf("location path = %q, want /oauth2/continue", loc.Path)
	}
	if loc.Scheme+"://"+loc.Host != cfg.Union.HubURL {
		t.Errorf("location host = %q, want %q", loc.Scheme+"://"+loc.Host, cfg.Union.HubURL)
	}

	q := loc.Query()
	if q.Get("state") != "xyz" {
		t.Errorf("state = %q, want xyz", q.Get("state"))
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

	// userInfo is standard base64.
	userInfoPayload, err := base64.StdEncoding.DecodeString(token.UserInfo)
	if err != nil {
		t.Fatalf("decode userInfo: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(userInfoPayload, &payload); err != nil {
		t.Fatalf("decode userInfo payload: %v", err)
	}
	if payload["uid"] != wantUser.ID {
		t.Errorf("uid = %v, want %v", payload["uid"], wantUser.ID)
	}
	if payload["nickname"] != wantUser.DisplayName {
		t.Errorf("nickname = %v, want %v", payload["nickname"], wantUser.DisplayName)
	}
	if payload["email"] != wantUser.Email {
		t.Errorf("email = %v, want %v", payload["email"], wantUser.Email)
	}
	expiresAt, ok := payload["expires_at"].(float64)
	if !ok {
		t.Fatalf("expires_at type = %T, want number", payload["expires_at"])
	}
	wantExpires := float64(time.Now().Unix() + 600)
	if expiresAt < wantExpires-5 || expiresAt > wantExpires+5 {
		t.Errorf("expires_at = %v, want near %v", expiresAt, wantExpires)
	}

	// MAC is hex.
	if _, err := hexDecodeString(token.Mac); err != nil {
		t.Errorf("mac is not valid hex: %v", err)
	}
	expectedMAC := hmacSHA256Hex(token.UserInfo, cfg.Union.MemberKey)
	if token.Mac != expectedMAC {
		t.Errorf("mac = %q, want %q", token.Mac, expectedMAC)
	}

	// Signature is standard base64.
	sigBytes, err := base64.StdEncoding.DecodeString(token.Signature)
	if err != nil {
		t.Errorf("signature is not valid standard base64: %v", err)
	}

	// Verify signature with the public key written by EnsureSigKeyPair.
	pubPEM, err := readFileString(cfg.Union.OAuth2SigPublicKeyPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	pubKey, err := parseOAuth2RSAPublicKey([]byte(pubPEM))
	if err != nil {
		t.Fatalf("parse sig public key: %v", err)
	}
	payloadToSign := token.UserInfo + "." + token.Mac
	digest := sha256.Sum256([]byte(payloadToSign))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestOAuth2GrantOnlyStatePassedThrough(t *testing.T) {
	hubPrivKey, hubPubPEM := generateRSAKeyPair(t, 2048)
	hub := newMockHubOAuth2(t, hubPubPEM)
	defer hub.Close()

	elementskin := newMockElementSkinUserInfo(t, bridge.UserInfo{ID: "u", DisplayName: "n", Email: "e"})
	defer elementskin.Close()

	cfg := newOAuth2TestConfig(t, hub.URL, elementskin.URL)
	srv := newOAuth2TestServer(t, cfg)

	sessionID := createSession(t, srv, "token")
	cookie := &http.Cookie{Name: testCookieName, Value: sessionID}

	rr := serveGet(t, srv.handleOAuth2Grant, "/api/union/member/oauth2/grant?state=s1&foo=bar&nonce=n", []*http.Cookie{cookie})
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", rr.Code, rr.Body.String())
	}

	loc, err := rr.Result().Location()
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	q := loc.Query()
	if q.Get("state") != "s1" {
		t.Errorf("state = %q, want s1", q.Get("state"))
	}
	if q.Get("foo") != "" {
		t.Errorf("foo was passed through: %q", q.Get("foo"))
	}
	if q.Get("nonce") != "" {
		t.Errorf("nonce was passed through: %q", q.Get("nonce"))
	}

	encryptedB64 := q.Get("userInfoToken")
	if encryptedB64 == "" {
		t.Fatal("userInfoToken is empty")
	}
	// Ensure the token can still be decrypted.
	_ = decryptUserInfoToken(t, hubPrivKey, encryptedB64)
}

func TestOAuth2GrantHubPublicKeyFetchFailure(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/backend" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"detail":"hub down"}`))
			return
		}
		t.Errorf("unexpected hub path %s", r.URL.Path)
	}))
	defer hub.Close()

	elementskin := newMockElementSkinUserInfo(t, bridge.UserInfo{ID: "u", DisplayName: "n", Email: "e"})
	defer elementskin.Close()

	cfg := newOAuth2TestConfig(t, hub.URL, elementskin.URL)
	srv := newOAuth2TestServer(t, cfg)

	sessionID := createSession(t, srv, "token")
	cookie := &http.Cookie{Name: testCookieName, Value: sessionID}

	rr := serveGet(t, srv.handleOAuth2Grant, "/api/union/member/oauth2/grant", []*http.Cookie{cookie})
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rr.Code, rr.Body.String())
	}
	assertDetail(t, rr.Body.String(), "failed to fetch hub public key")
}

func newMockHubOAuth2(t *testing.T, pubPEM string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/backend":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"publicKey": pubPEM})
		default:
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
	}))
}

func newMockElementSkinUserInfo(t *testing.T, user bridge.UserInfo) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/users/me" {
			t.Errorf("unexpected elementskin path %s", r.URL.Path)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing bearer authorization: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(user)
	}))
}

func generateRSAKeyPair(t *testing.T, bits int) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
	return key, pubPEM
}

func decryptUserInfoToken(t *testing.T, privKey *rsa.PrivateKey, encryptedB64 string) []byte {
	t.Helper()
	encrypted, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		t.Fatalf("decode encrypted token: %v", err)
	}

	chunkSize := privKey.Size()
	if len(encrypted)%chunkSize != 0 {
		t.Fatalf("encrypted length %d is not a multiple of chunk size %d", len(encrypted), chunkSize)
	}

	var plaintext []byte
	for offset := 0; offset < len(encrypted); offset += chunkSize {
		chunk, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, encrypted[offset:offset+chunkSize])
		if err != nil {
			t.Fatalf("decrypt chunk: %v", err)
		}
		plaintext = append(plaintext, chunk...)
	}
	return plaintext
}

func assertDetail(t *testing.T, body, want string) {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("decode body %q: %v", body, err)
	}
	if m["detail"] != want {
		t.Errorf("detail = %q, want %q", m["detail"], want)
	}
}

func readFileString(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func hexDecodeString(s string) ([]byte, error) {
	return hexDecodeStringImpl(s)
}

func hexDecodeStringImpl(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
