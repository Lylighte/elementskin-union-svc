package union

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVerifyInboundRequestMissingHeaders(t *testing.T) {
	client := newTestClient(t, "http://unused")
	defer client.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/union/member/updatelist", nil)
	if err := client.VerifyInboundRequest(context.Background(), req); err != ErrMissingSignatureHeaders {
		t.Fatalf("expected ErrMissingSignatureHeaders, got %v", err)
	}
}

func TestVerifyInboundRequestReplay(t *testing.T) {
	client := newTestClient(t, "http://unused")
	defer client.Close()

	if err := client.nonces.LogNonce(context.Background(), "replayed-nonce"); err != nil {
		t.Fatalf("log nonce failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/union/member/updatelist", nil)
	req.Header.Set(signatureHeader, "sig")
	req.Header.Set(timestampHeader, strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set(nonceHeader, "replayed-nonce")

	if err := client.VerifyInboundRequest(context.Background(), req); err != ErrReplay {
		t.Fatalf("expected ErrReplay, got %v", err)
	}
}

func TestVerifyInboundRequestTimestampOutOfWindow(t *testing.T) {
	client := newTestClient(t, "http://unused")
	defer client.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/union/member/updatelist", nil)
	req.Header.Set(signatureHeader, "sig")
	req.Header.Set(timestampHeader, strconv.FormatInt(time.Now().Unix()-60, 10))
	req.Header.Set(nonceHeader, "nonce-old")

	if err := client.VerifyInboundRequest(context.Background(), req); err != ErrTimestampOutOfWindow {
		t.Fatalf("expected ErrTimestampOutOfWindow, got %v", err)
	}
}

func TestVerifyInboundRequestInvalidSignature(t *testing.T) {
	client := newTestClient(t, "http://unused")
	defer client.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/union/member/updatelist", strings.NewReader("{}"))
	req.Header.Set(signatureHeader, "dGVzdA==")
	req.Header.Set(timestampHeader, strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set(nonceHeader, "nonce-invalid")

	if err := client.VerifyInboundRequest(context.Background(), req); err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestVerifyInboundRequestSuccessAndReplay(t *testing.T) {
	privPEM, pubPEM, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"union_host_signature_public_key": pubPEM,
		})
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	defer client.Close()

	body := `{"profileList":[]}`
	sigB64, ts, nonce, err := signRequestWithKey(t, body, privPEM)
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/union/member/updatelist", strings.NewReader(body))
	req.Header.Set(signatureHeader, sigB64)
	req.Header.Set(timestampHeader, ts)
	req.Header.Set(nonceHeader, nonce)

	if err := client.VerifyInboundRequest(context.Background(), req); err != nil {
		t.Fatalf("VerifyInboundRequest failed: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/union/member/updatelist", strings.NewReader(body))
	req2.Header.Set(signatureHeader, sigB64)
	req2.Header.Set(timestampHeader, ts)
	req2.Header.Set(nonceHeader, nonce)
	if err := client.VerifyInboundRequest(context.Background(), req2); err != ErrReplay {
		t.Fatalf("expected ErrReplay on second use, got %v", err)
	}
}

func signRequestWithKey(t *testing.T, body, privPEM string) (string, string, string, error) {
	t.Helper()
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		t.Fatal("failed to decode private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "nonce-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	signedData := []byte(body + ts + nonce)
	digest := sha256.Sum256(signedData)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return base64.StdEncoding.EncodeToString(sig), ts, nonce, nil
}
