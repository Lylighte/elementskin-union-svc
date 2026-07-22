package server

import (
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
	"testing"
)

// decodePrivateKey parses a PEM-encoded PKCS#1 RSA private key for tests.
func decodePrivateKey(t *testing.T, privPEM string) *rsa.PrivateKey {
	t.Helper()

	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		t.Fatal("failed to decode private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	return key
}

// signWithTimestamp signs body with the provided private key and an explicit
// timestamp, returning the signature and nonce. It mirrors union.SignInboundRequest
// but allows forcing an expired or otherwise chosen timestamp.
func signWithTimestamp(t *testing.T, body, privPEM, timestamp string) (sig, nonce string) {
	t.Helper()

	key := decodePrivateKey(t, privPEM)

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}
	nonce = base64.RawURLEncoding.EncodeToString(b)

	signed := []byte(body + timestamp + nonce)
	digest := sha256.Sum256(signed)

	raw, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nonce
}

// hubServer returns a mock Union Hub that advertises pubPEM at / and delegates
// all other routes to handler.
func hubServer(t *testing.T, pubPEM string, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"union_host_signature_public_key": pubPEM,
			})
			return
		}
		handler(w, r)
	}))
}
