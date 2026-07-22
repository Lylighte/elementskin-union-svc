package union

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// VerifyInboundRequest verifies that an inbound webhook from the Union Hub is
// authentic. It checks headers, nonce replay, timestamp window, and the RSA
// signature, then logs the nonce. The request body is restored so downstream
// handlers can read it.
func (c *Client) VerifyInboundRequest(ctx context.Context, r *http.Request) error {
	sig := r.Header.Get(signatureHeader)
	ts := r.Header.Get(timestampHeader)
	nonce := r.Header.Get(nonceHeader)
	if sig == "" || ts == "" || nonce == "" {
		return ErrMissingSignatureHeaders
	}

	used, err := c.nonces.IsUsed(ctx, nonce)
	if err != nil {
		return fmt.Errorf("check nonce: %w", err)
	}
	if used {
		return ErrReplay
	}

	timestamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("parse timestamp: %w", err)
	}
	now := time.Now().Unix()
	if timestamp < now-10 || timestamp > now+30 {
		return ErrTimestampOutOfWindow
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))

	pubKey, err := c.fetchHubPublicKey(ctx)
	if err != nil {
		return fmt.Errorf("fetch hub public key: %w", err)
	}

	if err := VerifyInboundSignature(string(body), sig, ts, nonce, []byte(pubKey)); err != nil {
		return err
	}

	if err := c.nonces.LogNonce(ctx, nonce); err != nil {
		return fmt.Errorf("log nonce: %w", err)
	}

	return nil
}

// SignInboundRequest signs a request body using the provided RSA private key
// and returns the headers that VerifyInboundRequest expects. It is a test
// helper and is not used for production traffic.
func SignInboundRequest(body string, key *rsa.PrivateKey) (signatureB64, timestamp, nonce string, err error) {
	timestamp = strconv.FormatInt(time.Now().Unix(), 10)
	nonce, err = randomNonce()
	if err != nil {
		return "", "", "", fmt.Errorf("generate nonce: %w", err)
	}

	signedData := []byte(body + timestamp + nonce)
	digest := sha256.Sum256(signedData)

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", "", "", fmt.Errorf("sign request: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sig), timestamp, nonce, nil
}

// GenerateRSAKeyPair returns a PEM-encoded RSA key pair for tests.
func GenerateRSAKeyPair() (privatePEM, publicPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate rsa key: %w", err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return string(privPEM), string(pubPEM), nil
}

func (c *Client) fetchHubPublicKey(ctx context.Context) (string, error) {
	c.mu.RLock()
	if c.pubKey != "" && time.Since(c.pubKeyAt) < publicKeyCacheTTL {
		defer c.mu.RUnlock()
		return c.pubKey, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pubKey != "" && time.Since(c.pubKeyAt) < publicKeyCacheTTL {
		return c.pubKey, nil
	}

	body, err := c.request(ctx, http.MethodGet, "", nil, nil)
	if err != nil {
		return "", err
	}

	var resp struct {
		UnionHostSignaturePublicKey string `json:"union_host_signature_public_key"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("decode hub public key response: %w", err)
	}
	if resp.UnionHostSignaturePublicKey == "" {
		return "", fmt.Errorf("hub public key missing from response")
	}

	c.pubKey = resp.UnionHostSignaturePublicKey
	c.pubKeyAt = time.Now()
	return c.pubKey, nil
}

func randomNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

const publicKeyCacheTTL = 60 * time.Second
