package union

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
)

const (
	memberKeyHeader     = "X-Union-Member-Key"
	signatureHeader     = "X-Message-Signature"
	timestampHeader     = "X-Message-Timestamp"
	nonceHeader         = "X-Message-Nonce"
	signedDataSeparator = ""
)

// SignOutbound authenticates an outbound request to the Union Hub using the
// shared member key. The protocol places the key in the X-Union-Member-Key
// header.
func SignOutbound(req *http.Request, memberKey string) {
	if req == nil {
		return
	}
	req.Header.Set(memberKeyHeader, memberKey)
}

// VerifyInboundSignature verifies that signatureB64 is a valid RSA-SHA256
// signature over body+timestamp+nonce made with the Union Hub public key.
func VerifyInboundSignature(body string, signatureB64, timestamp, nonce string, publicKeyPEM []byte) error {
	if signatureB64 == "" || timestamp == "" || nonce == "" {
		return ErrMissingSignatureHeaders
	}

	pub, err := parseRSAPublicKey(publicKeyPEM)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}

	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	signedData := []byte(body + timestamp + nonce)
	digest := sha256.Sum256(signedData)

	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	return nil
}

func parseRSAPublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		parsed, err2 := x509.ParsePKCS1PublicKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse public key: %v", err)
		}
		return parsed, nil
	}

	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}
	return pub, nil
}
