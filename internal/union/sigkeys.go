package union

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const rsaKeySizeBits = 4096

// GenerateRSAKeyPair4096 generates a new RSA 4096-bit key pair and returns the
// private key encoded as PKCS#1 PEM and the public key encoded as PKIX PEM.
func GenerateRSAKeyPair4096() (privatePEM, publicPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeySizeBits)
	if err != nil {
		return "", "", fmt.Errorf("generate rsa 4096 key: %w", err)
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

// EnsureSigKeyPair loads an existing RSA signature key pair from the filesystem
// or generates a new 4096-bit pair when either file is missing.
//
// If both files exist and are non-empty, their contents are read and validated
// by parsing the PEM blocks. Corrupt existing keys are reported as errors and
// are never silently overwritten.
//
// Newly generated keys are written with 0600 permissions for the private key
// and 0644 permissions for the public key.
func EnsureSigKeyPair(ctx context.Context, privateKeyPath, publicKeyPath string) (privatePEM, publicPEM string, err error) {
	privateExists, err := fileExistsAndNonEmpty(privateKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("check private key path: %w", err)
	}
	publicExists, err := fileExistsAndNonEmpty(publicKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("check public key path: %w", err)
	}

	if privateExists && publicExists {
		privatePEM, publicPEM, err = loadAndValidateKeyPair(privateKeyPath, publicKeyPath)
		if err != nil {
			return "", "", fmt.Errorf("validate existing key pair: %w", err)
		}
		return privatePEM, publicPEM, nil
	}

	privatePEM, publicPEM, err = GenerateRSAKeyPair4096()
	if err != nil {
		return "", "", fmt.Errorf("generate signature key pair: %w", err)
	}

	if err := os.WriteFile(privateKeyPath, []byte(privatePEM), 0o600); err != nil {
		return "", "", fmt.Errorf("write private key file: %w", err)
	}
	if err := os.WriteFile(publicKeyPath, []byte(publicPEM), 0o644); err != nil {
		return "", "", fmt.Errorf("write public key file: %w", err)
	}

	return privatePEM, publicPEM, nil
}

func fileExistsAndNonEmpty(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.IsDir() {
		return false, fmt.Errorf("path %q is a directory", path)
	}
	return info.Size() > 0, nil
}

func loadAndValidateKeyPair(privateKeyPath, publicKeyPath string) (privatePEM, publicPEM string, err error) {
	privBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("read private key file: %w", err)
	}
	pubBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("read public key file: %w", err)
	}

	if err := validatePrivateKeyPEM(privBytes); err != nil {
		return "", "", fmt.Errorf("invalid private key: %w", err)
	}
	if err := validatePublicKeyPEM(pubBytes); err != nil {
		return "", "", fmt.Errorf("invalid public key: %w", err)
	}

	return string(privBytes), string(pubBytes), nil
}

func validatePrivateKeyPEM(pemData []byte) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return fmt.Errorf("parse pkcs1 private key: %w", err)
	}
	return nil
}

func validatePublicKeyPEM(pemData []byte) error {
	if _, err := parseRSAPublicKey(pemData); err != nil {
		return err
	}
	return nil
}
