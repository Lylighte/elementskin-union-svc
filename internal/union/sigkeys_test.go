package union

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateRSAKeyPair4096(t *testing.T) {
	privPEM, pubPEM, err := GenerateRSAKeyPair4096()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair4096 failed: %v", err)
	}

	assertParsesAsPKCS1PrivateKey(t, privPEM)
	assertParsesAsPKIXPublicKey(t, pubPEM)
	assertKeySize(t, privPEM, 4096)
}

func TestEnsureSigKeyPairGeneratesMissingFiles(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "oauth2_sig_private.pem")
	publicPath := filepath.Join(dir, "oauth2_sig_public.pem")

	ctx := context.Background()
	privPEM, pubPEM, err := EnsureSigKeyPair(ctx, privatePath, publicPath)
	if err != nil {
		t.Fatalf("EnsureSigKeyPair failed on missing files: %v", err)
	}

	assertFileExistsWithMode(t, privatePath, 0o600)
	assertFileExistsWithMode(t, publicPath, 0o644)

	assertParsesAsPKCS1PrivateKey(t, privPEM)
	assertParsesAsPKIXPublicKey(t, pubPEM)
	assertKeySize(t, privPEM, 4096)

	assertFileContentEquals(t, privatePath, privPEM)
	assertFileContentEquals(t, publicPath, pubPEM)
}

func TestEnsureSigKeyPairReadsExistingFiles(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "oauth2_sig_private.pem")
	publicPath := filepath.Join(dir, "oauth2_sig_public.pem")

	ctx := context.Background()
	firstPriv, firstPub, err := EnsureSigKeyPair(ctx, privatePath, publicPath)
	if err != nil {
		t.Fatalf("first EnsureSigKeyPair failed: %v", err)
	}

	secondPriv, secondPub, err := EnsureSigKeyPair(ctx, privatePath, publicPath)
	if err != nil {
		t.Fatalf("second EnsureSigKeyPair failed: %v", err)
	}

	if firstPriv != secondPriv {
		t.Error("private key changed on second call")
	}
	if firstPub != secondPub {
		t.Error("public key changed on second call")
	}
}

func TestEnsureSigKeyPairRejectsCorruptPrivateKey(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "oauth2_sig_private.pem")
	publicPath := filepath.Join(dir, "oauth2_sig_public.pem")

	ctx := context.Background()
	_, _, err := EnsureSigKeyPair(ctx, privatePath, publicPath)
	if err != nil {
		t.Fatalf("setup: generate key pair failed: %v", err)
	}

	if err := os.WriteFile(privatePath, []byte("not a valid pem"), 0o600); err != nil {
		t.Fatalf("setup: corrupt private key file: %v", err)
	}

	_, _, err = EnsureSigKeyPair(ctx, privatePath, publicPath)
	if err == nil {
		t.Fatal("expected error for corrupt private key, got nil")
	}

	content, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatalf("read corrupted private key file: %v", err)
	}
	if string(content) != "not a valid pem" {
		t.Error("corrupt private key file was overwritten")
	}
}

func assertParsesAsPKCS1PrivateKey(t *testing.T, privPEM string) {
	t.Helper()
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		t.Fatal("failed to decode private key PEM block")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Fatalf("private key does not parse as PKCS#1: %v", err)
	}
}

func assertParsesAsPKIXPublicKey(t *testing.T, pubPEM string) {
	t.Helper()
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatal("failed to decode public key PEM block")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		t.Fatalf("public key does not parse as PKIX: %v", err)
	}
}

func assertKeySize(t *testing.T, privPEM string, bits int) {
	t.Helper()
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		t.Fatal("failed to decode private key PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	if key.N.BitLen() != bits {
		t.Fatalf("expected %d-bit key, got %d", bits, key.N.BitLen())
	}
}

func assertFileExistsWithMode(t *testing.T, path string, wantMode fs.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != wantMode {
		t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), wantMode)
	}
}

func assertFileContentEquals(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s content mismatch", path)
	}
}
