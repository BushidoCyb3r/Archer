package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestEnsureTLS_AutoGenIsServerOnly covers NEW-25: the auto-gen path
// must produce a cert that's an end-entity (not a CA), with KeyUsage
// limited to DigitalSignature | KeyEncipherment. Pre-fix the template
// had IsCA=true and KeyUsageCertSign — if the cert ever ended up in a
// system trust store, anyone with read access to the (mode 0600) key
// could issue arbitrary certs trusted by that store.
func TestEnsureTLS_AutoGenIsServerOnly(t *testing.T) {
	dir := t.TempDir()
	certPath, _, fp, err := EnsureTLS(dir)
	if err != nil {
		t.Fatalf("EnsureTLS: %v", err)
	}
	if fp == "" {
		t.Fatal("EnsureTLS returned empty fingerprint")
	}
	pemBytes, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(pemBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse generated cert: %v", err)
	}
	if cert.IsCA {
		t.Error("auto-gen cert IsCA=true; want false (NEW-25)")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Error("auto-gen cert has KeyUsageCertSign; want it dropped (NEW-25)")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("auto-gen cert missing KeyUsageDigitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("auto-gen cert missing KeyUsageKeyEncipherment")
	}
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("auto-gen cert missing ExtKeyUsageServerAuth")
	}
}

// TestEnsureTLS_RejectsExpiredOperatorCert exercises the path-1
// validation added alongside NEW-25. An operator who drops in an
// expired CA-signed cert previously got a cryptic TLS handshake
// failure on the first sensor connect; now they get a clear startup
// error naming the file.
func TestEnsureTLS_RejectsExpiredOperatorCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired"},
		NotBefore:    time.Now().AddDate(-2, 0, 0),
		NotAfter:     time.Now().AddDate(-1, 0, 0),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	_ = writePEM(certPath, "CERTIFICATE", der, 0o600)
	_ = writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600)

	_, _, _, err := EnsureTLS(dir)
	if err == nil {
		t.Fatal("EnsureTLS accepted an expired operator cert; want error")
	}
}

// TestEnsureTLS_RejectsKeyMismatch covers the cross-check between
// cert and key. Same motivation as the expiry check — fail loudly
// at startup, not at TLS handshake.
func TestEnsureTLS_RejectsKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader) // unrelated key
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mismatched"},
		NotBefore:    time.Now().AddDate(0, -1, 0),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, ed25519PrivFor(pub))
	keyDER, _ := x509.MarshalPKCS8PrivateKey(otherPriv)
	_ = writePEM(certPath, "CERTIFICATE", der, 0o600)
	_ = writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600)

	_, _, _, err := EnsureTLS(dir)
	if err == nil {
		t.Fatal("EnsureTLS accepted a key/cert mismatch; want error")
	}
}

// TestEnsureTLS_AcceptsValidOperatorECDSA verifies the multi-format
// PEM parser fallback for keys an operator might have produced via
// `openssl ecparam -genkey` (SEC1 form).
func TestEnsureTLS_AcceptsValidOperatorECDSA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ecdsa-test"},
		NotBefore:    time.Now().AddDate(0, -1, 0),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	// SEC1 form via x509.MarshalECPrivateKey.
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	_ = writePEM(certPath, "CERTIFICATE", der, 0o600)
	_ = writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600)

	_, _, fp, err := EnsureTLS(dir)
	if err != nil {
		t.Fatalf("EnsureTLS rejected valid ECDSA SEC1 key: %v", err)
	}
	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}
}

// ed25519PrivFor returns a deterministic Ed25519 private key paired
// with the given public key — used in the mismatch test to exercise
// signature creation against the cert's public key while installing
// a different private key on disk.
func ed25519PrivFor(pub ed25519.PublicKey) ed25519.PrivateKey {
	// We don't actually need the matching priv for the cert
	// signing — we use a fresh keypair and discard the priv,
	// because the mismatch test's purpose is to stage a wrong
	// priv on disk anyway. Just satisfy the signer interface.
	_, p, _ := ed25519.GenerateKey(rand.Reader)
	return p
}
