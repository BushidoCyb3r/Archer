package server

// TLS bootstrap for sensor-facing traffic. Quiver sensors curl Archer over
// HTTPS to fetch the install script and to make their daily checkin, so we
// need a working cert before any sensor can enroll. The default flow is
// fully automatic: on first boot Archer generates a self-signed ed25519
// cert into the data volume and prints its public-key fingerprint, which
// the admin embeds into the install one-liner via curl's --pinnedpubkey.
// Operators who later want to swap in an internal-CA-signed cert just drop
// it into the same paths; no code change required.

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// EnsureTLS makes sure a usable TLS cert/key pair exists in dir. Two
// paths:
//
//  1. Operator-supplied (both files present): parse the cert and
//     key, verify the key matches the cert's public key, verify
//     NotAfter is in the future, return the SubjectPublicKeyInfo
//     fingerprint. Pre-fix only file existence was checked, so an
//     expired / corrupt / key-mismatched cert silently passed
//     through and the listener failed to start with a cryptic
//     OpenSSL-flavored error 30 seconds later when the first sensor
//     connected. Now those failure modes surface as a clear startup
//     error naming the file. Audit 2026-05-10 NEW-25 (operator-CA
//     workflow follow-up).
//
//  2. Auto-gen (either file missing): generate a fresh self-signed
//     ed25519 cert with the host's hostname and non-loopback,
//     non-link-local IPs as SANs, valid for 10 years.
//
// NEW-25 changed the auto-gen template's posture from "CA-shaped"
// (KeyUsageCertSign + IsCA=true) to "server-only end-entity"
// (KeyUsageDigitalSignature | KeyUsageKeyEncipherment, IsCA=false).
// Pinned-pubkey verification doesn't care about chain shape, so no
// existing consumer behavior changes; the narrowing prevents the
// auto-gen cert from acquiring CA semantics if it ever lands in a
// system trust store via update-ca-certificates or container build.
//
// The fingerprint is in the format curl --pinnedpubkey "sha256//<value>"
// expects, so it can be embedded into the sensor enrollment one-liner.
func EnsureTLS(dir string) (certPath, keyPath, fingerprint string, err error) {
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	if _, e1 := os.Stat(certPath); e1 == nil {
		if _, e2 := os.Stat(keyPath); e2 == nil {
			fp, e := loadAndValidateOperatorTLS(certPath, keyPath)
			return certPath, keyPath, fp, e
		}
	}
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return
	}
	tpl := x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "archer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		// Server-only end-entity posture. CA capability isn't needed
		// — pinned-pubkey verification matches the SubjectPublicKey-
		// Info, not the chain. Audit 2026-05-10 NEW-25.
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              localDNSNames(),
		IPAddresses:           localIPs(),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, pub, priv)
	if err != nil {
		return
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return
	}
	if err = writePEM(certPath, "CERTIFICATE", der, 0o600); err != nil {
		return
	}
	if err = writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return
	}
	fingerprint = pinnedPubkeyFromDER(der)
	log.Printf("server: generated self-signed TLS cert at %s (sha256//%s)", certPath, fingerprint)
	return
}

// pinnedPubkeyFromDER returns the base64-encoded SHA256 of the cert's
// SubjectPublicKeyInfo. This is the form curl --pinnedpubkey "sha256//..."
// expects, matching `openssl x509 -pubkey | openssl pkey -pubin -outform der
// | openssl dgst -sha256 -binary | base64`.
func pinnedPubkeyFromDER(der []byte) string {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// loadAndValidateOperatorTLS handles path 1 of EnsureTLS — the
// operator-supplied cert + key workflow. Verifies the cert is parsable
// and not expired, the key is parsable, and the key's public component
// matches the cert's. Surfaces a clear error naming the file on any
// failure so the operator sees a startup message they can act on,
// rather than a cryptic TLS handshake failure 30 seconds later when
// the first sensor connects. Audit 2026-05-10 NEW-25 (operator-CA
// workflow follow-up).
func loadAndValidateOperatorTLS(certPath, keyPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("server: read cert %s: %w", certPath, err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return "", fmt.Errorf("server: %s contains no PEM block", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("server: parse cert %s: %w", certPath, err)
	}
	now := time.Now()
	if now.After(cert.NotAfter) {
		return "", fmt.Errorf("server: cert %s expired %s", certPath, cert.NotAfter.Format(time.RFC3339))
	}
	if now.Before(cert.NotBefore) {
		return "", fmt.Errorf("server: cert %s not valid until %s", certPath, cert.NotBefore.Format(time.RFC3339))
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("server: read key %s: %w", keyPath, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return "", fmt.Errorf("server: %s contains no PEM block", keyPath)
	}
	priv, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try the legacy formats — operator may have generated
		// the key with `openssl genrsa`/`openssl ecparam` and
		// shipped PKCS#1 / SEC1 PEM. A clear error here saves
		// the operator from staring at an opaque "tls: failed to
		// parse private key" at handshake time.
		if rsaKey, e2 := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); e2 == nil {
			priv = rsaKey
		} else if ecKey, e3 := x509.ParseECPrivateKey(keyBlock.Bytes); e3 == nil {
			priv = ecKey
		} else {
			return "", fmt.Errorf("server: parse key %s (tried PKCS#8, PKCS#1, SEC1): %w", keyPath, err)
		}
	}
	signer, ok := priv.(interface{ Public() crypto.PublicKey })
	if !ok {
		return "", fmt.Errorf("server: key %s does not implement crypto.Signer", keyPath)
	}
	if !publicKeysEqual(signer.Public(), cert.PublicKey) {
		return "", fmt.Errorf("server: key %s does not match cert %s public key", keyPath, certPath)
	}
	return pinnedPubkeyFromDER(certBlock.Bytes), nil
}

// publicKeysEqual compares two crypto.PublicKey values structurally.
// Different key types (RSA vs ECDSA vs Ed25519) all expose Equal as
// of Go 1.15+; we type-assert to that interface.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface {
		Equal(crypto.PublicKey) bool
	}
	if eq, ok := a.(equaler); ok {
		return eq.Equal(b)
	}
	return false
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

// localDNSNames returns hostname plus localhost so a sensor that resolves
// Archer by name validates the cert. Always includes "localhost" so local
// curl-from-the-host smoke tests work.
func localDNSNames() []string {
	out := []string{"localhost"}
	if h, err := os.Hostname(); err == nil && h != "" {
		out = append(out, h)
	}
	return out
}

// localIPs returns all non-loopback, non-link-local IPs assigned to
// the host. Sensors that connect by IP need an IP-SAN match;
// loopbacks (127.0.0.1, ::1) and IPv6 link-local addresses (fe80::/10)
// are skipped because no sensor talks to either — link-local
// addresses are interface-scoped and require zone identifiers to be
// reachable, so including them just bloats the cert. Audit
// 2026-05-10 LOW.
func localIPs() []net.IP {
	var out []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ipnet.IP)
	}
	return out
}
