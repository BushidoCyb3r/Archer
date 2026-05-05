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

// EnsureTLS makes sure a usable TLS cert/key pair exists in dir. If both
// files are present, the existing cert's public-key SHA256 fingerprint is
// returned. If either is missing, a fresh self-signed ed25519 cert is
// generated with the host's hostname and non-loopback IPs as Subject
// Alternative Names, valid for 10 years.
//
// The fingerprint is in the format curl --pinnedpubkey "sha256//<value>"
// expects, so it can be embedded into the sensor enrollment one-liner.
func EnsureTLS(dir string) (certPath, keyPath, fingerprint string, err error) {
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	if _, e1 := os.Stat(certPath); e1 == nil {
		if _, e2 := os.Stat(keyPath); e2 == nil {
			fp, e := readFingerprint(certPath)
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
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
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

func readFingerprint(certPath string) (string, error) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("server: %s contains no PEM block", certPath)
	}
	return pinnedPubkeyFromDER(block.Bytes), nil
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

// localIPs returns all non-loopback IPs assigned to the host. Sensors that
// connect by IP need an IP-SAN match; loopbacks are skipped because no
// sensor talks to 127.0.0.1.
func localIPs() []net.IP {
	var out []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		out = append(out, ipnet.IP)
	}
	return out
}
