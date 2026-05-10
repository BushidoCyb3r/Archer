package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// quiverCheckinSignature returns the HMAC-SHA256 hex digest of the raw
// JSON body keyed on the sensor's checkin_secret. The sensor signs the
// body it sends; the server reads the same body and re-derives the
// expected signature. Hex (not base64) keeps the wire-format easy to
// emit from a shell script — quiver.sh uses `openssl dgst -hmac …`
// which produces hex by default.
//
// The signed material is the entire request body, not a header
// subset. Including everything makes it impossible to forge a
// checkin's name or protocol_version without also knowing the secret.
// Audit 2026-05-10 NEW-16.
func quiverCheckinSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// validQuiverCheckinSig compares a presented signature against the
// expected one in constant time. hmac.Equal short-circuits the timing
// side-channel that a naive `==` string compare would leave.
func validQuiverCheckinSig(secret string, body []byte, presented string) bool {
	if secret == "" || presented == "" {
		return false
	}
	expected := quiverCheckinSignature(secret, body)
	return hmac.Equal([]byte(expected), []byte(presented))
}
