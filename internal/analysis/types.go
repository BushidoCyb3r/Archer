package analysis

import (
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// sslEntry holds the SSL/TLS metadata indexed by Zeek connection UID.
type sslEntry struct {
	serverName string
	ja3        string
	version    string
	subject    string
	issuer     string
}

// httpEntry holds HTTP metadata indexed by Zeek connection UID.
type httpEntry struct {
	method    string
	host      string
	uri       string
	userAgent string
}

// ProgressEvent is sent to the SSE broker during analysis.
type ProgressEvent struct {
	Pct  int    `json:"pct"`
	Step string `json:"step"`
}

// isPrivateIP returns true for RFC-1918 / loopback / link-local addresses.
func isPrivateIP(ip string) bool {
	if ip == "" {
		return false
	}
	private := []string{
		"10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"127.", "169.254.", "::1", "fc", "fd",
	}
	for _, p := range private {
		if len(ip) >= len(p) && ip[:len(p)] == p {
			return true
		}
	}
	return false
}

// sevFromScore converts a numeric score to a Severity level using generic thresholds.
func sevFromScore(score int) model.Severity {
	switch {
	case score >= 80:
		return model.SevCritical
	case score >= 60:
		return model.SevHigh
	case score >= 40:
		return model.SevMedium
	default:
		return model.SevLow
	}
}

// clamp restricts a value to [lo, hi].
func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
