package analysis

import (
	"net"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// sensorPrevData tracks unique internal source IPs and unique sources per
// external destination within one sensor's capture window. Built during
// analyzeConn and consumed by both the conn-level and HTTP-level beacon
// emit paths to apply a prevalence modifier.
type sensorPrevData struct {
	srcs    map[string]struct{}            // unique internal src IPs
	dstSrcs map[string]map[string]struct{} // external dst → unique internal srcs
}

// beaconSNINeed carries the SNI candidate UIDs for a conn beacon finding that
// needs post-phase-1 enrichment, plus enough context to reverse the rarity
// boost if an SNI is found. unboostedScore is non-zero only when the rare
// boost was applied; prevDetail is the prevalence fragment appended to Detail
// so it can be updated in-place when the boost is suppressed.
//
// chanRecs / winMin / winMax / prevalenceMod / blendScore additionally carry
// everything enrichBeaconSNI needs to split the blend into per-channel beacons
// once sslUIDIndex resolves each UID's JA3 (per-channel scoring, Fork A). They
// are zero/nil when the beacon had no TLS connections.
type beaconSNINeed struct {
	candidates     []string
	prevDetail     string
	unboostedScore int
	chanRecs       []chanRec
	winMin         float64
	winMax         float64
	prevalenceMod  float64
	blendScore     int
}

// sslEntry holds the SSL/TLS metadata indexed by Zeek connection UID.
type sslEntry struct {
	serverName string
	ja3        string
	ja4        string
	version    string
	subject    string
	issuer     string
}

// ProgressEvent is sent to the SSE broker during analysis.
type ProgressEvent struct {
	Pct  int    `json:"pct"`
	Step string `json:"step"`
}

// isPrivateIP returns true for RFC-1918 / loopback / link-local addresses.
// Callers pass DstIP, which for DNS-derived findings holds a domain, not an
// address — so the IPv6 unique-local (fc00::/7) and loopback checks are gated
// on the string actually looking like IPv6 (containing ":"). Without that
// gate the bare "fc"/"fd" prefixes matched domains like fda.gov / fcc.gov and
// silently dropped them from TI matching and staging.
func isPrivateIP(ip string) bool {
	if ip == "" {
		return false
	}
	if strings.Contains(ip, ":") {
		return ip == "::1" || strings.HasPrefix(ip, "fc") || strings.HasPrefix(ip, "fd")
	}
	private := []string{
		"10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"127.", "169.254.",
	}
	for _, p := range private {
		if len(ip) >= len(p) && ip[:len(p)] == p {
			return true
		}
	}
	return false
}

// isLocalInfraDest reports whether ip is a destination that is local network
// infrastructure rather than a routable remote host: multicast (224.0.0.0/4,
// ff00::/8 — mDNS, SSDP, LLMNR), the limited broadcast address, the
// unspecified address, or an IPv6 link-local unicast (fe80::/10). These are
// never a C2 endpoint, but they are NOT caught by isPrivateIP (which only
// covers RFC-1918 / loopback / IPv4 link-local), so without an explicit check
// they slip the `!isPrivateIP(dst)` egress gate and their regular chatter
// (a printer announcing on mDNS, a TV on SSDP) trips the beacon/strobe
// detectors. The egress conn detectors drop such destinations up front.
func isLocalInfraDest(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	return p.IsMulticast() || p.IsLinkLocalUnicast() || p.IsUnspecified() || p.Equal(net.IPv4bcast)
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
