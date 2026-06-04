package server

// TLS-fingerprint inventory: the read-only surface behind the "TLS
// Fingerprints" filter-bar button. Returns the high-signal JA3/JA4 client
// fingerprints from the latest analysis pass ranked by severity (known-bad C2
// matches plus rare/cross-host shapes), so an analyst can hunt fingerprint-first
// and pivot into the matching findings via the ja3/ja4 filter.

import (
	"encoding/json"
	"net/http"

	"github.com/BushidoCyb3r/Archer/internal/analysis"
)

// handleFingerprints serves GET /api/fingerprints. Analyst+ (read-only TLS
// telemetry, not credentials). The known-bad maps live in the analysis package;
// they're handed to the store here so the store stays independent of analysis.
func (s *Server) handleFingerprints(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Union the operator JA3/JA4 IOC list into the known-bad maps so an
	// operator-flagged fingerprint shows as known-bad (critical, non-markable)
	// on the wall immediately — the same status its built-in siblings carry —
	// rather than waiting for the next analysis to produce a Malicious finding.
	opJA3, opJA4 := analysis.ClassifyFingerprints(s.store.GetIOCFingerprints())
	badJA4 := unionFingerprintLabels(analysis.KnownBadJA4, opJA4)
	badJA3 := unionFingerprintLabels(analysis.KnownBadJA3, opJA3)
	rows := s.store.FingerprintInventory(badJA4, badJA3)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(rows)
}

// unionFingerprintLabels returns built ∪ extra without mutating either input.
// Built-in labels win on overlap so a renamed operator entry can't shadow a
// canonical C2 family name.
func unionFingerprintLabels(builtin, extra map[string]string) map[string]string {
	out := make(map[string]string, len(builtin)+len(extra))
	for fp, label := range extra {
		out[fp] = label
	}
	for fp, label := range builtin {
		out[fp] = label
	}
	return out
}
