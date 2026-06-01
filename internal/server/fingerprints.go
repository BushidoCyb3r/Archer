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
	rows := s.store.FingerprintInventory(analysis.KnownBadJA4, analysis.KnownBadJA3)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(rows)
}
