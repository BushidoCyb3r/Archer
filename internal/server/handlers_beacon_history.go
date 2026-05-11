package server

import (
	"encoding/json"
	"net/http"

	"github.com/BushidoCyb3r/Archer/internal/store"
)

// handleFindingHistory serves GET /api/findings/{id}/history. Returns
// the 30-day beacon_history row set for the given finding's
// BeaconHistoryKey, sorted ascending by day_utc. Consumed by the
// SPA's finding-detail evolution chart.
//
// Only Beaconing and HTTP Beaconing findings have history rows;
// other types get an empty array (not a 404) so the SPA can
// unconditionally call this endpoint when opening a detail pane
// without having to first check the type — the empty response
// just means "no chart to render."
func (s *Server) handleFindingHistory(w http.ResponseWriter, r *http.Request, id int) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	f, ok := s.store.GetFinding(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if f.Type != "Beaconing" && f.Type != "HTTP Beaconing" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
		return
	}
	rows := s.store.BeaconHistory(f.BeaconHistoryKey())
	if rows == nil {
		rows = []store.BeaconHistoryRow{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rows)
}
