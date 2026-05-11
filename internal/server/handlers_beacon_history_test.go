package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

// TestFindingHistory_NotFoundForUnknownID asserts the endpoint returns
// 404 when the finding doesn't exist, rather than an empty array (which
// would let a UI bug silently treat "no such finding" as "no history
// yet" and never surface the underlying mistake).
func TestFindingHistory_NotFoundForUnknownID(t *testing.T) {
	s := newAuditTestServer(t)
	w := httptest.NewRecorder()
	s.handleFindingHistory(w, httptest.NewRequest(http.MethodGet, "/api/findings/999/history", nil), 999)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// TestFindingHistory_EmptyArrayForNonBeacon asserts the endpoint
// returns [] (not 404, not error) for finding types that don't carry
// beacon_history rows. The SPA calls this unconditionally when opening
// a detail pane; the empty array is the "no chart to render" signal.
func TestFindingHistory_EmptyArrayForNonBeacon(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		{ID: 1, Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: "53",
			Score: 60, Severity: model.SevMedium, Timestamp: "2026-05-11 09:00:00"},
	})

	w := httptest.NewRecorder()
	s.handleFindingHistory(w, httptest.NewRequest(http.MethodGet, "/api/findings/1/history", nil), 1)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rows []store.BeaconHistoryRow
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("rows = %d, want 0 (non-beacon type has no history)", len(rows))
	}
}

// TestFindingHistory_ReturnsBeaconRows asserts the happy path: a
// Beaconing finding's history endpoint returns the row written by the
// preceding SetFindings call, with the four sub-axis scores intact.
func TestFindingHistory_ReturnsBeaconRows(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
			Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00",
			Hostname:  "kx9j3qm2pflw.com",
			TSScore:   0.92,
			DSScore:   0.88,
			HistScore: 0.10,
			DurScore:  0.95,
		},
	})

	w := httptest.NewRecorder()
	s.handleFindingHistory(w, httptest.NewRequest(http.MethodGet, "/api/findings/1/history", nil), 1)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rows []store.BeaconHistoryRow
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.MaxScore != 80 {
		t.Errorf("MaxScore = %d, want 80", r.MaxScore)
	}
	if r.LastScore != 80 {
		t.Errorf("LastScore = %d, want 80 (single-write day)", r.LastScore)
	}
	if r.TSScore != 0.92 {
		t.Errorf("TSScore = %f, want 0.92", r.TSScore)
	}
	if r.DSScore != 0.88 {
		t.Errorf("DSScore = %f, want 0.88", r.DSScore)
	}
	if r.HistScore != 0.10 {
		t.Errorf("HistScore = %f, want 0.10", r.HistScore)
	}
	if r.DurScore != 0.95 {
		t.Errorf("DurScore = %f, want 0.95", r.DurScore)
	}
}

// TestFindingHistory_MethodNotAllowed asserts non-GET requests are
// rejected. The endpoint is read-only — no PATCH semantics, no POST
// shape, no DELETE (retention handles cleanup).
func TestFindingHistory_MethodNotAllowed(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
			Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00"},
	})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		w := httptest.NewRecorder()
		s.handleFindingHistory(w, httptest.NewRequest(method, "/api/findings/1/history", nil), 1)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s status = %d, want 405", method, w.Code)
		}
	}
}
