package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/analysis"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestHandleFingerprintAllowlist_RejectsKnownBad pins the load-bearing
// invariant of the "mark benign" surface: the server refuses to allowlist a
// known-bad C2 fingerprint. An analyst (or a forged request) must not be able
// to mute a Cobalt Strike / Sliver match from the wall. A heuristic fingerprint
// adds, lists, and deletes through the normal round-trip.
func TestHandleFingerprintAllowlist_RejectsKnownBad(t *testing.T) {
	s := newFeedsTestServer(t)

	// A real known-bad JA3 from the analysis table.
	var c2JA3 string
	for fp := range analysis.KnownBadJA3 {
		c2JA3 = fp
		break
	}
	if c2JA3 == "" {
		t.Fatal("expected at least one known-bad JA3 in analysis.KnownBadJA3")
	}

	// Reject: allowlisting a known-bad fingerprint must fail and add nothing.
	body, _ := json.Marshal(map[string]string{"kind": "ja3", "fingerprint": c2JA3, "note": "nope"})
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/fingerprint-allowlist", bytes.NewReader(body)), model.RoleAnalyst)
	w := httptest.NewRecorder()
	s.handleFingerprintAllowlist(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST known-bad fingerprint: status = %d, want 400", w.Code)
	}
	if got := len(s.store.ListFingerprintAllowlist()); got != 0 {
		t.Fatalf("known-bad fingerprint was added (len=%d), want 0", got)
	}

	// Accept: a heuristic (non-known-bad) fingerprint adds.
	body, _ = json.Marshal(map[string]string{"kind": "ja4", "fingerprint": "t13d_benign_shape", "note": "EDR agent"})
	req = withUser(httptest.NewRequest(http.MethodPost, "/api/fingerprint-allowlist", bytes.NewReader(body)), model.RoleAnalyst)
	w = httptest.NewRecorder()
	s.handleFingerprintAllowlist(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST benign fingerprint: status = %d, want 200", w.Code)
	}

	// List shows the one entry.
	req = withUser(httptest.NewRequest(http.MethodGet, "/api/fingerprint-allowlist", nil), model.RoleAnalyst)
	w = httptest.NewRecorder()
	s.handleFingerprintAllowlist(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: status = %d, want 200", w.Code)
	}
	var list []model.FingerprintAllowEntry
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 || list[0].Fingerprint != "t13d_benign_shape" {
		t.Fatalf("list = %+v, want one entry for the benign fingerprint", list)
	}

	// Viewers can't mark benign.
	body, _ = json.Marshal(map[string]string{"kind": "ja4", "fingerprint": "t13d_other", "note": ""})
	req = withUser(httptest.NewRequest(http.MethodPost, "/api/fingerprint-allowlist", bytes.NewReader(body)), model.RoleViewer)
	w = httptest.NewRecorder()
	s.handleFingerprintAllowlist(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer POST: status = %d, want 403", w.Code)
	}

	// Delete removes the entry.
	id := list[0].ID
	req = withUser(httptest.NewRequest(http.MethodDelete, "/api/fingerprint-allowlist/"+itoa(id), nil), model.RoleAnalyst)
	w = httptest.NewRecorder()
	s.handleDeleteFingerprintAllow(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE: status = %d, want 200", w.Code)
	}
	if got := len(s.store.ListFingerprintAllowlist()); got != 0 {
		t.Errorf("after delete, list len = %d, want 0", got)
	}
}

func itoa(i int64) string {
	return strconv.FormatInt(i, 10)
}
