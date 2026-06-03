package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestComputeDetectorActivity pins the capture-regression invariant: a
// detector that produced new findings in the prior 7-day window but none in
// the most recent one is flagged Dropped, while a detector still firing this
// week is not — regardless of how much older history either carries. Roll-up
// types never appear (they mirror the network detectors). The fixed `now`
// makes the two windows deterministic without touching the clock.
func TestComputeDetectorActivity(t *testing.T) {
	const now int64 = 1_700_000_000
	day := int64(86400)
	inRecent := now - 2*day // 2 days ago — last-7-day window
	inPrior := now - 9*day  // 9 days ago — prior-7-day window
	older := now - 30*day   // 30 days ago — outside both windows

	findings := []model.Finding{
		// Beacon: firing in both windows → active, not dropped.
		{Type: "Beacon", DetectedAt: inRecent},
		{Type: "Beacon", DetectedAt: inPrior},
		{Type: "Beacon", DetectedAt: older},
		// DNS Beacon: fired last week, silent this week → DROPPED.
		{Type: "DNS Beacon", DetectedAt: inPrior},
		{Type: "DNS Beacon", DetectedAt: inPrior},
		// Strobe: only ancient history, nothing in either window → quiet, not
		// dropped (we don't alarm on detectors that weren't firing recently).
		{Type: "Strobe", DetectedAt: older},
		// Roll-ups must be excluded entirely.
		{Type: model.TypeHostRiskScore, DetectedAt: inRecent},
		{Type: model.TypeCorrelatedActivity, DetectedAt: inPrior},
	}

	got := computeDetectorActivity(findings, now)

	idx := make(map[string]detectorActivity, len(got))
	for _, d := range got {
		idx[d.Type] = d
	}

	if _, ok := idx[model.TypeHostRiskScore]; ok {
		t.Error("Host Risk Score (roll-up) must be excluded from detector activity")
	}
	if _, ok := idx[model.TypeCorrelatedActivity]; ok {
		t.Error("Correlated Activity (roll-up) must be excluded from detector activity")
	}

	beacon := idx["Beacon"]
	if beacon.Count7d != 1 || beacon.CountPrior != 1 || beacon.Total != 3 {
		t.Errorf("Beacon counts = {7d:%d prior:%d total:%d}, want {1 1 3}", beacon.Count7d, beacon.CountPrior, beacon.Total)
	}
	if beacon.Dropped {
		t.Error("Beacon is still firing this week; must not be flagged dropped")
	}

	dns := idx["DNS Beacon"]
	if dns.Count7d != 0 || dns.CountPrior != 2 {
		t.Errorf("DNS Beacon counts = {7d:%d prior:%d}, want {0 2}", dns.Count7d, dns.CountPrior)
	}
	if !dns.Dropped {
		t.Error("DNS Beacon fired last week and is silent this week; must be flagged dropped")
	}

	strobe := idx["Strobe"]
	if strobe.Dropped {
		t.Error("Strobe had no findings in either window; an ancient-only detector must not false-flag as dropped")
	}

	// Dropped detectors sort first so the alarm leads the tile.
	if len(got) == 0 || !got[0].Dropped {
		t.Errorf("expected a dropped detector to sort first, got %+v", got)
	}
}

// TestHandleDetectorActivity_HTTP exercises the handler end to end: an
// authed GET returns 200 with the documented JSON shape, the detectors the
// store holds appear, and roll-up types are excluded. SetFindings stamps
// DetectedAt=now, so seeded findings land in the recent window — this test
// covers the GetFindings→computeDetectorActivity→JSON wiring; the windowing
// and dropped-flag invariants are pinned deterministically in the pure test.
func TestHandleDetectorActivity_HTTP(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: "443", Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00"},
		{ID: 2, Type: "Beacon", SrcIP: "10.0.0.2", DstIP: "8.8.4.4", DstPort: "443", Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00"},
		{ID: 3, Type: "Strobe", SrcIP: "10.0.0.3", DstIP: "9.9.9.9", DstPort: "53", Score: 60, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00"},
		// Roll-up — must not appear in the response.
		{ID: 4, Type: model.TypeHostRiskScore, SrcIP: "10.0.0.1", DstIP: "(network)", Score: 70, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00"},
	})

	req := withUser(httptest.NewRequest(http.MethodGet, "/api/detector-activity", nil), model.RoleAnalyst)
	w := httptest.NewRecorder()
	s.handleDetectorActivity(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp detectorActivityResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.WindowDays != detectorActivityWindowDays {
		t.Errorf("window_days = %d, want %d", resp.WindowDays, detectorActivityWindowDays)
	}
	got := make(map[string]detectorActivity, len(resp.Detectors))
	for _, d := range resp.Detectors {
		got[d.Type] = d
	}
	if _, ok := got[model.TypeHostRiskScore]; ok {
		t.Error("Host Risk Score (roll-up) must not appear in detector activity")
	}
	if b, ok := got["Beacon"]; !ok || b.Total != 2 {
		t.Errorf("Beacon entry = %+v (ok=%v), want total 2", b, ok)
	}
	if _, ok := got["Strobe"]; !ok {
		t.Error("Strobe should appear in detector activity")
	}
}
