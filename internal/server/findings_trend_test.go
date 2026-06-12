package server

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

type trendSeriesJSON struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Counts []int  `json:"counts"`
}

type trendResp struct {
	Days           []string          `json:"days"`
	Series         []trendSeriesJSON `json:"series"`
	SeveritySeries []trendSeriesJSON `json:"severity_series"`
}

func fetchTrend(t *testing.T, s *Server, url string) trendResp {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleFindingsTrend(rec, httptest.NewRequest("GET", url, nil))
	if rec.Code != 200 {
		t.Fatalf("GET %s: status %d, body %s", url, rec.Code, rec.Body.String())
	}
	var resp trendResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse trend response: %v", err)
	}
	return resp
}

// TestFindingsTrend_BucketsAndZeroFills pins the chart's data contract:
// findings bucket into per-UTC-day family counts keyed off the Timestamp
// date prefix, the day axis is contiguous (gap days zero-filled), roll-up
// types and timestamp-less findings are excluded, and families with no
// findings in range are omitted from the series list entirely.
func TestFindingsTrend_BucketsAndZeroFills(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-10 09:00:00"},
		{ID: 2, Type: "HTTP Beacon", SrcIP: "10.0.0.1", DstIP: "1.1.1.2", Score: 75, Severity: model.SevHigh, Timestamp: "2026-05-10 10:00:00"},
		{ID: 3, Type: "TI Hit (IP)", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", Score: 95, Severity: model.SevCritical, Timestamp: "2026-05-12 11:00:00"},
		// Roll-ups are derived from the rows above — counting them would
		// double-count, so they must not appear in any bucket.
		{ID: 4, Type: model.TypeHostRiskScore, SrcIP: "10.0.0.1", Score: 90, Severity: model.SevCritical, Timestamp: "2026-05-12 12:00:00"},
		{ID: 5, Type: model.TypeMultiStageBeacon, SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 85, Severity: model.SevCritical, Timestamp: "2026-05-12 12:00:00"},
		// No timestamp → no day to bucket into; skipped, not crashed on.
		{ID: 6, Type: "Beacon", SrcIP: "10.0.0.3", DstIP: "3.3.3.3", Score: 70, Severity: model.SevMedium},
	})

	resp := fetchTrend(t, s, "/api/findings/trend")

	wantDays := []string{"2026-05-10", "2026-05-11", "2026-05-12"}
	if len(resp.Days) != len(wantDays) {
		t.Fatalf("days = %v, want %v", resp.Days, wantDays)
	}
	for i, d := range wantDays {
		if resp.Days[i] != d {
			t.Fatalf("days = %v, want %v (gap day must be zero-filled)", resp.Days, wantDays)
		}
	}

	series := map[string][]int{}
	for _, sr := range resp.Series {
		series[sr.Key] = sr.Counts
	}
	if got := series["beaconing"]; len(got) != 3 || got[0] != 2 || got[1] != 0 || got[2] != 0 {
		t.Errorf("beaconing counts = %v, want [2 0 0]", got)
	}
	if got := series["ti"]; len(got) != 3 || got[0] != 0 || got[1] != 0 || got[2] != 1 {
		t.Errorf("ti counts = %v, want [0 0 1]", got)
	}
	// Families with no findings must be omitted, and roll-ups must not have
	// landed anywhere (they'd surface in "other").
	for key := range series {
		if key != "beaconing" && key != "ti" {
			t.Errorf("unexpected series %q (roll-up leak or empty family not omitted)", key)
		}
	}

	// The severity lens shares the same day axis and exclusion rules: the
	// two HIGH beacons land on day 1, the CRITICAL TI hit on day 3, the
	// CRITICAL roll-ups don't count (CRITICAL would read 3, not 1, on a
	// leak), the timestamp-less MEDIUM is skipped, and empty tiers are
	// omitted.
	sev := map[string][]int{}
	for _, sr := range resp.SeveritySeries {
		sev[sr.Key] = sr.Counts
	}
	if got := sev["high"]; len(got) != 3 || got[0] != 2 || got[1] != 0 || got[2] != 0 {
		t.Errorf("severity high counts = %v, want [2 0 0]", got)
	}
	if got := sev["critical"]; len(got) != 3 || got[0] != 0 || got[1] != 0 || got[2] != 1 {
		t.Errorf("severity critical counts = %v, want [0 0 1] (roll-ups must not count)", got)
	}
	for key := range sev {
		if key != "high" && key != "critical" {
			t.Errorf("unexpected severity series %q (empty tier not omitted)", key)
		}
	}
}

// TestFindingsTrend_HonorsFilterSurface pins that the trend endpoint sees
// the same view as /api/findings: the q= query language narrows the counts,
// and pagination params are ignored rather than truncating the data.
func TestFindingsTrend_HonorsFilterSurface(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Timestamp: "2026-05-10 09:00:00"},
		{ID: 2, Type: "Beacon", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", Score: 80, Timestamp: "2026-05-10 09:30:00"},
		{ID: 3, Type: "Data Exfiltration", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 60, Timestamp: "2026-05-11 09:00:00"},
	})

	resp := fetchTrend(t, s, "/api/findings/trend?q=src:10.0.0.1&limit=1&offset=5")

	series := map[string][]int{}
	for _, sr := range resp.Series {
		series[sr.Key] = sr.Counts
	}
	if got := series["beaconing"]; len(got) != 2 || got[0] != 1 || got[1] != 0 {
		t.Errorf("beaconing counts = %v, want [1 0] (q= filter must apply, limit/offset must not)", got)
	}
	if got := series["exfil"]; len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Errorf("exfil counts = %v, want [0 1]", got)
	}
	if len(resp.Days) != 2 {
		t.Errorf("days = %v, want the 2-day span of the filtered set", resp.Days)
	}
}

// TestFindingsTrend_FamilyMappingTotal pins the family roll-up: every
// analyzer-emitted finding type maps to a declared family key, and the
// catch-all works for unknown future types. A type added to an analyzer
// without a (deliberate) family decision lands in "other" — visible, not
// dropped.
func TestFindingsTrend_FamilyMappingTotal(t *testing.T) {
	known := map[string]bool{}
	for _, fam := range trendFamilies {
		known[fam.Key] = true
	}
	allTypes := []string{
		"Beacon", "DNS Beacon", "HTTP Beacon", "Port-Hopping Beacon", "Strobe",
		model.TypeTIHitIP, model.TypeTIHitDomain, model.TypeTIHitHash, model.TypeTIHitLegacy, model.TypeSuspiciousURL,
		"Malicious JA3", "Malicious JA4",
		"Data Exfiltration", "Off-Hours Transfer", "Database Protocol Egress", "Admin Protocol Egress",
		"DNS Tunneling", "DNS NXDOMAIN Flood", "DNS Subdomain DGA",
		"Lateral Movement",
		"Weak TLS", "SSL No-SNI", "SSL No-SNI on C2 Port", "Suspicious Certificate", "DoH Bypass", "Domain Fronting",
		"Long Connection", "C2 Port", "C2 URI Pattern", "Cobalt Strike URI", "Protocol Anomaly",
		"Protocol on Unexpected Port", "Suspicious File Download", "Suspicious TLD", "Suspicious UA",
		"Zeek Notice", "Some Future Detector",
	}
	for _, typ := range allTypes {
		fam := trendFamilyOf(typ)
		if !known[fam] {
			t.Errorf("trendFamilyOf(%q) = %q, not a declared family", typ, fam)
		}
	}
	if got := trendFamilyOf("Some Future Detector"); got != "other" {
		t.Errorf("unknown type mapped to %q, want \"other\"", got)
	}
}
