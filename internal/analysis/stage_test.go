package analysis

import (
	"sort"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// testStagingParams is a fixed parameter set so these tests are independent of
// the production default constants (which are tuned on corpus evidence and may
// drift). minHosts=2, rare dst ≤6 sources, 48h clustering window.
var testStagingParams = stagingParams{
	minHosts:      2,
	maxDstSources: 6,
	windowHours:   48,
	score:         80,
	scoreCorrob:   96,
}

func bcn(id int, sensor, src, dst, ts string) model.Finding {
	return model.Finding{
		ID: id, Type: "Beacon", Sensor: sensor,
		SrcIP: src, DstIP: dst, Timestamp: ts,
		Score: 80, Severity: model.SevHigh,
	}
}

// dstSrc returns a dstSources closure reporting a fixed unique-source count
// for every (sensor,dst). The rarity gate is the FP killer: a CDN with many
// sources must never qualify.
func dstSrc(n int) func(sensor, dst string) int {
	return func(sensor, dst string) int { return n }
}

// TestStaging_BasicCluster: two internal hosts beaconing to the same rare
// external dst with staggered onsets inside the window, no corroboration →
// exactly one HIGH Multi-Stage Beacon finding, anchored on the earliest-onset
// host (patient zero), binding both fresh contributor IDs.
func TestStaging_BasicCluster(t *testing.T) {
	fresh := []model.Finding{
		bcn(1, "s1", "10.0.0.1", "203.0.113.5", "2026-06-08 10:00:00"),
		bcn(2, "s1", "10.0.0.2", "203.0.113.5", "2026-06-08 10:30:00"),
	}
	got := computeStaging(fresh, nil, nil, dstSrc(2), testStagingParams)
	if len(got) != 1 {
		t.Fatalf("expected 1 staging finding, got %d", len(got))
	}
	f := got[0]
	if f.Type != model.TypeMultiStageBeacon {
		t.Errorf("type = %q, want %q", f.Type, model.TypeMultiStageBeacon)
	}
	if f.Severity != model.SevHigh || f.Score != 80 {
		t.Errorf("severity/score = %v/%d, want HIGH/80", f.Severity, f.Score)
	}
	if f.SrcIP != "10.0.0.1" { // patient zero = earliest onset
		t.Errorf("anchor src = %q, want 10.0.0.1 (earliest onset)", f.SrcIP)
	}
	if f.DstIP != "203.0.113.5" || f.Sensor != "s1" {
		t.Errorf("dst/sensor = %q/%q", f.DstIP, f.Sensor)
	}
	sort.Ints(f.Correlations)
	if len(f.Correlations) != 2 || f.Correlations[0] != 1 || f.Correlations[1] != 2 {
		t.Errorf("correlations = %v, want [1 2]", f.Correlations)
	}
	if !strings.Contains(f.Detail, "10.0.0.1") || !strings.Contains(f.Detail, "10.0.0.2") {
		t.Errorf("detail should enumerate both hosts: %q", f.Detail)
	}
}

// TestStaging_LateralCorroboration: an internal Lateral Movement finding
// linking two participants escalates the cluster to CRITICAL — the "A moved to
// B, B called home" staging mechanic.
func TestStaging_LateralCorroboration(t *testing.T) {
	fresh := []model.Finding{
		bcn(1, "s1", "10.0.0.1", "203.0.113.5", "2026-06-08 10:00:00"),
		bcn(2, "s1", "10.0.0.2", "203.0.113.5", "2026-06-08 10:30:00"),
	}
	related := []model.Finding{
		{ID: 9, Type: "Lateral Movement", Sensor: "s1", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Timestamp: "2026-06-08 10:15:00"},
	}
	got := computeStaging(fresh, nil, related, dstSrc(2), testStagingParams)
	if len(got) != 1 || got[0].Severity != model.SevCritical || got[0].Score != 96 {
		t.Fatalf("expected 1 CRITICAL/96 finding, got %+v", got)
	}
}

// TestStaging_MaliciousJA3OnDst: a Malicious JA3 finding on the shared dst
// (covers built-in known-bad fingerprints and the operator JA3/JA4 IOC list,
// both of which surface as Malicious JA3/JA4 findings) escalates to CRITICAL.
func TestStaging_MaliciousJA3OnDst(t *testing.T) {
	fresh := []model.Finding{
		bcn(1, "s1", "10.0.0.1", "203.0.113.5", "2026-06-08 10:00:00"),
		bcn(2, "s1", "10.0.0.2", "203.0.113.5", "2026-06-08 10:30:00"),
	}
	related := []model.Finding{
		{ID: 9, Type: "Malicious JA3", Sensor: "s1", SrcIP: "10.0.0.1", DstIP: "203.0.113.5"},
	}
	got := computeStaging(fresh, nil, related, dstSrc(2), testStagingParams)
	if len(got) != 1 || got[0].Severity != model.SevCritical {
		t.Fatalf("expected CRITICAL via Malicious JA3 on dst, got %+v", got)
	}
}

// TestStaging_TIHitOnDst: a TI Hit (IP) on the shared C2 destination
// escalates to CRITICAL regardless of which IP field carries the hit.
func TestStaging_TIHitOnDst(t *testing.T) {
	fresh := []model.Finding{
		bcn(1, "s1", "10.0.0.1", "203.0.113.5", "2026-06-08 10:00:00"),
		bcn(2, "s1", "10.0.0.2", "203.0.113.5", "2026-06-08 10:30:00"),
	}
	related := []model.Finding{
		{ID: 9, Type: model.TypeTIHitIP, DstIP: "203.0.113.5"},
	}
	got := computeStaging(fresh, nil, related, dstSrc(2), testStagingParams)
	if len(got) != 1 || got[0].Severity != model.SevCritical {
		t.Fatalf("expected CRITICAL via TI Hit on dst, got %+v", got)
	}
}

// TestStaging_RarityGate: a destination with many unique sources (a CDN /
// shared service) must never qualify, no matter how many hosts beacon to it.
func TestStaging_RarityGate(t *testing.T) {
	fresh := []model.Finding{
		bcn(1, "s1", "10.0.0.1", "203.0.113.5", "2026-06-08 10:00:00"),
		bcn(2, "s1", "10.0.0.2", "203.0.113.5", "2026-06-08 10:30:00"),
	}
	got := computeStaging(fresh, nil, nil, dstSrc(50), testStagingParams)
	if len(got) != 0 {
		t.Fatalf("rarity gate should exclude a 50-source dst, got %+v", got)
	}
}

// TestStaging_MinHosts: a single host beaconing to a rare dst is an ordinary
// beacon, not convergence — no staging finding.
func TestStaging_MinHosts(t *testing.T) {
	fresh := []model.Finding{
		bcn(1, "s1", "10.0.0.1", "203.0.113.5", "2026-06-08 10:00:00"),
	}
	got := computeStaging(fresh, nil, nil, dstSrc(1), testStagingParams)
	if len(got) != 0 {
		t.Fatalf("single host must not produce a staging finding, got %+v", got)
	}
}

// TestStaging_WindowGate: onsets clustered in time signal one campaign; onsets
// weeks apart are two independent niche-app users. Spread beyond the window
// must not fire.
func TestStaging_WindowGate(t *testing.T) {
	fresh := []model.Finding{
		bcn(1, "s1", "10.0.0.1", "203.0.113.5", "2026-06-01 10:00:00"),
		bcn(2, "s1", "10.0.0.2", "203.0.113.5", "2026-06-08 10:00:00"), // 7 days later
	}
	got := computeStaging(fresh, nil, nil, dstSrc(2), testStagingParams)
	if len(got) != 0 {
		t.Fatalf("onsets 7 days apart exceed the 48h window, got %+v", got)
	}
}

// TestStaging_InternalDstExcluded: convergence on an internal destination is
// not C2 egress — the detector is scoped to external destinations.
func TestStaging_InternalDstExcluded(t *testing.T) {
	fresh := []model.Finding{
		bcn(1, "s1", "10.0.0.1", "10.0.0.9", "2026-06-08 10:00:00"),
		bcn(2, "s1", "10.0.0.2", "10.0.0.9", "2026-06-08 10:30:00"),
	}
	got := computeStaging(fresh, nil, nil, dstSrc(2), testStagingParams)
	if len(got) != 0 {
		t.Fatalf("internal dst must be excluded, got %+v", got)
	}
}

// TestStaging_HistoricalParticipant: a cluster can span this run and history.
// A historical-only participant counts toward the host floor and is named in
// the detail, but only fresh contributors are linked via Correlations (their
// IDs are the ones SetFindings can translate this run).
func TestStaging_HistoricalParticipant(t *testing.T) {
	fresh := []model.Finding{
		bcn(1, "s1", "10.0.0.1", "203.0.113.5", "2026-06-08 10:00:00"),
	}
	hist := []model.Finding{
		bcn(7, "s1", "10.0.0.2", "203.0.113.5", "2026-06-08 10:30:00"),
	}
	got := computeStaging(fresh, hist, nil, dstSrc(2), testStagingParams)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding from a fresh+historical cluster, got %d", len(got))
	}
	f := got[0]
	if len(f.Correlations) != 1 || f.Correlations[0] != 1 {
		t.Errorf("correlations = %v, want only the fresh ID [1]", f.Correlations)
	}
	if !strings.Contains(f.Detail, "10.0.0.2") {
		t.Errorf("historical participant should be named in detail: %q", f.Detail)
	}
}

// TestStaging_DedupAcrossFreshAndHistory: the same beacon present in both the
// fresh and historical sets (same fingerprint, different IDs) is one host, not
// two — it must not inflate the host count past the floor on its own.
func TestStaging_DedupAcrossFreshAndHistory(t *testing.T) {
	fresh := []model.Finding{
		bcn(1, "s1", "10.0.0.1", "203.0.113.5", "2026-06-08 10:00:00"),
	}
	hist := []model.Finding{
		bcn(7, "s1", "10.0.0.1", "203.0.113.5", "2026-06-08 10:00:00"), // same fingerprint as fresh #1
	}
	got := computeStaging(fresh, hist, nil, dstSrc(1), testStagingParams)
	if len(got) != 0 {
		t.Fatalf("one host duplicated across fresh+history must not qualify, got %+v", got)
	}
}

// TestStaging_AnalyzerWiring proves the end-to-end Analyzer integration: beacon
// findings in a.findings plus a populated prevalence map produce a Multi-Stage
// Beacon finding via a.detectStaging(), and IsRollupType keeps it from feeding
// the host-risk weights or the same-pair roll-up.
func TestStaging_AnalyzerWiring(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.add(model.Finding{Type: "Beacon", Sensor: "s1", SrcIP: "10.0.0.1", DstIP: "203.0.113.5", Score: 80, Timestamp: "2026-06-08 10:00:00"})
	a.add(model.Finding{Type: "Beacon", Sensor: "s1", SrcIP: "10.0.0.2", DstIP: "203.0.113.5", Score: 80, Timestamp: "2026-06-08 10:30:00"})
	// Rare destination: only the two converging hosts have been seen talking
	// to it (well under the rarity cap).
	a.sensorPrev["s1"] = &sensorPrevData{dstSrcs: map[string]map[string]struct{}{
		"203.0.113.5": {"10.0.0.1": {}, "10.0.0.2": {}},
	}}

	a.detectStaging()

	var stage *model.Finding
	for i := range a.findings {
		if a.findings[i].Type == model.TypeMultiStageBeacon {
			stage = &a.findings[i]
		}
	}
	if stage == nil {
		t.Fatal("expected a Multi-Stage Beacon finding via detectStaging; got none")
	}
	if !model.IsRollupType(stage.Type) {
		t.Errorf("Multi-Stage Beacon must be a rollup type (host-risk + correlate exclusion)")
	}
	if len(stage.Correlations) != 2 {
		t.Errorf("expected 2 bound contributors, got %v", stage.Correlations)
	}
}

// TestStaging_Deterministic: identical input yields identical output across
// runs (sorted cluster keys + participants), so IDs and detail strings are
// stable and SetFindings can fingerprint-merge cleanly.
func TestStaging_Deterministic(t *testing.T) {
	fresh := []model.Finding{
		bcn(2, "s1", "10.0.0.2", "203.0.113.5", "2026-06-08 10:30:00"),
		bcn(1, "s1", "10.0.0.1", "203.0.113.5", "2026-06-08 10:00:00"),
		bcn(3, "s1", "10.0.0.3", "198.51.100.7", "2026-06-08 11:00:00"),
		bcn(4, "s1", "10.0.0.4", "198.51.100.7", "2026-06-08 11:20:00"),
	}
	a := computeStaging(fresh, nil, nil, dstSrc(2), testStagingParams)
	b := computeStaging(fresh, nil, nil, dstSrc(2), testStagingParams)
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("expected 2 clusters each, got %d / %d", len(a), len(b))
	}
	for i := range a {
		if a[i].DstIP != b[i].DstIP || a[i].SrcIP != b[i].SrcIP || a[i].Detail != b[i].Detail {
			t.Errorf("nondeterministic output at %d: %+v vs %+v", i, a[i], b[i])
		}
	}
}
