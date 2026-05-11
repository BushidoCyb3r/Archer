package analysis

import (
	"sort"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestCorrelate_EmitsOnTwoDistinctTypes verifies the basic
// kill-chain shape: Beaconing + DNS Tunneling to the same (src, dst)
// pair → a Correlated Activity finding plus annotated contributors.
func TestCorrelate_EmitsOnTwoDistinctTypes(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.add(model.Finding{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85, Timestamp: "2026-05-11 09:00:00 UTC"})
	a.add(model.Finding{Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 60, Timestamp: "2026-05-11 09:00:15 UTC"})

	a.correlateFindings()

	var corr *model.Finding
	for i := range a.findings {
		if a.findings[i].Type == model.TypeCorrelatedActivity {
			corr = &a.findings[i]
		}
	}
	if corr == nil {
		t.Fatal("expected a Correlated Activity finding; got none")
	}
	if corr.SrcIP != "10.0.0.1" || corr.DstIP != "1.2.3.4" {
		t.Errorf("wrong (src, dst): got (%s, %s)", corr.SrcIP, corr.DstIP)
	}
	// Score = max(85, 60) + 5*(numTypes-minTypes) = 85 + 0 = 85.
	if corr.Score != 85 {
		t.Errorf("Score = %d; want 85 (max contributor 85, no extra-type bump at numTypes==minTypes)", corr.Score)
	}
	if corr.Severity != model.SevCritical {
		t.Errorf("Severity = %s; want CRITICAL (score >= 80)", corr.Severity)
	}
	// Earliest contributor timestamp wins.
	if corr.Timestamp != "2026-05-11 09:00:00 UTC" {
		t.Errorf("Timestamp = %q; want earliest contributor 2026-05-11 09:00:00 UTC", corr.Timestamp)
	}
	if !strings.Contains(corr.Detail, "Beaconing") || !strings.Contains(corr.Detail, "DNS Tunneling") {
		t.Errorf("Detail %q missing one of the contributing types", corr.Detail)
	}

	// Contributors annotated with siblings + correlation row's ID.
	bcn := findOne(t, a.findings, "Beaconing")
	dns := findOne(t, a.findings, "DNS Tunneling")
	if got, want := bcn.Correlations, append(append([]int{}, dns.ID), corr.ID); !sameInts(got, want) {
		t.Errorf("Beaconing.Correlations = %v; want %v (DNS Tunneling ID + correlation ID)", got, want)
	}
	if got, want := dns.Correlations, append(append([]int{}, bcn.ID), corr.ID); !sameInts(got, want) {
		t.Errorf("DNS Tunneling.Correlations = %v; want %v (Beaconing ID + correlation ID)", got, want)
	}
	// The Correlated Activity row carries the contributor list itself.
	if got, want := corr.Correlations, append(append([]int{}, bcn.ID), dns.ID); !sameInts(got, want) {
		t.Errorf("Correlated Activity.Correlations = %v; want %v (the contributors)", got, want)
	}
}

// TestCorrelate_NoEmitOnSingleType verifies that one detector type
// on a pair is not enough — correlation needs distinct signal.
func TestCorrelate_NoEmitOnSingleType(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.add(model.Finding{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85})
	a.add(model.Finding{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 70})

	a.correlateFindings()

	for _, f := range a.findings {
		if f.Type == model.TypeCorrelatedActivity {
			t.Errorf("expected no Correlated Activity; got one with score %d", f.Score)
		}
		if f.Correlations != nil {
			t.Errorf("expected no Correlations annotation on single-type pair; got %v", f.Correlations)
		}
	}
}

// TestCorrelate_ExcludesIneligibleTypes verifies that the consultant's
// no-contribute list (Host Risk Score, Zeek Notice, Long Connection,
// and Correlated Activity itself) doesn't count toward the type set.
// A pair with one Beaconing + one Long Connection has only one
// eligible distinct type and must not correlate.
func TestCorrelate_ExcludesIneligibleTypes(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.add(model.Finding{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85})
	a.add(model.Finding{Type: "Long Connection", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 50})
	a.add(model.Finding{Type: "Zeek Notice", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 68})

	a.correlateFindings()

	for _, f := range a.findings {
		if f.Type == model.TypeCorrelatedActivity {
			t.Errorf("expected no Correlated Activity; got %+v", f)
		}
	}
}

// TestCorrelate_UnionsHistoricalFindings codifies NEW-67's pattern
// applied to correlation: a pair's contributing detections may have
// come from a prior run and live only in the historical store. The
// union via findingsProvider lets the same-pair count cross that
// boundary.
func TestCorrelate_UnionsHistoricalFindings(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	// This run sees only Beaconing fresh.
	a.add(model.Finding{ID: 10, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85})
	// Historical: a DNS Tunneling against the same pair from yesterday.
	a.SetFindingsProvider(&stubFindingsProvider{findings: []model.Finding{
		{ID: 11, Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 60, Timestamp: "2026-05-10 14:00:00 UTC"},
		// A stale Correlated Activity row from yesterday MUST NOT
		// re-enter as a contributor — that's the recursive-feedback
		// hazard the eligibility filter guards against.
		{ID: 12, Type: model.TypeCorrelatedActivity, SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 90},
	}})

	a.correlateFindings()

	var corr *model.Finding
	for i := range a.findings {
		if a.findings[i].Type == model.TypeCorrelatedActivity && a.findings[i].ID != 12 {
			corr = &a.findings[i]
		}
	}
	if corr == nil {
		t.Fatal("expected a fresh Correlated Activity finding from union(this-run, historical); got none")
	}
	// Beaconing(85) is the higher score; bump = 0 (numTypes == minTypes).
	if corr.Score != 85 {
		t.Errorf("Score = %d; want 85 (no recursive bump from the historical Correlated Activity row)", corr.Score)
	}
}

// TestCorrelate_DeterministicOrder codifies NEW-68: when multiple
// pairs cross the threshold in one run, the assigned correlation IDs
// must be stable across runs on identical input. Map iteration order
// is randomized; sort.Slice on pair keys eliminates that.
func TestCorrelate_DeterministicOrder(t *testing.T) {
	run := func() []string {
		a := New(config.Default(), "", nil, nil)
		// Three pairs, each crossing the threshold. Alphabetical
		// src+dst order is unambiguous so we can assert exact
		// ordering rather than just stability.
		a.add(model.Finding{Type: "Beaconing", SrcIP: "10.0.0.3", DstIP: "9.9.9.9", Score: 80})
		a.add(model.Finding{Type: "DNS Tunneling", SrcIP: "10.0.0.3", DstIP: "9.9.9.9", Score: 60})
		a.add(model.Finding{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80})
		a.add(model.Finding{Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 60})
		a.add(model.Finding{Type: "Beaconing", SrcIP: "10.0.0.2", DstIP: "5.5.5.5", Score: 80})
		a.add(model.Finding{Type: "DNS Tunneling", SrcIP: "10.0.0.2", DstIP: "5.5.5.5", Score: 60})

		a.correlateFindings()

		var corrSrcs []string
		for _, f := range a.findings {
			if f.Type == model.TypeCorrelatedActivity {
				corrSrcs = append(corrSrcs, f.SrcIP)
			}
		}
		return corrSrcs
	}
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for trial := 0; trial < 5; trial++ {
		got := run()
		if len(got) != len(want) {
			t.Fatalf("trial %d: got %d correlations, want %d", trial, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("trial %d: correlation[%d] src = %s, want %s (pair iteration not sorted)", trial, i, got[i], want[i])
			}
		}
	}
}

// TestCorrelate_ScoreBump verifies the extra-type bump: each distinct
// type beyond the minimum adds 5 to the score, capped at 99.
func TestCorrelate_ScoreBump(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.add(model.Finding{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 70})
	a.add(model.Finding{Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 60})
	a.add(model.Finding{Type: "Data Exfiltration", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 50})
	a.add(model.Finding{Type: "Strobe", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 40})

	a.correlateFindings()

	var corr *model.Finding
	for i := range a.findings {
		if a.findings[i].Type == model.TypeCorrelatedActivity {
			corr = &a.findings[i]
		}
	}
	if corr == nil {
		t.Fatal("expected Correlated Activity finding")
	}
	// 4 types, minTypes=2 → extra=2 → 70 + 5*2 = 80.
	if corr.Score != 80 {
		t.Errorf("Score = %d; want 80 (max 70 + 5*2 extra types)", corr.Score)
	}
}

// TestCorrelate_DisabledThresholdSkipsPhase verifies the NEW-66-style
// defensive guard. A config that somehow ends up with
// CorrelationMinTypes < 2 (direct DB write, half-applied migration)
// must short-circuit rather than degenerate to "correlate every pair."
func TestCorrelate_DisabledThresholdSkipsPhase(t *testing.T) {
	cfg := config.Default()
	cfg.CorrelationMinTypes = 1
	a := New(cfg, "", nil, nil)
	a.add(model.Finding{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85})

	a.correlateFindings()

	for _, f := range a.findings {
		if f.Type == model.TypeCorrelatedActivity {
			t.Errorf("expected no correlation with degenerate min_types=1; got %+v", f)
		}
	}
}

// TestCorrelate_PartitionsBySensor codifies NEW-73. Two sensors
// observing the same (src, dst) pair independently (overlapping
// captures from multiple Quiver collectors watching the same
// backbone) must produce two separate correlations — one per sensor
// — not a single conflated row. Same shape as NEW-6's beacon-pair
// sensor partitioning. Single-sensor deployments are unaffected
// (Sensor field is constant across findings).
func TestCorrelate_PartitionsBySensor(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	// Sensor-A observation: Beaconing + DNS Tunneling on (10.0.0.1 → 1.2.3.4).
	a.add(model.Finding{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 80, Sensor: "sensor-a"})
	a.add(model.Finding{Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 60, Sensor: "sensor-a"})
	// Sensor-B observation: Strobe + Data Exfiltration on the SAME pair
	// (because both sensors capture the same flow). These should NOT
	// merge with sensor-a's findings; the correlations are per-sensor.
	a.add(model.Finding{Type: "Strobe", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 70, Sensor: "sensor-b"})
	a.add(model.Finding{Type: "Data Exfiltration", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 65, Sensor: "sensor-b"})

	a.correlateFindings()

	corrBySensor := map[string]*model.Finding{}
	for i := range a.findings {
		f := &a.findings[i]
		if f.Type != model.TypeCorrelatedActivity {
			continue
		}
		if existing, ok := corrBySensor[f.Sensor]; ok {
			t.Errorf("duplicate correlation for sensor %q: existing=%+v new=%+v", f.Sensor, existing, f)
		}
		corrBySensor[f.Sensor] = f
	}
	if len(corrBySensor) != 2 {
		t.Errorf("expected exactly 2 correlations (one per sensor); got %d", len(corrBySensor))
	}
	if corrBySensor["sensor-a"] == nil {
		t.Error("missing correlation for sensor-a")
	}
	if corrBySensor["sensor-b"] == nil {
		t.Error("missing correlation for sensor-b")
	}
	// Pre-fix the test would have surfaced ONE correlation conflating
	// Beaconing+DNS Tunneling+Strobe+Data Exfil into a single 4-type
	// roll-up keyed only on (src, dst). The sensor field would have
	// reflected whichever finding's Sensor happened to win the
	// (non-existent) merge — silently wrong.
}

// TestCorrelate_ClearsStaleCorrelations verifies the staleness fix:
// a finding from a prior run that carried Correlations from then but
// doesn't participate this run gets its slice cleared, so the table
// doesn't render a "+N correlated" chip pointing at dead siblings.
func TestCorrelate_ClearsStaleCorrelations(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	// Single Beaconing finding with stale Correlations from a prior
	// run when DNS Tunneling also fired. This run, DNS Tunneling
	// doesn't fire on this pair so the correlation shouldn't hold.
	a.add(model.Finding{
		Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85,
		Correlations: []int{99, 100}, // stale from prior run
	})

	a.correlateFindings()

	bcn := findOne(t, a.findings, "Beaconing")
	if bcn.Correlations != nil {
		t.Errorf("expected stale Correlations cleared; got %v", bcn.Correlations)
	}
}

func findOne(t *testing.T, findings []model.Finding, typ string) *model.Finding {
	t.Helper()
	for i := range findings {
		if findings[i].Type == typ {
			return &findings[i]
		}
	}
	t.Fatalf("no finding of type %q", typ)
	return nil
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]int{}, a...)
	bc := append([]int{}, b...)
	sort.Ints(ac)
	sort.Ints(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
