package analysis

import (
	"sort"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestCorrelate_EmitsOnTwoDistinctTypes verifies the basic
// kill-chain shape: Beacon + DNS Tunneling to the same (src, dst)
// pair → a Correlated Activity finding plus annotated contributors.
func TestCorrelate_EmitsOnTwoDistinctTypes(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85, Timestamp: "2026-05-11 09:00:00 UTC"})
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
	if !strings.Contains(corr.Detail, "Beacon") || !strings.Contains(corr.Detail, "DNS Tunneling") {
		t.Errorf("Detail %q missing one of the contributing types", corr.Detail)
	}

	// Contributors annotated with siblings + correlation row's ID.
	bcn := findOne(t, a.findings, "Beacon")
	dns := findOne(t, a.findings, "DNS Tunneling")
	if got, want := bcn.Correlations, append(append([]int{}, dns.ID), corr.ID); !sameInts(got, want) {
		t.Errorf("Beacon.Correlations = %v; want %v (DNS Tunneling ID + correlation ID)", got, want)
	}
	if got, want := dns.Correlations, append(append([]int{}, bcn.ID), corr.ID); !sameInts(got, want) {
		t.Errorf("DNS Tunneling.Correlations = %v; want %v (Beacon ID + correlation ID)", got, want)
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
	a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85})
	a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 70})

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
// A pair with one Beacon + one Long Connection has only one
// eligible distinct type and must not correlate.
func TestCorrelate_ExcludesIneligibleTypes(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85})
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
	// This run sees only Beacon fresh.
	a.add(model.Finding{ID: 10, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85})
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
	// Beacon(85) is the higher score; bump = 0 (numTypes == minTypes).
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
		a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.3", DstIP: "9.9.9.9", Score: 80})
		a.add(model.Finding{Type: "DNS Tunneling", SrcIP: "10.0.0.3", DstIP: "9.9.9.9", Score: 60})
		a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80})
		a.add(model.Finding{Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 60})
		a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.2", DstIP: "5.5.5.5", Score: 80})
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
	a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 70})
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
	a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85})

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
	// Sensor-A observation: Beacon + DNS Tunneling on (10.0.0.1 → 1.2.3.4).
	a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 80, Sensor: "sensor-a"})
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
	// Beacon+DNS Tunneling+Strobe+Data Exfil into a single 4-type
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
	// Single Beacon finding with stale Correlations from a prior
	// run when DNS Tunneling also fired. This run, DNS Tunneling
	// doesn't fire on this pair so the correlation shouldn't hold.
	a.add(model.Finding{
		Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85,
		Correlations: []int{99, 100}, // stale from prior run
	})

	a.correlateFindings()

	bcn := findOne(t, a.findings, "Beacon")
	if bcn.Correlations != nil {
		t.Errorf("expected stale Correlations cleared; got %v", bcn.Correlations)
	}
}

// TestCorrelate_ThisRunContributorRetainsCorrelationsWhenHistoricalTwinAlsoFires
// codifies NEW-96 (twenty-second audit round). The invariant: for any
// this-run finding that participates in a correlation, its Correlations
// slice must list its sibling contributors after correlateFindings —
// regardless of whether a historical finding of the SAME fingerprint
// also contributed to the same pair.
//
// The failure mode pre-fix: idsByFingerprint dedup let the historical
// pass override the fresh pass (so the persisted ID won), then the
// annotation apply pass keyed lookups on a.findings[i].ID (the fresh
// ID), found nothing, and silently cleared the this-run finding's
// Correlations to nil. Asymmetric result: the Correlated Activity row
// listed Beacon as a contributor while the Beacon finding
// itself claimed no correlations.
//
// We articulate the invariant ("every this-run participant gets its
// Correlations populated") rather than the narrow failure case ("the
// specific fresh-vs-historical-Beacon collision"). Multiple shapes
// touch the same code path: this asserts the contract holds for the
// shape that broke, and the non-collision shape continues to work.
func TestCorrelate_ThisRunContributorRetainsCorrelationsWhenHistoricalTwinAlsoFires(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	// This-run Beacon. Fresh ID assigned by a.add (will be 1).
	a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", DstPort: "443", Score: 85, Timestamp: "2026-05-12 09:00:00 UTC"})
	// Historical fingerprint-twin (same Type/Src/Dst/Port) at a
	// persisted ID well above any fresh ID this run will assign.
	// Plus a historical DNS Tunneling on the same pair so the pair
	// has the >=2 distinct types it needs to correlate.
	a.SetFindingsProvider(&stubFindingsProvider{findings: []model.Finding{
		{ID: 47, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", DstPort: "443", Score: 70, Timestamp: "2026-05-11 09:00:00 UTC"},
		{ID: 92, Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 60, Timestamp: "2026-05-11 14:00:00 UTC"},
	}})

	a.correlateFindings()

	bcn := findOne(t, a.findings, "Beacon")
	if bcn.ID == 47 {
		t.Fatalf("expected this-run Beacon in a.findings, got the historical row (ID=47) — test setup wrong")
	}
	var corr *model.Finding
	for i := range a.findings {
		if a.findings[i].Type == model.TypeCorrelatedActivity {
			corr = &a.findings[i]
		}
	}
	if corr == nil {
		t.Fatal("expected a Correlated Activity finding from the cross-run pair; got none")
	}

	// The invariant: this-run Beacon's Correlations must contain at
	// least the historical DNS Tunneling ID + the correlation row's
	// ID. Pre-fix this slice was nil because the annotation map was
	// keyed on the historical Beacon ID and the apply pass looked
	// up under the fresh ID.
	if len(bcn.Correlations) == 0 {
		t.Fatalf("invariant violated: this-run Beacon has empty Correlations after correlateFindings — historical fingerprint-twin override silently cleared it")
	}
	// Historical-only DNS Tunneling (ID 92, no fresh twin) must appear as
	// sentinel -92 in Correlations slices before SetFindings translation.
	hasDNS, hasCorr := false, false
	for _, id := range bcn.Correlations {
		if id == -92 {
			hasDNS = true
		}
		if id == corr.ID {
			hasCorr = true
		}
	}
	if !hasDNS {
		t.Errorf("Beacon.Correlations = %v; missing historical DNS Tunneling sentinel (-92)", bcn.Correlations)
	}
	if !hasCorr {
		t.Errorf("Beacon.Correlations = %v; missing the new Correlated Activity row ID (%d)", bcn.Correlations, corr.ID)
	}

	// The Correlated Activity row must include the this-run Beacon's
	// fresh ID (not historical 47) and the historical DNS sentinel (-92).
	hasThisRun, hasDNSSentinel := false, false
	for _, id := range corr.Correlations {
		if id == bcn.ID {
			hasThisRun = true
		}
		if id == -92 {
			hasDNSSentinel = true
		}
		if id == 47 {
			t.Errorf("Correlated Activity.Correlations = %v; contains historical Beacon ID 47 — fingerprint dedup should have collapsed it onto fresh ID %d", corr.Correlations, bcn.ID)
		}
	}
	if !hasThisRun {
		t.Errorf("Correlated Activity.Correlations = %v; missing the this-run Beacon ID (%d)", corr.Correlations, bcn.ID)
	}
	if !hasDNSSentinel {
		t.Errorf("Correlated Activity.Correlations = %v; missing historical DNS Tunneling sentinel (-92)", corr.Correlations)
	}
}

// TestCorrelate_NoDuplicateWhenFreshSensorResolvedAtEmit codifies the
// fix for the duplicate-Correlated-Activity bug: when the watch loop
// assigns Sensor AFTER Analyze returns, fresh contributors enter
// correlateFindings with Sensor="" while historical contributors
// arrive from the FindingsProvider with their persisted Sensor.
// pairKey is (sensor, src, dst); Fingerprint is (Type, src, dst,
// port) and excludes Sensor. The asymmetry produced TWO pairKeys
// for the same (src, dst), two Correlated Activity emissions with
// identical Fingerprint, and SetFindings (no in-batch fingerprint
// dedup) persisted both as IsNew=true with different IDs.
//
// The invariant tested here: when defaultSensor is set (single-sensor
// deployment) BEFORE Analyze runs, a.add resolves Sensor at emit
// time, fresh contributors carry the same Sensor as their historical
// fingerprint twins, correlate produces ONE pairKey, and ONE
// Correlated Activity row appears for the (src, dst).
//
// Testing the invariant rather than the narrow failure: the assertion
// is "exactly one CA row for this pair" — same shape as
// TestCorrelate_PartitionsBySensor's "exactly N correlations" check.
// Any future regression that re-introduces a sensor-disagreement path
// (different field, different code path) will surface here.
func TestCorrelate_NoDuplicateWhenFreshSensorResolvedAtEmit(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.SetDefaultSensor("sensor01")

	// Fresh contributor — Sensor left empty so a.add must resolve it
	// from defaultSensor. This mimics what aggregate detectors emit
	// (empty SourceFile, no caller-set Sensor).
	a.add(model.Finding{Type: "Beacon", SrcIP: "10.18.61.48", DstIP: "35.163.162.183", Score: 88, Timestamp: "2026-05-10 00:03:31 UTC"})

	// Historical contributor for the SAME pair, persisted with Sensor
	// already populated — the shape findingsProvider returns from
	// store. Pre-fix this would have split into a separate pairKey
	// because the fresh contributor's Sensor was still "".
	a.SetFindingsProvider(&stubFindingsProvider{findings: []model.Finding{
		{ID: 187626, Type: "Off-Hours Transfer", SrcIP: "10.18.61.48", DstIP: "35.163.162.183", Score: 52, Sensor: "sensor01", Timestamp: "2026-05-10 02:03:34 UTC"},
	}})

	a.correlateFindings()

	count := 0
	for _, f := range a.findings {
		if f.Type == model.TypeCorrelatedActivity &&
			f.SrcIP == "10.18.61.48" && f.DstIP == "35.163.162.183" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 Correlated Activity for the (src, dst); got %d — fresh contributor's Sensor was not resolved before correlateFindings, splitting pairKey from the historical contributor", count)
	}
}

// TestAnalyzerAdd_ResolvesSensorFromSourceFile codifies the second
// resolution path: per-record detectors emit findings with SourceFile
// set to the originating Zeek log. a.add must derive Sensor from
// that path so correlateFindings sees the same Sensor that a
// historical fingerprint twin would carry, even in multi-sensor
// deployments where defaultSensor is intentionally unset.
func TestAnalyzerAdd_ResolvesSensorFromSourceFile(t *testing.T) {
	a := New(config.Default(), "/logs", nil, nil)
	a.add(model.Finding{
		Type:       "TI Hit (IP)",
		SrcIP:      "10.0.0.1",
		DstIP:      "1.2.3.4",
		SourceFile: "/logs/sensor01/2026-05-10/conn.log",
	})
	if got := a.findings[0].Sensor; got != "sensor01" {
		t.Errorf("Sensor = %q; want \"sensor01\" resolved from SourceFile", got)
	}
}

// TestAnalyzerAdd_PreservesExplicitSensor guards against the resolve
// path overwriting a caller-set Sensor. correlate.go emits Correlated
// Activity findings with Sensor: key.sensor — that value must win.
func TestAnalyzerAdd_PreservesExplicitSensor(t *testing.T) {
	a := New(config.Default(), "/logs", nil, nil)
	a.SetDefaultSensor("default-name")
	a.add(model.Finding{
		Type:       "Beacon",
		SrcIP:      "10.0.0.1",
		DstIP:      "1.2.3.4",
		Sensor:     "explicit-name",
		SourceFile: "/logs/different/2026-05-10/conn.log",
	})
	if got := a.findings[0].Sensor; got != "explicit-name" {
		t.Errorf("Sensor = %q; want \"explicit-name\" (caller-set value must not be overwritten by SourceFile resolution or defaultSensor)", got)
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

// TestCorrelate_HistoricalOnlyContributorEmitsSentinel codifies NEW-91
// case B2: a historical-only contributor (no fresh twin) whose persisted
// ID numerically equals a fresh per-run ID must be stored as a negative
// sentinel in Correlations slices so the SetFindings translation pass can
// distinguish it from the fresh ID and avoid mis-mapping it.
func TestCorrelate_HistoricalOnlyContributorEmitsSentinel(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	// This-run Beacon gets fresh ID 1. No DNS Tunneling this run.
	a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 85, Timestamp: "2026-05-12 09:00:00 UTC"})
	// Historical DNS Tunneling with persisted ID = 1, the same as the
	// fresh Beacon. This is the B2 collision: a fresh ID and a
	// historical persisted ID share the same numeric value.
	a.SetFindingsProvider(&stubFindingsProvider{findings: []model.Finding{
		{ID: 1, Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Score: 60, Timestamp: "2026-05-11 09:00:00 UTC"},
	}})

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

	// Historical DNS Tunneling (persisted ID=1, same value as fresh Beacon
	// ID=1) must appear as sentinel -1 in corr.Correlations before
	// SetFindings translation. If it appeared as positive 1, the translation
	// pass would map it via freshToPersisted[1] to whatever persisted ID the
	// Beacon receives — silently referencing the wrong finding.
	bcn := findOne(t, a.findings, "Beacon")
	hasSentinel := false
	for _, id := range corr.Correlations {
		if id == -1 {
			hasSentinel = true
		}
		if id == 1 && id != bcn.ID {
			t.Errorf("Correlated Activity.Correlations = %v; contains positive 1 for the historical DNS — should be sentinel -1 (B2 fix)", corr.Correlations)
		}
	}
	if !hasSentinel {
		t.Errorf("Correlated Activity.Correlations = %v; missing historical DNS Tunneling sentinel (-1) for B2 collision", corr.Correlations)
	}
	// Beacon's fresh ID must be the positive value in corr.Correlations.
	hasFresh := false
	for _, id := range corr.Correlations {
		if id == bcn.ID {
			hasFresh = true
		}
	}
	if !hasFresh {
		t.Errorf("Correlated Activity.Correlations = %v; missing this-run Beacon fresh ID (%d)", corr.Correlations, bcn.ID)
	}
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
