package analysis

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// stubFindingsProvider feeds aggregateRisk a fixed historical set.
type stubFindingsProvider struct{ findings []model.Finding }

func (s *stubFindingsProvider) GetFindings() []model.Finding { return s.findings }

// TestDampenComposite_AsymptoticAbove75 covers the curve replacing the
// old hard-clamp at 99. The pre-fix bug was that two saturated hosts
// (raw=120 and raw=300) both reported "99" — losing the relative signal
// the analyst used to triage which host was worse. Audit 2026-05-10
// NEW-10.
func TestDampenComposite_AsymptoticAbove75(t *testing.T) {
	cases := []struct {
		raw       int
		want      int
		whyMatter string
	}{
		// Identity below threshold preserves single-detector hosts at
		// their unscaled score — same shape goldens exercise.
		{raw: 0, want: 0},
		{raw: 30, want: 30, whyMatter: "single Beacon finding"},
		{raw: 65, want: 65, whyMatter: "Beacon + Suspicious URL + TI Hit (Domain)"},
		{raw: 75, want: 75, whyMatter: "threshold boundary"},

		// Above threshold, dampened toward 99 with monotonic increase.
		// Exact values follow 75 + 24*(1 - exp(-(raw-75)/50)).
		{raw: 100, want: 84, whyMatter: "two-detector saturated host"},
		{raw: 150, want: 94, whyMatter: "highly-saturated host"},
		{raw: 200, want: 97},
		{raw: 400, want: 99, whyMatter: "asymptote"},
		{raw: 1_000, want: 99, whyMatter: "no overflow at extreme raw"},
	}
	for _, c := range cases {
		got := dampenComposite(c.raw)
		if got != c.want {
			t.Errorf("dampenComposite(%d) = %d; want %d (%s)", c.raw, got, c.want, c.whyMatter)
		}
	}
}

// TestDampenComposite_Monotonic asserts the curve is non-decreasing —
// a host with strictly more detector signal should never score lower.
func TestDampenComposite_Monotonic(t *testing.T) {
	prev := dampenComposite(0)
	for raw := 1; raw <= 500; raw++ {
		cur := dampenComposite(raw)
		if cur < prev {
			t.Fatalf("non-monotonic at raw=%d: %d < prev %d", raw, cur, prev)
		}
		prev = cur
	}
}

// TestDampenComposite_NeverExceeds99 caps blast radius if the formula
// is later edited — Severity bucketing in aggregateRisk treats 99 as
// the implicit max.
func TestDampenComposite_NeverExceeds99(t *testing.T) {
	for _, raw := range []int{99, 100, 500, 5_000, 1 << 20} {
		if got := dampenComposite(raw); got > 99 {
			t.Errorf("dampenComposite(%d) = %d; must be ≤ 99", raw, got)
		}
	}
}

// TestAggregateRisk_UnionsHistoricalFindings codifies NEW-67. Pre-fix
// aggregateRisk computed Host Risk Score from a.findings alone, so a
// host whose contributing detections existed in the store from a
// prior run but didn't re-fire this run got NO fresh HRS row — and
// SetFindings's preserve-historical loop then left the old HRS in
// the store indefinitely. The fix unions a.findings with the
// FindingsProvider snapshot so the aggregator sees the complete
// detection footprint.
func TestAggregateRisk_UnionsHistoricalFindings(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	// This run sees only host B with a fresh Beacon finding.
	a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.2", DstIP: "1.1.1.1", Score: 60, Timestamp: "2026-05-11 09:00:00 UTC"})
	// Historical store carries host A's Beacon + TI Hit (Domain)
	// from a prior run; host A is quiet this run.
	a.SetFindingsProvider(&stubFindingsProvider{findings: []model.Finding{
		{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "2.2.2.2", Score: 60, Timestamp: "2026-05-10 12:00:00 UTC"},
		{Type: "TI Hit (Domain)", SrcIP: "10.0.0.1", DstIP: "evil.example", Score: 50, Timestamp: "2026-05-10 12:00:15 UTC"},
		// A stale Host Risk Score row for the same host MUST NOT
		// feed back into the new composite — that's the double-
		// counting hazard the type-filter in contribute() guards
		// against.
		{Type: "Host Risk Score", SrcIP: "10.0.0.1", DstIP: "(network)", Score: 65},
	}})

	a.aggregateRisk(nil)

	var hrsA, hrsB *model.Finding
	for i := range a.findings {
		f := &a.findings[i]
		if f.Type != "Host Risk Score" {
			continue
		}
		switch f.SrcIP {
		case "10.0.0.1":
			hrsA = f
		case "10.0.0.2":
			hrsB = f
		}
	}
	if hrsA == nil {
		t.Fatal("expected fresh Host Risk Score for 10.0.0.1 (the quiet-this-run host with historical detections); got none")
	}
	// 10.0.0.1 has Beacon (score=60) + TI Hit (Domain) (score=50).
	// New formula: weight × (0.5 + 0.5×score/100).
	//   Beacon:       30 × (0.5 + 0.3)  = 24
	//   TI Hit (Domain): 35 × (0.5 + 0.25) = 26.25 → 26 (Round)
	//   composite = 50; below dampen threshold → identity.
	if hrsA.Score != 50 {
		t.Errorf("10.0.0.1 HRS = %d; want 50 (Beacon×0.8 + TI Hit Domain×0.75)", hrsA.Score)
	}
	// firstTS should come from the earliest contributing finding —
	// proves the union path runs through contribute()'s timestamp
	// pick, not just an after-the-fact tag.
	if hrsA.Timestamp != "2026-05-10 12:00:00 UTC" {
		t.Errorf("10.0.0.1 HRS Timestamp = %q; want earliest contributor timestamp", hrsA.Timestamp)
	}
	if hrsB == nil {
		t.Fatal("expected Host Risk Score for 10.0.0.2 (the fresh-this-run host); got none")
	}
	// 10.0.0.2 has Beacon (score=60): 30 × 0.8 = 24.
	if hrsB.Score != 24 {
		t.Errorf("10.0.0.2 HRS = %d; want 24 (Beacon weight×scoreScale)", hrsB.Score)
	}
}

// TestAggregateRisk_DeterministicHostOrder codifies NEW-68. Pre-fix
// the outer loop iterated the hosts map in randomized order; HRS
// findings got per-run sequential IDs assigned in that order, so two
// fresh runs (post-ClearFindings) on the same input produced
// different IDs for the same host. The sorted-key iteration removes
// the non-determinism.
func TestAggregateRisk_DeterministicHostOrder(t *testing.T) {
	run := func() []string {
		a := New(config.Default(), "", nil, nil)
		// Three hosts whose alphabetical order is unambiguous so we
		// can assert the exact ordering rather than just stability.
		a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.3", DstIP: "x", Score: 50, Timestamp: "2026-05-11 09:00:00 UTC"})
		a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "x", Score: 50, Timestamp: "2026-05-11 09:00:00 UTC"})
		a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.2", DstIP: "x", Score: 50, Timestamp: "2026-05-11 09:00:00 UTC"})
		a.aggregateRisk(nil)
		var hrsHosts []string
		for _, f := range a.findings {
			if f.Type == "Host Risk Score" {
				hrsHosts = append(hrsHosts, f.SrcIP)
			}
		}
		return hrsHosts
	}
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for trial := 0; trial < 5; trial++ {
		got := run()
		if len(got) != len(want) {
			t.Fatalf("trial %d: got %d HRS rows, want %d", trial, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("trial %d: HRS host[%d] = %s, want %s (map iteration not sorted)", trial, i, got[i], want[i])
			}
		}
	}
}

// TestAggregateRisk_MultiplicityBoost codifies the dst-count multiplier:
// a host beaconing to N distinct C2 destinations must score higher than
// one beaconing to a single destination at the same score. The multiplier
// is 1 + 0.5·log₂(n), capped at 3×. Each distinct DstIP is one entry
// in the dst set; the same DstIP repeated via the historical union counts
// only once.
func TestAggregateRisk_MultiplicityBoost(t *testing.T) {
	// Single Beacon dst at score 80.
	// weight=30, scoreScale=0.9, multiMod=1.0 → contribution=27.
	single := func() int {
		a := New(config.Default(), "", nil, nil)
		a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Timestamp: "2026-01-01 00:00:00 UTC"})
		a.aggregateRisk(nil)
		for _, f := range a.findings {
			if f.Type == "Host Risk Score" {
				return f.Score
			}
		}
		return -1
	}()

	// Four distinct Beacon dsts at score 80.
	// multiMod = 1 + 0.5·log₂(4) = 1 + 0.5·2 = 2.0 → contribution=54.
	four := func() int {
		a := New(config.Default(), "", nil, nil)
		for i, dst := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
			_ = i
			a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: dst, Score: 80, Timestamp: "2026-01-01 00:00:00 UTC"})
		}
		a.aggregateRisk(nil)
		for _, f := range a.findings {
			if f.Type == "Host Risk Score" {
				return f.Score
			}
		}
		return -1
	}()

	if single != 27 {
		t.Errorf("single-dst HRS = %d; want 27 (weight 30 × scoreScale 0.9 × multiMod 1.0)", single)
	}
	if four != 54 {
		t.Errorf("four-dst HRS = %d; want 54 (weight 30 × scoreScale 0.9 × multiMod 2.0)", four)
	}
	if four <= single {
		t.Errorf("four-dst (%d) should exceed single-dst (%d)", four, single)
	}

	// Dedup check: the same DstIP appearing via both fresh findings and
	// the historical union must count as 1, not 2.
	dedup := func() int {
		a := New(config.Default(), "", nil, nil)
		a.add(model.Finding{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Timestamp: "2026-01-01 00:00:00 UTC"})
		a.SetFindingsProvider(&stubFindingsProvider{findings: []model.Finding{
			{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Timestamp: "2026-01-01 00:00:00 UTC"},
		}})
		a.aggregateRisk(nil)
		for _, f := range a.findings {
			if f.Type == "Host Risk Score" {
				return f.Score
			}
		}
		return -1
	}()
	if dedup != single {
		t.Errorf("dedup HRS = %d; want %d (same dst via union must count once)", dedup, single)
	}
}
