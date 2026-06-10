package analysis

import (
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestCorroborateBeacons_AnnotatesOnly is the precise unit test for the
// on-mission enrichment: corroborateBeacons must (1) append the same-dst
// egress/exfil signal to a beacon whose (sensor, src, dst) carries one, naming
// the corroborating type; (2) leave a beacon with no such signal untouched; (3)
// be annotation-only — never change Score or Severity; (4) annotate only
// beacons, not the egress finding itself; (5) exclude DNS Beacon (its dst is the
// resolver, not the C2 endpoint). Driving the helper directly keeps the
// invariant free of beacon-timing fragility (a same-dst egress conn is folded
// into the beacon pair and perturbs its score, which is real but not what this
// asserts).
func TestCorroborateBeacons_AnnotatesOnly(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.findings = []model.Finding{
		{ID: 1, Type: "Beacon", Sensor: "s1", SrcIP: "10.0.0.1", DstIP: "203.0.113.7", Score: 70, Severity: model.SevHigh, Detail: "60s interval"},
		{ID: 2, Type: "Database Protocol Egress", Sensor: "s1", SrcIP: "10.0.0.1", DstIP: "203.0.113.7", Score: 72, Severity: model.SevHigh, Detail: "MySQL egress"},
		{ID: 3, Type: "Beacon", Sensor: "s1", SrcIP: "10.0.0.2", DstIP: "203.0.113.8", Score: 70, Severity: model.SevHigh, Detail: "60s interval"},
		{ID: 4, Type: "DNS Beacon", Sensor: "s1", SrcIP: "10.0.0.3", DstIP: "203.0.113.9", Score: 70, Severity: model.SevHigh, Detail: "dns"},
		{ID: 5, Type: "Admin Protocol Egress", Sensor: "s1", SrcIP: "10.0.0.3", DstIP: "203.0.113.9", Score: 72, Severity: model.SevHigh, Detail: "ssh egress"},
	}

	a.corroborateBeacons()

	// (1) corroborated beacon: annotated, names the type, score/severity intact.
	got := a.findings[0]
	if !strings.Contains(got.Detail, "Exfil-over-C2 corroboration") || !strings.Contains(got.Detail, "Database Protocol Egress") {
		t.Errorf("beacon with same-dst egress must be annotated naming the type; Detail = %q", got.Detail)
	}
	if got.Score != 70 || got.Severity != model.SevHigh {
		t.Errorf("enrichment must be annotation-only; score/severity changed to %s/%d", got.Severity, got.Score)
	}

	// (2) beacon with no same-dst signal: untouched.
	if strings.Contains(a.findings[2].Detail, "Exfil-over-C2") {
		t.Errorf("beacon with no same-dst egress must not be annotated; Detail = %q", a.findings[2].Detail)
	}

	// (4) the egress finding itself is not annotated.
	if strings.Contains(a.findings[1].Detail, "Exfil-over-C2") {
		t.Errorf("egress findings must not be annotated; Detail = %q", a.findings[1].Detail)
	}

	// (5) DNS Beacon is excluded even though its dst has Admin Protocol Egress.
	if strings.Contains(a.findings[3].Detail, "Exfil-over-C2") {
		t.Errorf("DNS Beacon must be excluded (dst is the resolver); Detail = %q", a.findings[3].Detail)
	}
}

// TestCorroborateBeacons_MultipleSignalsSorted pins that several same-dst
// corroborators are listed together, deterministically sorted so the Detail
// string is stable across re-runs (Detail is regenerated each run).
func TestCorroborateBeacons_MultipleSignalsSorted(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.findings = []model.Finding{
		{ID: 1, Type: "Beacon", Sensor: "s1", SrcIP: "10.0.0.1", DstIP: "203.0.113.7", Detail: "x"},
		{ID: 2, Type: "Protocol on Unexpected Port", Sensor: "s1", SrcIP: "10.0.0.1", DstIP: "203.0.113.7", Detail: "y"},
		{ID: 3, Type: "Data Exfiltration", Sensor: "s1", SrcIP: "10.0.0.1", DstIP: "203.0.113.7", Detail: "z"},
	}

	a.corroborateBeacons()

	// Alphabetical: "Data Exfiltration" before "Protocol on Unexpected Port".
	want := "Exfil-over-C2 corroboration: same destination also shows Data Exfiltration, Protocol on Unexpected Port."
	if !strings.HasSuffix(a.findings[0].Detail, want) {
		t.Errorf("multi-signal annotation not sorted/stable; Detail = %q", a.findings[0].Detail)
	}
}
