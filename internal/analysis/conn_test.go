package analysis

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestOffHoursRespectsTimezone verifies that the off-hours detector
// interprets OffHoursStart/End in the configured operator timezone.
// Same fixture, two different timezone settings, two different outcomes.
func TestOffHoursRespectsTimezone(t *testing.T) {
	fixture := []string{"testdata/zeek/off_hours/conn.log"}

	// Default timezone (empty → UTC). Fixture timestamps are 02:00 UTC,
	// firmly inside the 22-06 off-hours window. Off-Hours Transfer fires.
	utcCfg := config.Default()
	utcCfg.Timezone = ""
	utc := New(utcCfg, "", nil, nil)
	utc.feodoIPs = map[string]bool{}
	utc.urlhausIPs = map[string]bool{}
	utc.urlhausHosts = map[string]bool{}
	utcFindings := utc.Analyze(fixture)
	if !hasFindingType(utcFindings, "Off-Hours Transfer") {
		t.Errorf("UTC: expected Off-Hours Transfer to fire on 02:00 UTC fixture, got types: %v", findingTypes(utcFindings))
	}

	// America/New_York is UTC-5 (EST, no DST in January). 02:00 UTC =
	// 21:00 EST → hour 21. Off-hours window 22-06 → hour 21 is OUTSIDE
	// the window. Off-Hours Transfer must NOT fire.
	nyCfg := config.Default()
	nyCfg.Timezone = "America/New_York"
	ny := New(nyCfg, "", nil, nil)
	ny.feodoIPs = map[string]bool{}
	ny.urlhausIPs = map[string]bool{}
	ny.urlhausHosts = map[string]bool{}
	nyFindings := ny.Analyze(fixture)
	if hasFindingType(nyFindings, "Off-Hours Transfer") {
		t.Errorf("America/New_York: expected NO Off-Hours Transfer (02:00 UTC = 21:00 EST is outside 22-06 window), got types: %v", findingTypes(nyFindings))
	}

	// Asia/Tokyo is UTC+9. 02:00 UTC = 11:00 JST → still outside 22-06.
	jstCfg := config.Default()
	jstCfg.Timezone = "Asia/Tokyo"
	jst := New(jstCfg, "", nil, nil)
	jst.feodoIPs = map[string]bool{}
	jst.urlhausIPs = map[string]bool{}
	jst.urlhausHosts = map[string]bool{}
	jstFindings := jst.Analyze(fixture)
	if hasFindingType(jstFindings, "Off-Hours Transfer") {
		t.Errorf("Asia/Tokyo: expected NO Off-Hours Transfer (02:00 UTC = 11:00 JST is outside 22-06 window), got types: %v", findingTypes(jstFindings))
	}
}

// TestOffHoursBadTimezoneFallsBackToUTC checks the defensive fallback —
// an invalid IANA name should not silently disable detection.
func TestOffHoursBadTimezoneFallsBackToUTC(t *testing.T) {
	cfg := config.Default()
	cfg.Timezone = "Not/A/Real/Zone"
	a := New(cfg, "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	findings := a.Analyze([]string{"testdata/zeek/off_hours/conn.log"})
	if !hasFindingType(findings, "Off-Hours Transfer") {
		t.Errorf("bad timezone should fall back to UTC and fire detection, got types: %v", findingTypes(findings))
	}
}

// TestBeaconEmitsStructuredTriageFields asserts the analyzer populates
// the migration-0018 triage fields at the conn-level Beaconing emit
// site — the producer half of the NEW-89 closure (the store round-trip
// is covered in store_test.go). Invariant: a Beaconing finding carries
// a positive sample size and mean/median interval, four sub-scores in
// [0,1] that are not all zero, and a finite non-negative jitter whose
// implied spread (mean × jitter) is well-defined. A regression that
// drops any field at emit time (e.g. a struct-literal key omitted in a
// future refactor) fails here even though the golden snapshot — which
// projects only Score/Type — would stay green.
func TestBeaconEmitsStructuredTriageFields(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	findings := a.Analyze([]string{
		"testdata/zeek/beacon_url/conn.log",
		"testdata/zeek/beacon_url/http.log",
	})

	var b *model.Finding
	for i := range findings {
		if findings[i].Type == "Beaconing" {
			b = &findings[i]
			break
		}
	}
	if b == nil {
		t.Fatalf("expected a Beaconing finding from beacon_url fixture, got types: %v", findingTypes(findings))
	}

	if b.SampleSize <= 0 {
		t.Errorf("SampleSize = %d; want > 0", b.SampleSize)
	}
	if b.MeanInterval <= 0 {
		t.Errorf("MeanInterval = %v; want > 0", b.MeanInterval)
	}
	if b.MedianInterval <= 0 {
		t.Errorf("MedianInterval = %v; want > 0", b.MedianInterval)
	}
	for _, sc := range []struct {
		name string
		v    float64
	}{{"ts", b.TSScore}, {"ds", b.DSScore}, {"hist", b.HistScore}, {"dur", b.DurScore}} {
		if sc.v < 0 || sc.v > 1 {
			t.Errorf("%s sub-score = %v; want within [0,1]", sc.name, sc.v)
		}
	}
	if b.TSScore+b.DSScore+b.HistScore+b.DurScore == 0 {
		t.Error("all four sub-scores are zero — emit site did not populate them")
	}
	if b.Jitter < 0 || b.Jitter != b.Jitter { // NaN-safe
		t.Errorf("Jitter = %v; want finite and >= 0", b.Jitter)
	}
}

// beaconExpectedSeverity returns the expected severity for a beacon finding
// score under the four-band mapping.
func beaconExpectedSeverity(score int) model.Severity {
	switch {
	case score >= 85:
		return model.SevCritical
	case score >= 70:
		return model.SevHigh
	case score >= 50:
		return model.SevMedium
	default:
		return model.SevLow
	}
}

// TestBeaconScoreSeverityInvariants runs across the beacon-heavy fixture
// scenarios and asserts that every Beaconing / HTTP Beaconing finding
// satisfies two invariants:
//  1. score >= beaconMinEmitScore (emit floor enforced)
//  2. severity is consistent with the four-band mapping
//
// A regression that drops the emit gate or miscodes the severity switch
// fails here even when the golden snapshots still match (goldens project
// Detail which wouldn't reveal a wrong Severity value).
func TestBeaconScoreSeverityInvariants(t *testing.T) {
	beaconScenarios := []string{
		"testdata/zeek/beacon_url",
		"testdata/zeek/jittered_beacon",
		"testdata/zeek/multimode_beacon",
		"testdata/zeek/scrambled_beacon",
		"testdata/zeek/http_beacon",
	}
	for _, dir := range beaconScenarios {
		t.Run(dir, func(t *testing.T) {
			files := collectFixtureLogs(t, dir)
			if len(files) == 0 {
				t.Skip("no fixtures in", dir)
			}
			a := New(config.Default(), "", nil, nil)
			a.feodoIPs = map[string]bool{}
			a.urlhausIPs = map[string]bool{}
			a.urlhausHosts = map[string]bool{}
			findings := a.Analyze(files)
			for _, f := range findings {
				if f.Type != "Beaconing" && f.Type != "HTTP Beaconing" {
					continue
				}
				if f.Score < beaconMinEmitScore {
					t.Errorf("%s: %s score=%d < emit floor %d", dir, f.Type, f.Score, beaconMinEmitScore)
				}
				if want := beaconExpectedSeverity(f.Score); f.Severity != want {
					t.Errorf("%s: %s score=%d got severity %v, want %v", dir, f.Type, f.Score, f.Severity, want)
				}
			}
		})
	}
}

// TestStrobeExcludesBeacon verifies that a pair qualifying as a Strobe does
// not also emit a Beaconing finding. Pre-fix, strobe pairs scored near-perfect
// timing regularity and double-alerted.
func TestStrobeExcludesBeacon(t *testing.T) {
	files := collectFixtureLogs(t, "testdata/zeek/strobe")
	if len(files) == 0 {
		t.Skip("no strobe fixtures")
	}
	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	findings := a.Analyze(files)

	for _, strobe := range findings {
		if strobe.Type != "Strobe" {
			continue
		}
		for _, beacon := range findings {
			if beacon.Type == "Beaconing" &&
				beacon.SrcIP == strobe.SrcIP &&
				beacon.DstIP == strobe.DstIP {
				t.Errorf("strobe pair %s→%s also emitted Beaconing (should be excluded by strobe gate)",
					strobe.SrcIP, strobe.DstIP)
			}
		}
	}
}

func hasFindingType(findings []model.Finding, t string) bool {
	for _, f := range findings {
		if f.Type == t {
			return true
		}
	}
	return false
}

func findingTypes(findings []model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Type)
	}
	return out
}
