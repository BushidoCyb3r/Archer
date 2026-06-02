package analysis

import (
	"strings"
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
// the migration-0018 triage fields at the conn-level Beacon emit
// site — the producer half of the NEW-89 closure (the store round-trip
// is covered in store_test.go). Invariant: a Beacon finding carries
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
		if findings[i].Type == "Beacon" {
			b = &findings[i]
			break
		}
	}
	if b == nil {
		t.Fatalf("expected a Beacon finding from beacon_url fixture, got types: %v", findingTypes(findings))
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
// scenarios and asserts that every Beacon / HTTP Beacon finding
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
				if f.Type != "Beacon" && f.Type != "HTTP Beacon" {
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
// not also emit a Beacon finding. Pre-fix, strobe pairs scored near-perfect
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
			if beacon.Type == "Beacon" &&
				beacon.SrcIP == strobe.SrcIP &&
				beacon.DstIP == strobe.DstIP {
				t.Errorf("strobe pair %s→%s also emitted Beacon (should be excluded by strobe gate)",
					strobe.SrcIP, strobe.DstIP)
			}
		}
	}
}

// TestSlowBeaconNotExcludedByStrobeGate is the regression anchor for the
// strobe rate-gate fix. Under the old count-only gate (StrobeMinConnections
// = 1000), a pair with ≥ 1000 connections was always excluded from beacon
// scoring — regardless of interval. A 60-second C2 beacon over a multi-week
// capture accumulates ~43,200 connections at 0.017/s: the old gate silently
// reclassified it as Strobe. Invariant: count alone is not sufficient; rate
// must also meet StrobeMinRatePerSec. The fixture runs at ≈ 0.06/s.
func TestSlowBeaconNotExcludedByStrobeGate(t *testing.T) {
	files := collectFixtureLogs(t, "testdata/zeek/slow_c2_beacon")
	if len(files) == 0 {
		t.Skip("no fixtures")
	}
	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	findings := a.Analyze(files)

	if hasFindingType(findings, "Strobe") {
		t.Errorf("slow C2 beacon (rate ≈ 0.06/s) should NOT emit Strobe — below StrobeMinRatePerSec=%.2f",
			config.Default().StrobeMinRatePerSec)
	}
	if !hasFindingType(findings, "Beacon") {
		t.Errorf("slow C2 beacon (1000 connections at ~16s intervals) should emit Beacon; got: %v",
			findingTypes(findings))
	}
}

// TestRareBoostSuppressedWhenSNIPresent asserts that when enrichBeaconSNI
// resolves a non-empty SNI for a finding that received the rare-destination
// boost, the boost is reversed: score reverts to unboostedScore, severity is
// recomputed, and the Detail fragment is updated.
func TestRareBoostSuppressedWhenSNIPresent(t *testing.T) {
	a := New(config.Default(), "", nil, nil)

	pk := pairKey{sensor: "s1", src: "192.168.1.10", dst: "172.64.149.56"}
	boostDetail := " | Prevalence: 1/50 (<2%) — rare dst, score boosted"
	a.findings = append(a.findings, model.Finding{
		Type:     "Beacon",
		Score:    90,
		Severity: model.SevCritical,
		Sensor:   pk.sensor,
		SrcIP:    pk.src,
		DstIP:    pk.dst,
		Detail:   "Connections: 200 | Mean interval: 7214.7s" + boostDetail,
	})

	uid := "Cabc123"
	a.sslUIDIndex[uid] = sslEntry{serverName: "api.example.com", ja3: "deadbeef"}
	a.beaconSNINeeds[pk] = beaconSNINeed{
		candidates:     []string{uid},
		prevDetail:     boostDetail,
		unboostedScore: 78,
	}

	a.enrichBeaconSNI()

	f := a.findings[0]
	if f.Score != 78 {
		t.Errorf("Score = %d; want 78 — boost must be suppressed when SNI is present", f.Score)
	}
	if f.Severity != model.SevHigh {
		t.Errorf("Severity = %v; want High — 78 is below the Critical threshold of 85", f.Severity)
	}
	if f.Hostname != "api.example.com" {
		t.Errorf("Hostname = %q; want api.example.com", f.Hostname)
	}
	if strings.Contains(f.Detail, "score boosted") {
		t.Error("Detail still says 'score boosted' after SNI-gated suppression")
	}
	if !strings.Contains(f.Detail, "boost suppressed (SNI present)") {
		t.Errorf("Detail missing 'boost suppressed (SNI present)', got: %s", f.Detail)
	}
}

// TestRareBoostRetainedWhenNoSNI asserts that when the ssl entry resolves to
// an empty server_name, the rare boost is kept and the finding is unchanged.
func TestRareBoostRetainedWhenNoSNI(t *testing.T) {
	a := New(config.Default(), "", nil, nil)

	pk := pairKey{sensor: "s1", src: "192.168.1.10", dst: "203.0.113.1"}
	boostDetail := " | Prevalence: 1/50 (<2%) — rare dst, score boosted"
	a.findings = append(a.findings, model.Finding{
		Type:     "Beacon",
		Score:    90,
		Severity: model.SevCritical,
		Sensor:   pk.sensor,
		SrcIP:    pk.src,
		DstIP:    pk.dst,
		Detail:   "Connections: 200 | Mean interval: 3600.0s" + boostDetail,
	})

	uid := "Cxyz456"
	a.sslUIDIndex[uid] = sslEntry{serverName: "", ja3: "deadbeef"}
	a.beaconSNINeeds[pk] = beaconSNINeed{
		candidates:     []string{uid},
		prevDetail:     boostDetail,
		unboostedScore: 78,
	}

	a.enrichBeaconSNI()

	f := a.findings[0]
	if f.Score != 90 {
		t.Errorf("Score = %d; want 90 — boost must be retained when no SNI resolves", f.Score)
	}
	if f.Severity != model.SevCritical {
		t.Errorf("Severity = %v; want Critical — score 90 is above the 85 threshold", f.Severity)
	}
	if strings.Contains(f.Detail, "boost suppressed") {
		t.Error("Detail incorrectly says 'boost suppressed' when no SNI was found")
	}
}

// TestBeaconModalPortLabel asserts the dominant-port labeling fix. A
// single (src,dst) beacon whose connections span two destination ports —
// 8 early conns on 22, 40 later conns on 443 — must be labeled with the
// MODAL port (443, the one carrying the beacon), not the first-seen port
// (22). Pre-fix the analyzer reported st.firstPort, so the earliest stray
// connection's port mislabeled the finding (the 110382 bug). The minority
// port must also be surfaced, not silently dropped: the Detail carries a
// co-traffic line naming port 22, its connection count, byte volume, and
// first/last-seen timestamps.
func TestBeaconModalPortLabel(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	findings := a.Analyze([]string{"testdata/zeek/beacon_multiport/conn.log"})

	var b *model.Finding
	for i := range findings {
		if findings[i].Type == "Beacon" {
			b = &findings[i]
			break
		}
	}
	if b == nil {
		t.Fatalf("expected a Beacon finding from beacon_multiport fixture, got types: %v", findingTypes(findings))
	}

	if b.DstPort != "443" {
		t.Errorf("DstPort = %q; want \"443\" — beacon must be labeled with the modal port (40 conns), not the first-seen port 22 (8 conns)", b.DstPort)
	}
	if !strings.Contains(b.Detail, "co-traffic to dst:") {
		t.Errorf("Detail missing co-traffic line, got: %s", b.Detail)
	}
	if !strings.Contains(b.Detail, "22×8") {
		t.Errorf("co-traffic line must name minority port 22 with its 8 conns, got: %s", b.Detail)
	}
	if !strings.Contains(b.Detail, "14.1 KB") {
		t.Errorf("co-traffic line must carry port-22 byte volume (14.1 KB), got: %s", b.Detail)
	}
	if !strings.Contains(b.Detail, "2024-01-15 12:00") || !strings.Contains(b.Detail, "2024-01-15 12:35") {
		t.Errorf("co-traffic line must carry port-22 first/last-seen timestamps (2024-01-15 12:00→12:35), got: %s", b.Detail)
	}
	// The dominant port is the label, never duplicated into the co-traffic
	// list — only the OTHER ports appear there.
	coIdx := strings.Index(b.Detail, "co-traffic to dst:")
	if coIdx >= 0 && strings.Contains(b.Detail[coIdx:], "443×") {
		t.Errorf("dominant port 443 must not appear in its own co-traffic list, got: %s", b.Detail[coIdx:])
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
