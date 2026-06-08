package analysis

import (
	"fmt"
	"os"
	"path/filepath"
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

// TestAuxKeyCapSparesBeaconPath is the mission-critical regression for the
// PERF-1 cap: bounding the strobe/exfil/off-hours auxiliary maps must never
// cost a beacon. The fixture floods the analyzer with enough distinct
// single-connection host-pairs to blow past a lowered maxConnAuxKeys, THEN
// presents one clean 60-second beacon whose pair is therefore refused entry
// to the aux maps. Invariants: (1) the beacon is still detected, and (2) the
// operator gets the one-shot "capped" status warning so the undercount is
// never silent. If a future refactor accidentally gates the beacon path on
// the same cap, the beacon vanishes here and the test fails.
func TestAuxKeyCapSparesBeaconPath(t *testing.T) {
	orig := maxConnAuxKeys
	maxConnAuxKeys = 8
	defer func() { maxConnAuxKeys = orig }()

	dir := t.TempDir()
	path := filepath.Join(dir, "conn.log")

	var b strings.Builder
	uid := 0
	line := func(ts float64, src, dst string, port int) {
		fmt.Fprintf(&b, `{"ts": %.1f, "uid": "C%07d", "id.orig_h": "%s", "id.orig_p": 40000, "id.resp_h": "%s", "id.resp_p": %d, "proto": "tcp", "duration": 0.3, "orig_bytes": 400, "resp_bytes": 800, "orig_ip_bytes": 440, "resp_ip_bytes": 840, "conn_state": "SF"}`+"\n",
			ts, uid, src, dst, port)
		uid++
	}

	// 30 distinct single-connection pairs — far past the cap of 8 — so the
	// aux maps are full before the beacon's pair is ever seen.
	base := 1705320000.0
	for i := 0; i < 30; i++ {
		line(base+float64(i), "192.168.1.10", fmt.Sprintf("198.51.100.%d", i+1), 443)
	}
	// The beacon, presented last: 100 connections at a clean 60s cadence to
	// one external host — enough for the confidence ramp to clear the emit
	// floor. Its (src,dst) pair is first seen well after the aux cap filled,
	// so it never entered the strobe/exfil/off-hours maps.
	for i := 0; i < 100; i++ {
		line(base+1000+float64(i)*60.0, "192.168.1.10", "203.0.113.77", 8443)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	status := make(chan string, 64)
	a := New(config.Default(), "", nil, status)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	findings := a.Analyze([]string{path})

	var beacon *model.Finding
	for i := range findings {
		if findings[i].Type == "Beacon" && findings[i].DstIP == "203.0.113.77" {
			beacon = &findings[i]
			break
		}
	}
	if beacon == nil {
		t.Fatalf("beacon to 203.0.113.77 was lost when the aux cap was hit — the cap leaked into the beacon path. Got types: %v", findingTypes(findings))
	}

	close(status)
	var warned bool
	for msg := range status {
		if strings.Contains(msg, "capped") {
			warned = true
		}
	}
	if !warned {
		t.Error("aux cap was exceeded but no operator warning was emitted — a silent undercount")
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

// TestPortHoppingBeacon pins the Port-Hopping Beacon detector: a single
// (src,dst) pair that beacons on a regular cadence but spreads its
// connections across many destination ports with no dominant port (here 36
// conns round-robin over 6 ports, max share 16.7%) must be relabeled from
// "Beacon" to "Port-Hopping Beacon". The pair still qualifies as a beacon —
// the relabel is a promotion of an already-emitted finding, never a gate, so
// no detection is lost. The Detail must surface the port spread, and the
// triage sub-scores must still be populated (it stays in the beacon family).
func TestPortHoppingBeacon(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	findings := a.Analyze([]string{"testdata/zeek/port_hopping_beacon/conn.log"})

	var b *model.Finding
	for i := range findings {
		if findings[i].Type == "Port-Hopping Beacon" {
			b = &findings[i]
			break
		}
	}
	if b == nil {
		t.Fatalf("expected a Port-Hopping Beacon finding, got types: %v", findingTypes(findings))
	}
	// A plain Beacon must NOT also be emitted for the same pair — the
	// port-hopper is the single finding for this (src,dst).
	if hasFindingType(findings, "Beacon") {
		t.Errorf("port-hopping pair must emit one Port-Hopping Beacon, not also a plain Beacon; types: %v", findingTypes(findings))
	}
	if !strings.Contains(b.Detail, "Port-hopping:") {
		t.Errorf("Detail must summarize the port spread, got: %s", b.Detail)
	}
	if b.TSScore == 0 {
		t.Errorf("Port-Hopping Beacon must carry beacon sub-scores (TSScore populated), got 0")
	}
	if !model.IsBeaconType(b.Type) {
		t.Errorf("Port-Hopping Beacon must be in the beacon family (IsBeaconType)")
	}
}

// TestLateralMovementPorts pins the Lateral Movement detector's port set and
// labeling. Invariant: an internal→internal connection on any port in
// LateralMovementPorts emits exactly one Lateral Movement finding labeled with
// that port's protocol (never "unknown"), while an internal→internal
// connection on a non-admin port and an internal→external connection on an
// admin port both emit none (the detector is internal-only and port-scoped).
// Iterating the live port map means a future port added without a matching
// lateralPortLabel entry, or removed from the set, fails here — and it pins the
// VNC (5900) and Telnet (23) additions specifically.
func TestLateralMovementPorts(t *testing.T) {
	// Each lateral port gets its own internal→internal pair so the per-pair
	// dedup never collapses two ports together.
	ports := make([]int, 0, len(LateralMovementPorts))
	for p := range LateralMovementPorts {
		ports = append(ports, p)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "conn.log")
	var b strings.Builder
	uid := 0
	// base is 2024-01-15 12:00:00 UTC — daytime, outside the default 22–06
	// off-hours window, so Off-Hours Transfer doesn't fire on these conns.
	base := 1705320000.0
	line := func(src, dst string, port int) {
		fmt.Fprintf(&b, `{"ts": %.1f, "uid": "C%07d", "id.orig_h": "%s", "id.orig_p": 40000, "id.resp_h": "%s", "id.resp_p": %d, "proto": "tcp", "duration": 1.2, "orig_bytes": 500, "resp_bytes": 700, "orig_ip_bytes": 540, "resp_ip_bytes": 740, "conn_state": "SF"}`+"\n",
			base+float64(uid), uid, src, dst, port)
		uid++
	}

	for i, p := range ports {
		line(fmt.Sprintf("192.168.10.%d", i+1), fmt.Sprintf("192.168.20.%d", i+1), p)
	}
	// Negative: internal→internal on a non-admin port (443) must not fire.
	line("192.168.30.1", "192.168.30.2", 443)
	// Negative: internal→external on an admin port (3389) must not fire — the
	// detector requires both endpoints to be internal.
	line("192.168.40.1", "203.0.113.9", 3389)

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	findings := a.Analyze([]string{path})

	lateralByPort := map[string]model.Finding{}
	for _, f := range findings {
		if f.Type == "Lateral Movement" {
			lateralByPort[f.DstPort] = f
		}
	}

	for _, p := range ports {
		f, ok := lateralByPort[fmt.Sprint(p)]
		if !ok {
			t.Errorf("port %d in LateralMovementPorts produced no Lateral Movement finding", p)
			continue
		}
		label := lateralPortLabel(p)
		if label == "unknown" {
			t.Errorf("port %d is in LateralMovementPorts but lateralPortLabel returns \"unknown\" — add a label", p)
		}
		if !strings.Contains(f.Detail, label) {
			t.Errorf("port %d: Detail %q does not carry the protocol label %q", p, f.Detail, label)
		}
	}

	// Explicit pins for the two additions so their intent is documented even
	// if the port set is later reshaped.
	if _, ok := lateralByPort["23"]; !ok {
		t.Error("Telnet (23) must be flagged as Lateral Movement")
	}
	if _, ok := lateralByPort["5900"]; !ok {
		t.Error("VNC (5900) must be flagged as Lateral Movement")
	}

	// Negative cases: the non-admin internal pair and the external-dst admin
	// pair must not appear.
	for _, f := range findings {
		if f.Type != "Lateral Movement" {
			continue
		}
		if f.SrcIP == "192.168.30.1" {
			t.Errorf("internal→internal on non-admin port 443 must not emit Lateral Movement, got: %s", f.Detail)
		}
		if f.DstIP == "203.0.113.9" {
			t.Errorf("internal→external on admin port 3389 must not emit Lateral Movement (internal-only detector)")
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

// TestConnDetectors_SkipMulticastDest pins the local-infrastructure exclusion:
// a perfectly periodic UDP stream to the mDNS multicast group (224.0.0.251:5353)
// — which would otherwise qualify as a Beacon — must produce no conn findings.
// Multicast/broadcast/IPv6-link-local destinations are local network
// infrastructure (mDNS, SSDP, LLMNR), never a routable C2 endpoint, and slip
// isPrivateIP because they aren't RFC-1918, so they must be dropped up front.
func TestConnDetectors_SkipMulticastDest(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	findings := a.Analyze([]string{"testdata/zeek/beacon_multicast/conn.log"})
	if len(findings) != 0 {
		t.Errorf("multicast-dest traffic produced %d finding(s); want 0 — local infra must be skipped: %v",
			len(findings), findingTypes(findings))
	}
}

func findingTypes(findings []model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Type)
	}
	return out
}

// TestProtocolOnUnexpectedPort pins the service-port-mismatch detector. The
// invariant: a connection to an EXTERNAL destination whose Zeek DPD service is
// known but runs on a port outside that service's expected set emits exactly
// one "Protocol on Unexpected Port" finding; an expected-port connection, an
// internal destination, and an empty (unfingerprinted) service emit none. The
// fixture exercises all four shapes plus the C2-port score bump.
func TestProtocolOnUnexpectedPort(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	findings := a.Analyze([]string{"testdata/zeek/service_port_mismatch/conn.log"})

	var got []model.Finding
	for _, f := range findings {
		if f.Type == "Protocol on Unexpected Port" {
			got = append(got, f)
		}
	}
	// Two external mismatches: http/8443 and ssl/4444. The expected-port
	// (http/80), internal-destination (http/9099), and empty-service (31337)
	// records must each produce nothing.
	if len(got) != 2 {
		t.Fatalf("expected 2 Protocol on Unexpected Port findings (http/8443, ssl/4444), got %d: %v", len(got), findingTypes(findings))
	}

	byPort := map[string]model.Finding{}
	for _, f := range got {
		byPort[f.DstPort] = f
	}
	http8443, ok := byPort["8443"]
	if !ok {
		t.Fatalf("missing finding for http on 8443; ports seen: %v", byPort)
	}
	if http8443.Score != 70 {
		t.Errorf("http/8443 score = %d; want 70 (mismatch on a non-C2 port)", http8443.Score)
	}
	if http8443.DstIP != "203.0.113.10" {
		t.Errorf("http/8443 DstIP = %q; want 203.0.113.10", http8443.DstIP)
	}
	if !strings.Contains(http8443.Detail, "http") || !strings.Contains(http8443.Detail, "8443") {
		t.Errorf("http/8443 Detail must name the service and port, got: %s", http8443.Detail)
	}

	ssl4444, ok := byPort["4444"]
	if !ok {
		t.Fatalf("missing finding for ssl on 4444; ports seen: %v", byPort)
	}
	if ssl4444.Score != 75 {
		t.Errorf("ssl/4444 score = %d; want 75 (mismatch on a known C2 port)", ssl4444.Score)
	}
	if !strings.Contains(ssl4444.Detail, "Metasploit") {
		t.Errorf("ssl/4444 Detail must carry the C2-port label, got: %s", ssl4444.Detail)
	}
}
