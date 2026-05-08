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
	utc := New(utcCfg, nil, nil)
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
	ny := New(nyCfg, nil, nil)
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
	jst := New(jstCfg, nil, nil)
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
	a := New(cfg, nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	findings := a.Analyze([]string{"testdata/zeek/off_hours/conn.log"})
	if !hasFindingType(findings, "Off-Hours Transfer") {
		t.Errorf("bad timezone should fall back to UTC and fire detection, got types: %v", findingTypes(findings))
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
