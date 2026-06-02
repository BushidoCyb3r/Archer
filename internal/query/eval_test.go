package query

import (
	"testing"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

func TestNumericScore(t *testing.T) {
	f := beacon() // score 98
	tests := []struct {
		q    string
		want bool
	}{
		{"score:>=90", true},
		{"score:>98", false},
		{"score:>=98", true},
		{"score:<=98", true},
		{"score:<98", false},
		{"score:=98", true},
		{"score:98", true}, // bare value == equality
		{"score:[80 TO 100]", true},
		{"score:[99 TO 100]", false},
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, f); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestIPAndCIDR(t *testing.T) {
	f := beacon() // src 10.2.4.9, dst 91.218.114.11
	tests := []struct {
		q    string
		want bool
	}{
		{"src:10.2.4.9", true},
		{"src:10.2.0.0/16", true},
		{"src:10.3.0.0/16", false},
		{"dst:91.218.114.11", true},
		{"dst:91.218.0.0/16", true},
		{"dst:10.0.0.0/8", false},
		{"dst:91.218.*", true}, // non-CIDR -> wildcard against the IP string
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, f); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestPort(t *testing.T) {
	f := beacon() // port 443
	tests := []struct {
		q    string
		want bool
	}{
		{"port:443", true},
		{"port:80", false},
		{"port:80,443", true},
		{"port:80,8080", false},
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, f); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestStringFieldsAndWildcards(t *testing.T) {
	f := beacon() // hostname cdn.evil.com
	f.SourceFile = "conn.log"
	tests := []struct {
		q    string
		want bool
	}{
		{"hostname:evil.com", true},     // substring
		{"hostname:cdn.*", true},        // trailing wildcard
		{"hostname:*.evil.com", true},   // leading wildcard
		{"hostname:*.good.com", false},  //
		{"hostname:cdn?evil.com", true}, // single-char wildcard for the dot
		{"file:conn", true},
		{"file:dns", false},
		{"detail:period*3600", true}, // wildcard inside detail
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, f); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestStatus(t *testing.T) {
	open := beacon() // Status ""
	ack := beacon()
	ack.Status = model.StatusAcknowledged
	if !matches(t, "status:open", open) {
		t.Error("empty status should match status:open")
	}
	if matches(t, "status:acknowledged", open) {
		t.Error("open finding should not match status:acknowledged")
	}
	if !matches(t, "status:acknowledged", ack) {
		t.Error("acknowledged finding should match status:acknowledged")
	}
	if matches(t, "status:open", ack) {
		t.Error("acknowledged finding should not match status:open")
	}
}

func TestFingerprintFields(t *testing.T) {
	f := beacon() // JA3 stored lowercased
	if !matches(t, "ja3:a0e9f5d64349fb13191bc781f81f42e1", f) {
		t.Error("exact ja3 should match")
	}
	if !matches(t, "ja3:A0E9F5D64349FB13191BC781F81F42E1", f) {
		t.Error("uppercase ja3 should match (case-insensitive)")
	}
	if matches(t, "ja3:deadbeef", f) {
		t.Error("wrong ja3 should not match")
	}
}

func TestBoolFields(t *testing.T) {
	f := beacon() // IOCMatch false, IsNewToMe false, detail has "Spectral rescued:"
	if matches(t, "ioc:true", f) {
		t.Error("non-IOC finding should not match ioc:true")
	}
	if !matches(t, "ioc:false", f) {
		t.Error("non-IOC finding should match ioc:false")
	}
	if !matches(t, "spectral:true", f) {
		t.Error("spectral-rescued finding should match spectral:true")
	}
	if matches(t, "new:true", f) {
		t.Error("not-new finding should not match new:true")
	}
	f.IOCMatch = true
	if !matches(t, "ioc:true", f) {
		t.Error("IOC finding should match ioc:true")
	}
}

func TestTimeRange(t *testing.T) {
	f := beacon()
	f.Timestamp = "2026-03-15 12:00:00"
	if !matches(t, "ts:[2026-03-01 TO 2026-04-01]", f) {
		t.Error("in-window finding should match")
	}
	if matches(t, "ts:[2026-01-01 TO 2026-02-01]", f) {
		t.Error("out-of-window finding should not match")
	}
	if !matches(t, "ts:2026-03-15", f) {
		t.Error("same-day bare date should match")
	}
	if matches(t, "ts:2026-03-16", f) {
		t.Error("different day should not match")
	}
}

func TestSubScoreBeaconScope(t *testing.T) {
	b := beacon()
	b.DurScore = 0.2
	if !matches(t, "dur:<0.3", b) {
		t.Error("beacon with dur 0.2 should match dur:<0.3")
	}
	if matches(t, "dur:>=0.3", b) {
		t.Error("beacon with dur 0.2 should not match dur:>=0.3")
	}
	// Non-beacon: a sub-score predicate must NOT match even though the
	// structural zero (0.0) satisfies <0.3 numerically.
	nonBeacon := model.Finding{Type: "DNS Tunneling", Severity: model.SevHigh, Score: 70}
	if matches(t, "dur:<0.3", nonBeacon) {
		t.Error("non-beacon must not match a sub-score predicate (beacon-scope rule)")
	}
}

func TestBeaconMetricFields(t *testing.T) {
	b := beacon()
	b.SampleSize = 8640
	b.MeanInterval = 9.5
	b.MedianInterval = 10
	b.Jitter = 0.42
	tests := []struct {
		q    string
		want bool
	}{
		{"conns:<=10000", true},
		{"conns:>10000", false},
		{"conns:[8000 TO 9000]", true},
		{"conns:8640", true},
		{"meanint:<=10", true},
		{"meanint:<9", false},
		{"medint:>=10", true},
		{"jitter:<0.5", true},
		{"jitter:>=0.5", false},
		{"connections:<=10000", true},  // alias
		{"mean_interval:<=10", true},   // alias
		{"median_interval:>=10", true}, // alias
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, b); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
	// Beacon-scope: a non-beacon whose metrics are a structural zero must
	// not surface under a bare upper bound (same rule as the sub-scores).
	nonBeacon := model.Finding{Type: "DNS Tunneling", Severity: model.SevHigh, Score: 70}
	if matches(t, "conns:<=10000", nonBeacon) {
		t.Error("non-beacon must not match conns:<=10000 (beacon-scope rule)")
	}
	if matches(t, "meanint:<=10", nonBeacon) {
		t.Error("non-beacon must not match meanint:<=10 (beacon-scope rule)")
	}
}

func TestIDField(t *testing.T) {
	f := beacon()
	f.ID = 1542
	tests := []struct {
		q    string
		want bool
	}{
		{"id:1542", true},
		{"id:=1542", true},
		{"id:1543", false},
		{"id:>=1000", true},
		{"id:<1000", false},
		{"id:[1500 TO 1600]", true},
		{"id:[1600 TO 1700]", false},
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, f); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
	// id is not beacon-scoped: every finding carries one.
	nonBeacon := model.Finding{Type: "DNS Tunneling", ID: 77, Severity: model.SevHigh, Score: 70}
	if !matches(t, "id:77", nonBeacon) {
		t.Error("id must match on a non-beacon finding")
	}
}

func TestUnknownFieldIsParseError(t *testing.T) {
	if _, err := Parse("bogus:value"); err == nil {
		t.Error("unknown field should be a parse error")
	}
}

func TestTimeComparisons(t *testing.T) {
	f := beacon()
	f.Timestamp = "2026-03-15 12:00:00"
	tests := []struct {
		q    string
		want bool
	}{
		{"ts:>=2026-03-15", true},
		{"ts:>=2026-03-16", false},
		{"ts:>2026-03-14", true},
		{"ts:>2026-03-15", false}, // a bare upper-of-day date excludes the same day's noon
		{"ts:<=2026-03-15", true},
		{"ts:<2026-03-16", true},
		{"ts:<2026-03-15", false},
		{`ts:>="2026-03-15 08:00:00"`, true},
		{`ts:<"2026-03-15 08:00:00"`, false},
	}
	for _, c := range tests {
		if got := matches(t, c.q, f); got != c.want {
			t.Errorf("%s: got %v want %v", c.q, got, c.want)
		}
	}
}

func TestOperatorTimezone(t *testing.T) {
	f := beacon()
	f.Timestamp = "2026-03-15 23:30:00" // UTC
	// In UTC+09:00 this is 2026-03-16 08:30 local. A bare ts of the local
	// day must match when interpreted in the operator timezone.
	loc := time.FixedZone("KST", 9*3600)
	parsed, err := Parse("ts:2026-03-16")
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Match(f, loc) {
		t.Error("bare date should be interpreted in the operator timezone")
	}
}
