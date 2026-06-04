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
		{"src:rfc1918", true},  // 10.2.4.9 is private/internal
		{"src:private", true},  // synonym for rfc1918
		{"dst:rfc1918", false}, // 91.218.114.11 is external
		{"NOT dst:rfc1918", true},
		{"src:rfc1918 AND NOT dst:rfc1918", true}, // outbound shape
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
	f.IOCMatch = true
	if !matches(t, "ioc:true", f) {
		t.Error("IOC finding should match ioc:true")
	}
	// channel: scopes to promoted per-channel beacon sub-findings.
	if matches(t, "channel:true", f) {
		t.Error("blend (empty Channel) should not match channel:true")
	}
	if !matches(t, "channel:false", f) {
		t.Error("blend (empty Channel) should match channel:false")
	}
	f.Channel = "ja3:deadbeefdeadbeefdeadbeefdeadbeef"
	if !matches(t, "channel:true", f) {
		t.Error("per-channel sub-finding should match channel:true")
	}
	if matches(t, "channel:false", f) {
		t.Error("per-channel sub-finding should not match channel:false")
	}
	// benign: matches a finding whose fingerprint was marked benign (the flag
	// is stamped by findings_filter; here we set it directly).
	if matches(t, "benign:true", f) {
		t.Error("non-allowlisted finding should not match benign:true")
	}
	if !matches(t, "benign:false", f) {
		t.Error("non-allowlisted finding should match benign:false")
	}
	f.TLSAllowlisted = true
	if !matches(t, "benign:true", f) {
		t.Error("allowlisted-fingerprint finding should match benign:true")
	}
	if matches(t, "benign:false", f) {
		t.Error("allowlisted-fingerprint finding should not match benign:false")
	}
}

// TestNewFieldRemoved pins the v0.54.0 removal of the new: query field: it
// duplicated the "New only" delta filter, so it's gone from the grammar and
// must now be rejected as an unknown field rather than silently matching.
func TestNewFieldRemoved(t *testing.T) {
	for _, q := range []string{"new:true", "new:false"} {
		if _, err := Parse(q); err == nil {
			t.Errorf("Parse(%q) succeeded; new: should be an unknown field", q)
		}
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

func TestURIField(t *testing.T) {
	f := beacon()
	f.Type = "HTTP Beacon"
	f.URI = "/submit.php"
	tests := []struct {
		q    string
		want bool
	}{
		{"uri:/submit.php", true},
		{"uri:submit", true}, // substring
		{"uri:*.php", true},
		{"uri:/sub*php", true},
		{"uri:/login", false},
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, f); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
	// A finding with no URI (every non-HTTP-Beacon type) must not match a
	// non-empty pattern — the field is naturally scoped without a guard.
	if matches(t, "uri:submit", beacon()) {
		t.Error("empty URI must not match uri:submit")
	}
}

func TestNoteAndAnalystFields(t *testing.T) {
	f := beacon()
	f.AnalystNote = "pending pcap pull — looks like cobalt"
	f.Analyst = "alice"
	tests := []struct {
		q    string
		want bool
	}{
		{"note:pcap", true},
		{"note:*cobalt*", true},
		{"note:lateral", false},
		{"analyst_note:pcap", true}, // alias
		{"analyst:alice", true},
		{"analyst:ALICE", true}, // case-insensitive
		{"analyst:bob", false},
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, f); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestDirectionField(t *testing.T) {
	outbound := beacon() // 10.2.4.9 (internal) -> 91.218.114.11 (external)
	inbound := model.Finding{Type: "Beacon", Severity: model.SevHigh, SrcIP: "91.218.114.11", DstIP: "10.2.4.9"}
	internal := model.Finding{Type: "Lateral Movement", Severity: model.SevHigh, SrcIP: "10.2.4.9", DstIP: "192.168.1.5"}
	external := model.Finding{Type: "Beacon", Severity: model.SevHigh, SrcIP: "8.8.8.8", DstIP: "91.218.114.11"}
	tests := []struct {
		q    string
		f    model.Finding
		want bool
	}{
		{"dir:outbound", outbound, true},
		{"dir:inbound", outbound, false},
		{"dir:inbound", inbound, true},
		{"dir:internal", internal, true},
		{"dir:lateral", internal, true}, // value alias for internal
		{"dir:external", external, true},
		{"dir:outbound", internal, false},
		{"direction:outbound", outbound, true},            // field alias
		{"type:beacons AND dir:outbound", outbound, true}, // the earlier pain point
		{"type:beacons AND dir:outbound", inbound, false},
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, tc.f); got != tc.want {
			t.Errorf("%q on %s->%s = %v, want %v", tc.q, tc.f.SrcIP, tc.f.DstIP, got, tc.want)
		}
	}
	// An unknown direction value is rejected loudly at the query bar, not a
	// silent no-match (consistent with type: misspelling rejection).
	if _, err := Parse("dir:sideways"); err == nil {
		t.Error("unknown direction value should be a parse error")
	}
}

func TestDetectedField(t *testing.T) {
	f := beacon()
	f.DetectedAt = time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC).Unix()
	tests := []struct {
		q    string
		want bool
	}{
		{"detected:>=2026-06-01", true},
		{"detected:>=2026-06-03", false},
		{"detected:<2026-06-03", true},
		{"detected:2026-06-02", true}, // bare date = whole-day window
		{"detected:2026-06-01", false},
		{"detected:[2026-06-01 TO 2026-06-30]", true},
		{"detected:[2026-01-01 TO 2026-02-01]", false},
		{"detected_at:>=2026-06-01", true}, // alias
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, f); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
	// A finding with no detected_at (epoch 0) can't be placed in time and must
	// not match any detected predicate — same shape as an unparseable ts.
	if matches(t, "detected:>=2026-06-01", beacon()) {
		t.Error("finding with no detected_at must not match a detected predicate")
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
