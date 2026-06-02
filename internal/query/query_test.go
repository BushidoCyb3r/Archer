package query

import (
	"testing"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// matches parses q and returns whether f matches, failing the test on a
// parse error. Timezone is UTC unless a test needs otherwise.
func matches(t *testing.T, q string, f model.Finding) bool {
	t.Helper()
	parsed, err := Parse(q)
	if err != nil {
		t.Fatalf("Parse(%q) unexpected error: %v", q, err)
	}
	return parsed.Match(f, time.UTC)
}

func beacon() model.Finding {
	return model.Finding{
		Type:     "Beaconing",
		Severity: model.SevCritical,
		Score:    98,
		SrcIP:    "10.2.4.9",
		DstIP:    "91.218.114.11",
		DstPort:  "443",
		Detail:   "Spectral rescued: period 3600s",
		Hostname: "cdn.evil.com",
		Sensor:   "sensor-a",
		JA3:      "a0e9f5d64349fb13191bc781f81f42e1",
	}
}

func TestParseEmptyMatchesEverything(t *testing.T) {
	for _, q := range []string{"", "   ", "\t"} {
		if !matches(t, q, beacon()) {
			t.Errorf("empty query %q should match everything", q)
		}
	}
}

func TestFieldExactMatch(t *testing.T) {
	tests := []struct {
		q    string
		want bool
	}{
		{"type:Beaconing", true},
		{"type:beaconing", true}, // case-insensitive
		{`type:"DNS Tunneling"`, false},
		{"severity:CRITICAL", true},
		{"severity:critical", true},
		{"severity:HIGH", false},
		{"sensor:sensor-a", true},
		{"sensor:sensor-b", false},
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, beacon()); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestBareTermSubstringAcrossFields(t *testing.T) {
	f := beacon()
	tests := []struct {
		q    string
		want bool
	}{
		{"Beaconing", true},  // type
		{"rescued", true},    // detail substring
		{"443", true},        // port
		{"nonsense", false},  //
		{"10.2.4.9", true},   // exact IP against src
		{"10.2.4.99", false}, // full-IP must be exact, not prefix
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, f); got != tc.want {
			t.Errorf("bare %q = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestBooleanOperators(t *testing.T) {
	f := beacon()
	tests := []struct {
		q    string
		want bool
	}{
		{"type:Beaconing AND severity:CRITICAL", true},
		{"type:Beaconing AND severity:HIGH", false},
		{`type:"DNS Tunneling" OR severity:CRITICAL`, true},
		{`type:"DNS Tunneling" OR severity:HIGH`, false},
		{"NOT type:Beaconing", false},
		{`NOT type:"DNS Tunneling"`, true},
		{"type:Beaconing severity:CRITICAL", true}, // implicit AND
		{"type:Beaconing severity:HIGH", false},    // implicit AND
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, f); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestPrecedenceAndGrouping(t *testing.T) {
	f := beacon() // type=Beaconing, sev=CRITICAL
	tests := []struct {
		q    string
		want bool
	}{
		// AND binds tighter than OR: (DNS AND HIGH) OR CRITICAL -> true.
		{`type:"DNS Tunneling" AND severity:HIGH OR severity:CRITICAL`, true},
		// Grouping flips it: DNS AND (HIGH OR CRITICAL) -> false (not DNS).
		{`type:"DNS Tunneling" AND (severity:HIGH OR severity:CRITICAL)`, false},
		// NOT binds tighter than AND.
		{`NOT type:"DNS Tunneling" AND severity:CRITICAL`, true},
		{"(type:Beaconing OR type:Strobe) AND severity:CRITICAL", true},
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, f); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestQuotedPhrase(t *testing.T) {
	f := beacon() // detail contains "Spectral rescued: period 3600s"
	if !matches(t, `detail:"Spectral rescued"`, f) {
		t.Error(`detail:"Spectral rescued" should match`)
	}
	if matches(t, `detail:"rescued spectral"`, f) {
		t.Error("phrase order matters; should not match")
	}
	// A bare quoted phrase is an all-field substring.
	if !matches(t, `"period 3600s"`, f) {
		t.Error("bare quoted phrase should substring-match detail")
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		"type:",              // missing value
		"(type:Beaconing",    // unbalanced paren
		"type:Beaconing )",   // stray close paren
		"AND type:Beaconing", // leading binary operator
		"type:Beaconing AND", // trailing binary operator
		"score:[80 TO]",      // malformed range
		"score:[TO 100]",     // malformed range
	}
	for _, q := range bad {
		if _, err := Parse(q); err == nil {
			t.Errorf("Parse(%q) expected error, got nil", q)
		}
	}
}
