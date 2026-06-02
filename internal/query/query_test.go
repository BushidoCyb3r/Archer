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
		Type:     "Beacon",
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
		{"type:Beacon", true},
		{"type:beacon", true}, // case-insensitive
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
		{"Beacon", true},     // type
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
		{"type:Beacon AND severity:CRITICAL", true},
		{"type:Beacon AND severity:HIGH", false},
		{`type:"DNS Tunneling" OR severity:CRITICAL`, true},
		{`type:"DNS Tunneling" OR severity:HIGH`, false},
		{"NOT type:Beacon", false},
		{`NOT type:"DNS Tunneling"`, true},
		{"type:Beacon AND NOT type:Strobe", true},
	}
	for _, tc := range tests {
		if got := matches(t, tc.q, f); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestPrecedenceAndGrouping(t *testing.T) {
	f := beacon() // type=Beacon, sev=CRITICAL
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
		{"(type:Beacon OR type:Strobe) AND severity:CRITICAL", true},
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
		"type:",                         // missing value
		"(type:Beacon",                  // unbalanced paren
		"type:Beacon )",                 // stray close paren
		"AND type:Beacon",               // leading binary operator
		"type:Beacon AND",               // trailing binary operator
		"score:[80 TO]",                 // malformed range
		"score:[TO 100]",                // malformed range
		"dest:1.2.3.4",                  // unknown field (misspelled dst)
		"type:Beaon",                    // unknown finding type (misspelled, plain)
		`type:"Correlatd Activity"`,     // unknown finding type (misspelled, quoted)
		"type:Beaconing",                // retired pre-v0.50 type
		"type:Beacon severity:CRITICAL", // missing operator between terms
		"type:Beacon NOT type:Strobe",   // missing operator before NOT
		"type:Beacon (severity:HIGH)",   // missing operator before group
		"severity:HIGH score:>=90",      // missing operator between terms
		"185.220.101.7 type:Beacon",     // bare term then field, no operator
		`type:Beacon "DNS Tunneling"`,   // field then bare phrase, no operator
	}
	for _, q := range bad {
		if _, err := Parse(q); err == nil {
			t.Errorf("Parse(%q) expected error, got nil", q)
		}
	}
}

// TestTypeValueValidation pins the rule the red query-error toast depends on:
// an exact type: term must name a real finding type, but the family selector,
// case folding, and multi-word quoted types stay valid.
func TestTypeValueValidation(t *testing.T) {
	good := []string{
		"type:Beacon", "type:beacon", // exact + case-insensitive
		`type:"DNS Tunneling"`,       // multi-word quoted type
		`type:"Correlated Activity"`, // multi-word, correctly spelled
		"type:beacons",               // family selector — always valid
		"type:Strobe AND score:>=90", // composed with other terms
	}
	for _, q := range good {
		if _, err := Parse(q); err != nil {
			t.Errorf("Parse(%q) unexpected error: %v", q, err)
		}
	}
}
