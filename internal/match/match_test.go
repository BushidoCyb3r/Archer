package match

import "testing"

func TestCompile_EmptyAndCommentLines(t *testing.T) {
	m := Compile([]string{"", "  ", "# section header", "1.2.3.4"})
	if !m.Matches("1.2.3.4") {
		t.Errorf("expected 1.2.3.4 to match")
	}
	if m.Matches("# section header") {
		t.Errorf("# comment lines must not be matchable")
	}
	if m.Matches("") {
		t.Errorf("empty candidate must never match")
	}
}

func TestCompile_ExactAndCIDR(t *testing.T) {
	m := Compile([]string{
		"203.0.113.10",
		"10.0.0.0/8",
		"evil.test",
		"2001:db8::/32",
	})
	tests := []struct {
		candidate string
		want      bool
	}{
		{"203.0.113.10", true},  // exact IPv4
		{"203.0.113.11", false}, // close miss
		{"10.5.6.7", true},      // CIDR hit
		{"11.5.6.7", false},     // outside CIDR
		{"evil.test", true},     // exact domain
		{"good.test", false},    // unrelated domain
		{"2001:db8::1", true},   // CIDR IPv6 hit
		{"2001:db9::1", false},  // CIDR IPv6 miss
	}
	for _, tt := range tests {
		if got := m.Matches(tt.candidate); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.candidate, got, tt.want)
		}
	}
}

func TestMatches_NilReceiver(t *testing.T) {
	var m *Matcher
	if m.Matches("1.2.3.4") {
		t.Errorf("nil matcher must not match anything")
	}
}

func TestMatches_DomainCandidatesSkipCIDRWalk(t *testing.T) {
	// A domain candidate (which can't ParseIP) must not accidentally hit a
	// CIDR — we want the CIDR walk to short-circuit on non-IP inputs.
	m := Compile([]string{"0.0.0.0/0"}) // matches every IP
	if m.Matches("evil.test") {
		t.Errorf("domain candidate must not match a CIDR")
	}
	if !m.Matches("1.2.3.4") {
		t.Errorf("IP candidate should still match the all-IPv4 CIDR")
	}
}
