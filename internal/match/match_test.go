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

func TestCompile_Wildcards(t *testing.T) {
	m := Compile([]string{
		"*.in-addr.arpa", // reverse-DNS apex family (the motivating case)
		"*.ip6.arpa",
		"185.220.*",       // IP-prefix glob
		"10.?.0.1",        // single-char glob
		"*.internal.corp", // domain suffix glob
		"203.0.113.10",    // a literal alongside (must still be exact)
		"192.168.0.0/16",  // a CIDR alongside (must still be CIDR)
	})
	tests := []struct {
		candidate string
		want      bool
	}{
		// Reverse-DNS apexes (DNS findings put the apex in DstIP).
		{"172.in-addr.arpa", true},
		{"10.in-addr.arpa", true},
		{"168.192.in-addr.arpa", true},
		{"172.IN-ADDR.ARPA", true}, // case-insensitive
		{"1.0.0.0.ip6.arpa", true},
		// in-addr.arpa without the leading label still needs a label before the
		// dot to satisfy `*.in-addr.arpa`; the bare suffix should NOT match.
		{"in-addr.arpa", false},
		// IP-prefix glob.
		{"185.220.114.11", true},
		{"185.221.1.1", false},
		// Single-char glob.
		{"10.5.0.1", true},
		{"10.55.0.1", false}, // ? is exactly one char
		// Domain suffix glob.
		{"host.internal.corp", true},
		{"internal.corp", false},
		{"host.internal.corp.evil.com", false}, // anchored — must end at the pattern
		// Literal and CIDR neighbours still work.
		{"203.0.113.10", true},
		{"203.0.113.11", false},
		{"192.168.5.5", true},
		{"11.0.0.1", false},
	}
	for _, tt := range tests {
		if got := m.Matches(tt.candidate); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.candidate, got, tt.want)
		}
	}
}

// TestCompile_NoWildcardsNoGlobTier pins the feed-path guarantee: a list with
// no wildcard entries compiles to an empty glob tier, so the per-candidate
// glob scan is skipped entirely (the 1M-indicator feed matchers stay fast).
func TestCompile_NoWildcardsNoGlobTier(t *testing.T) {
	m := Compile([]string{"1.2.3.4", "evil.test", "10.0.0.0/8"})
	if len(m.globs) != 0 {
		t.Errorf("expected no glob entries, got %v", m.globs)
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

func TestIPv6Canonicalization(t *testing.T) {
	// Non-canonical IPv6 in the allowlist should match the canonical form
	// Zeek emits, and vice versa. net.ParseIP normalises to the compressed
	// form (::), so both directions must work.
	nonCanonical := "2606:4700:4700:0:0:0:0:1111"
	canonical := "2606:4700:4700::1111"

	mNon := Compile([]string{nonCanonical})
	if !mNon.Matches(canonical) {
		t.Errorf("non-canonical allowlist entry should match canonical candidate")
	}
	if !mNon.Matches(nonCanonical) {
		t.Errorf("non-canonical allowlist entry should match itself")
	}

	mCan := Compile([]string{canonical})
	if !mCan.Matches(nonCanonical) {
		t.Errorf("canonical allowlist entry should match non-canonical candidate")
	}

	// IPv4 must not be altered — canonical form is identical.
	mIPv4 := Compile([]string{"1.2.3.4"})
	if !mIPv4.Matches("1.2.3.4") {
		t.Errorf("IPv4 exact match should still work after canonicalization")
	}

	// Domain entries must not be affected by IP canonicalization.
	mDomain := Compile([]string{"example.com"})
	if !mDomain.Matches("example.com") {
		t.Errorf("domain entry should still match exactly")
	}
	if mDomain.Matches("EXAMPLE.COM") {
		t.Errorf("domain match should not do case folding")
	}
}
