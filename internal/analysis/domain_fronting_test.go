package analysis

import "testing"

// TestDomainFrontingMismatch codifies the invariant the Domain Fronting
// detector depends on: a mismatch fires only when the SNI and the HTTP Host
// header name genuinely different hosts. A :port suffix on the Host header
// (explicit-proxy CONNECT logs "example.com:443" while the TLS handshake
// records SNI "example.com") and a case difference are NOT mismatches —
// comparing the two raw, as the detector did before, emitted a score-88
// CRITICAL for every proxied HTTPS destination. The genuine-fronting case
// (Host and SNI naming different domains) must still fire.
func TestDomainFrontingMismatch(t *testing.T) {
	cases := []struct {
		name      string
		sni, host string
		want      bool
	}{
		{"identical", "example.com", "example.com", false},
		{"host has port suffix (proxy CONNECT)", "example.com", "example.com:443", false},
		{"case difference", "example.com", "Example.com", false},
		{"case difference both ways", "Example.COM", "example.com", false},
		{"port and case together", "example.com", "EXAMPLE.com:8443", false},
		{"genuine fronting", "cdn.cloudfront.net", "evil.example", true},
		{"genuine fronting with port", "cdn.cloudfront.net", "evil.example:443", true},
		{"empty sni", "", "example.com", false},
		{"empty host", "example.com", "", false},
		// IPv6 literal Host headers carry multiple colons and are bracketed;
		// the single-colon port-strip guard must leave them intact so a real
		// SNI/Host disagreement on an IPv6 dst still registers.
		{"ipv6 host not stripped", "example.com", "[2001:db8::1]", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := domainFrontingMismatch(c.sni, c.host); got != c.want {
				t.Errorf("domainFrontingMismatch(%q, %q) = %v; want %v", c.sni, c.host, got, c.want)
			}
		})
	}
}
