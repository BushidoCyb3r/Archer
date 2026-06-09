package analysis

import "testing"

// TestIsPrivateIP_DomainsNotMisclassified is the LG-5 regression: isPrivateIP
// is called with DstIP, which for DNS-derived findings is a domain. The IPv6
// unique-local check keyed on the bare "fc"/"fd" prefixes matched domains
// like fda.gov and fcc.gov, excluding them from TI matching and staging. The
// IPv6 checks must apply only to strings that look like IPv6 (contain ":"),
// while genuine RFC-1918/loopback/link-local and real ULA addresses still
// register as private.
func TestIsPrivateIP_DomainsNotMisclassified(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// Domains that begin fc/fd must NOT be treated as private.
		{"fda.gov", false},
		{"fcc.gov", false},
		{"fdic.gov", false},
		{"fd-cdn.example.com", false},
		{"facebook.com", false},
		// Other public domains.
		{"example.com", false},
		{"10domains.io", false},
		// Genuine IPv6 unique-local / loopback still private.
		{"fc00::1", true},
		{"fd12:3456:789a::1", true},
		{"::1", true},
		// Public IPv6 not private.
		{"2001:db8::1", false},
		// IPv4 private ranges unchanged.
		{"10.0.0.5", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		// Public IPv4 unchanged.
		{"203.0.113.5", false},
		{"8.8.8.8", false},
		{"172.32.0.1", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isPrivateIP(c.in); got != c.want {
			t.Errorf("isPrivateIP(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}
