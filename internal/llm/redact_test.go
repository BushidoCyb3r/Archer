package llm

import (
	"net"
	"regexp"
	"strings"
	"testing"
)

// The core security invariant: after redaction, no internal address may remain
// in the text that leaves the box. This asserts the whole input space shape,
// not one example — every private-range family plus an org CIDR, mixed with
// external indicators that must survive.
func TestRedactRemovesAllInternalAddresses(t *testing.T) {
	r := NewRedactor([]string{"203.0.113.0/24", "198.51.100.42"})
	text := strings.Join([]string{
		"src 10.1.2.3 beaconing to 8.8.8.8",
		"lateral 192.168.5.9 -> 172.16.0.4",
		"link-local 169.254.1.1 loopback 127.0.0.1",
		"org host 203.0.113.77 and single 198.51.100.42",
		"ipv6 ula fc00::1 and global 2606:4700:4700::1111",
		"external domain evil.example.com",
	}, "\n")

	redacted, mapping := r.Redact(text)

	internal := []string{
		"10.1.2.3", "192.168.5.9", "172.16.0.4", "169.254.1.1",
		"127.0.0.1", "203.0.113.77", "198.51.100.42", "fc00::1",
	}
	for _, ip := range internal {
		if strings.Contains(redacted, ip) {
			t.Errorf("internal address %s leaked into redacted payload:\n%s", ip, redacted)
		}
	}

	// Belt-and-suspenders: re-scan the redacted text for ANY token that
	// parses as an internal IP, so a future range we forget to list above
	// still fails the test.
	for _, m := range regexp.MustCompile(`\S+`).FindAllString(redacted, -1) {
		if ip := net.ParseIP(strings.Trim(m, ".,")); ip != nil && r.isInternal(ip) {
			t.Errorf("an internal address survived redaction as %q", m)
		}
	}

	// External indicators must survive — they're the point of the briefing.
	for _, keep := range []string{"8.8.8.8", "2606:4700:4700::1111", "evil.example.com"} {
		if !strings.Contains(redacted, keep) {
			t.Errorf("external indicator %s was wrongly redacted", keep)
		}
	}

	// Round-trip: expanding the model's reply restores the real addresses.
	expanded := Expand(redacted, mapping)
	for _, ip := range internal {
		if !strings.Contains(expanded, ip) {
			t.Errorf("expand did not restore internal address %s", ip)
		}
	}
}

// Same address must always map to the same token within a call, and distinct
// addresses to distinct tokens — otherwise the analyst can't tell hosts apart
// in the briefing.
func TestRedactTokensAreStableAndDistinct(t *testing.T) {
	r := NewRedactor(nil)
	redacted, mapping := r.Redact("10.0.0.1 talks to 10.0.0.2, then 10.0.0.1 again")
	if got := strings.Count(redacted, "HOST_1"); got != 2 {
		t.Errorf("repeated address should reuse one token, got HOST_1 %d times", got)
	}
	if len(mapping) != 2 {
		t.Errorf("expected 2 distinct tokens, got %d", len(mapping))
	}
	if mapping["HOST_1"] != "10.0.0.1" || mapping["HOST_2"] != "10.0.0.2" {
		t.Errorf("token assignment not in first-appearance order: %v", mapping)
	}
}

// Expand must not let HOST_1 partially clobber HOST_10.
func TestExpandHandlesOverlappingTokenNames(t *testing.T) {
	mapping := map[string]string{"HOST_1": "10.0.0.1", "HOST_10": "10.0.0.10"}
	got := Expand("see HOST_10 and HOST_1", mapping)
	if got != "see 10.0.0.10 and 10.0.0.1" {
		t.Errorf("overlapping token expansion wrong: %q", got)
	}
}
