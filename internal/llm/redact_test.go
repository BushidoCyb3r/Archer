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
	r := NewRedactor([]string{"203.0.113.0/24", "198.51.100.42"}, nil)
	text := strings.Join([]string{
		"src 10.1.2.3 beaconing to 8.8.8.8",
		"lateral 192.168.5.9 -> 172.16.0.4",
		"link-local 169.254.1.1 loopback 127.0.0.1",
		"org host 203.0.113.77 and single 198.51.100.42",
		"ipv6 ula fc00::1 and global 2606:4700:4700::1111",
		"ipv6 loopback ::1 leading double-colon",
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
	// "::1" can't be checked with Contains — it's a substring of the surviving
	// external "...::1111" — so confirm via the mapping that it was tokenized.
	// This is the regression for the leading-"::" regex fix.
	loopbackTokenized := false
	for _, v := range mapping {
		if v == "::1" {
			loopbackTokenized = true
		}
	}
	if !loopbackTokenized {
		t.Errorf("IPv6 loopback ::1 was not tokenized (leading-:: regex regression):\n%s", redacted)
	}
	internal = append(internal, "::1")

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

// Internal hostnames under a configured org-internal domain suffix are
// tokenized; external names — including an external lookalike that merely
// contains the suffix mid-name — survive, since they are the indicators the
// briefing exists to send. Whole-token matching is what prevents the lookalike
// from being partially rewritten.
func TestRedactInternalHostnames(t *testing.T) {
	r := NewRedactor(nil, []string{"corp.example.com", ".lab.internal"})
	text := strings.Join([]string{
		"workstation wks01.corp.example.com beaconing",
		"apex corp.example.com and deep a.b.lab.internal",
		"external c2 evil.example.com and lookalike corp.example.com.attacker.net",
		"plain google.com and bare-label DC01",
	}, "\n")

	redacted, mapping := r.Redact(text)

	// The internal names were tokenized (assert via the mapping, since the apex
	// "corp.example.com" also appears as a substring of the surviving lookalike).
	tokenized := map[string]bool{}
	for _, v := range mapping {
		tokenized[v] = true
	}
	for _, internal := range []string{"wks01.corp.example.com", "corp.example.com", "a.b.lab.internal"} {
		if !tokenized[internal] {
			t.Errorf("internal hostname %q was not tokenized; mapping=%v", internal, mapping)
		}
	}
	// External / benign names survive verbatim, and none was tokenized.
	for _, keep := range []string{"evil.example.com", "corp.example.com.attacker.net", "google.com", "DC01"} {
		if !strings.Contains(redacted, keep) {
			t.Errorf("external/benign token %q was wrongly redacted:\n%s", keep, redacted)
		}
		if tokenized[keep] {
			t.Errorf("external/benign token %q was wrongly tokenized", keep)
		}
	}
	// Round-trip restores the real internal names.
	expanded := Expand(redacted, mapping)
	for _, name := range []string{"wks01.corp.example.com", "a.b.lab.internal"} {
		if !strings.Contains(expanded, name) {
			t.Errorf("expand did not restore internal hostname %s", name)
		}
	}
	// With no domains configured, hostnames are left entirely alone.
	plain, _ := NewRedactor(nil, nil).Redact("wks01.corp.example.com talks out")
	if !strings.Contains(plain, "wks01.corp.example.com") {
		t.Errorf("hostname redacted with no internal domains configured: %q", plain)
	}
}

// Same address must always map to the same token within a call, and distinct
// addresses to distinct tokens — otherwise the analyst can't tell hosts apart
// in the briefing.
func TestRedactTokensAreStableAndDistinct(t *testing.T) {
	r := NewRedactor(nil, nil)
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
