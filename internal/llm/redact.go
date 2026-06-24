package llm

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// Redactor tokenizes internal IP addresses out of the evidence before it is
// sent to a provider, and expands the tokens back in the returned briefing so
// the analyst still reads real addresses.
//
// Scope is deliberate: only internal IPs (RFC1918, IPv4 link-local, IPv6 ULA
// and link-local, plus any operator-configured org-internal CIDRs) are
// tokenized. The external indicators in a finding — the C2 destination IPs and
// domains — are NOT redacted: they are the point of the briefing, and they
// already leave the box on the TI-enrichment path. The result is that a cloud
// provider sees the threat indicators but never the internal victim topology.
//
// Hostname redaction is intentionally out of scope: an internal hostname can't
// be classified deterministically without a resolver, and the hostnames that
// appear in these findings (beacon SNI / Host headers) are the external
// indicators we want to send.
type Redactor struct {
	nets []*net.IPNet
}

// internalCIDRs are the always-on private/local ranges, independent of any
// operator configuration.
var internalCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16", // IPv4 link-local
	"127.0.0.0/8",    // loopback
	"fc00::/7",       // IPv6 unique-local
	"fe80::/10",      // IPv6 link-local
	"::1/128",        // IPv6 loopback
}

// ipPattern matches IPv4 and IPv6-shaped candidates. Each candidate is
// validated with net.ParseIP before it is treated as an address, so the loose
// pattern (which can match version strings or hex blobs) never causes a
// non-address to be redacted.
var ipPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b`)

// NewRedactor builds a Redactor covering the built-in private ranges plus any
// extra org-internal CIDRs (single IPs accepted as /32 or /128). Unparseable
// entries are skipped — they are surfaced at config-validation time, not here.
func NewRedactor(orgCIDRs []string) *Redactor {
	r := &Redactor{}
	for _, c := range internalCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			r.nets = append(r.nets, n)
		}
	}
	for _, c := range orgCIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			r.nets = append(r.nets, n)
			continue
		}
		if ip := net.ParseIP(c); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			r.nets = append(r.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return r
}

// isInternal reports whether ip falls in any internal range.
func (r *Redactor) isInternal(ip net.IP) bool {
	for _, n := range r.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Redact replaces every internal IP in text with a stable HOST_n token and
// returns the redacted text plus a token→address map for Expand. Tokens are
// assigned in first-appearance order and deduplicated, so the same address
// always maps to the same token within one call.
func (r *Redactor) Redact(text string) (string, map[string]string) {
	realToToken := map[string]string{}
	tokenToReal := map[string]string{}
	next := 0
	redacted := ipPattern.ReplaceAllStringFunc(text, func(m string) string {
		ip := net.ParseIP(m)
		if ip == nil || !r.isInternal(ip) {
			return m
		}
		if tok, ok := realToToken[m]; ok {
			return tok
		}
		next++
		tok := fmt.Sprintf("HOST_%d", next)
		realToToken[m] = tok
		tokenToReal[tok] = m
		return tok
	})
	return redacted, tokenToReal
}

// Expand restores HOST_n tokens to their real addresses. Longer token names
// are substituted first so HOST_10 is not partially rewritten by HOST_1.
func Expand(text string, mapping map[string]string) string {
	tokens := make([]string, 0, len(mapping))
	for tok := range mapping {
		tokens = append(tokens, tok)
	}
	sort.Slice(tokens, func(i, j int) bool { return len(tokens[i]) > len(tokens[j]) })
	for _, tok := range tokens {
		text = strings.ReplaceAll(text, tok, mapping[tok])
	}
	return text
}
