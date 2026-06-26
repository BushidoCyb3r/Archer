package llm

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// Redactor tokenizes internal identifiers out of the evidence before it is
// sent to a provider, and expands the tokens back in the returned briefing so
// the analyst still reads the real values.
//
// Scope is deliberate: internal IPs (RFC1918, IPv4 link-local, IPv6 ULA and
// link-local, plus any operator-configured org-internal CIDRs) and internal
// hostnames (any name under an operator-configured internal domain suffix) are
// tokenized. The external indicators in a finding — the C2 destination IPs and
// domains — are NOT redacted: they are the point of the briefing, and they
// already leave the box on the TI-enrichment path. The result is that a cloud
// provider sees the threat indicators but never the internal victim topology.
//
// Hostname redaction is suffix-driven, not resolver-driven: a bare single-label
// name (e.g. "DC01") can't be classified deterministically and is left alone,
// and an external lookalike (a subdomain of a configured internal domain that
// trails off into another domain) is matched on the whole token so it is never
// partially rewritten. Free-text the operator's analysts type into notes can
// still carry internal context the suffix list doesn't cover — that residue is
// why the local/enclave providers exist and is documented in docs/AI_TRIAGE.md.
type Redactor struct {
	nets    []*net.IPNet
	domains []string // lowercased internal domain suffixes, no leading dot
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
// non-address to be redacted. The IPv6 alternative carries no leading \b so
// that leading-"::" forms (e.g. ::1, ::ffff:10.0.0.1) are caught — \b cannot
// anchor before a colon, and ParseIP rejects any over-match anyway.
var ipPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}`)

// hostPattern matches dotted DNS-name tokens (at least two labels). The whole
// token is matched so the internal-suffix check in isInternalHost runs against
// the complete name, never a substring of a longer external name.
var hostPattern = regexp.MustCompile(`(?i)\b(?:[a-z0-9_-]+\.)+[a-z0-9_-]+\b`)

// NewRedactor builds a Redactor covering the built-in private ranges plus any
// extra org-internal CIDRs (single IPs accepted as /32 or /128) and any
// org-internal domain suffixes. Unparseable entries are skipped — they are
// surfaced at config-validation time, not here.
func NewRedactor(orgCIDRs, orgDomains []string) *Redactor {
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
	for _, d := range orgDomains {
		d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
		if d != "" {
			r.domains = append(r.domains, d)
		}
	}
	return r
}

// isInternalHost reports whether name is, or is a subdomain of, any configured
// internal domain suffix (case-insensitive, on a label boundary).
func (r *Redactor) isInternalHost(name string) bool {
	n := strings.ToLower(strings.TrimRight(name, "."))
	for _, d := range r.domains {
		if n == d || strings.HasSuffix(n, "."+d) {
			return true
		}
	}
	return false
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

// Redact replaces every internal IP and internal hostname in text with a stable
// HOST_n token and returns the redacted text plus a token→value map for Expand.
// Tokens are assigned in first-appearance order and deduplicated across both
// passes, so the same value always maps to the same token within one call. The
// IP pass runs first; the hostname pass only runs when internal domains are
// configured (default: no hostname redaction, no behavior change).
func (r *Redactor) Redact(text string) (string, map[string]string) {
	realToToken := map[string]string{}
	tokenToReal := map[string]string{}
	next := 0
	assign := func(real string) string {
		if tok, ok := realToToken[real]; ok {
			return tok
		}
		next++
		tok := fmt.Sprintf("HOST_%d", next)
		realToToken[real] = tok
		tokenToReal[tok] = real
		return tok
	}
	text = ipPattern.ReplaceAllStringFunc(text, func(m string) string {
		ip := net.ParseIP(m)
		if ip == nil || !r.isInternal(ip) {
			return m
		}
		return assign(m)
	})
	if len(r.domains) > 0 {
		text = hostPattern.ReplaceAllStringFunc(text, func(m string) string {
			if !r.isInternalHost(m) {
				return m
			}
			return assign(m)
		})
	}
	return text, tokenToReal
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
