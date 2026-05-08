// Package match provides the compiled-list matcher used by the allowlist,
// IOC list, and (Phase 7) feed-indicator union. Compiled once and reused
// across many Matches calls — what was previously rebuilt per
// /api/findings request.
//
// Match semantics: exact entries (IPs, domains, any free-form string)
// live in `exact`. CIDR entries are parsed into ipnets and matched
// against IP-shaped candidates only. Whole-line `# ...` comments are
// ignored. Empty entries are ignored. Inline `value # tail` tails are
// expected to have been stripped at store time (see
// internal/store.sanitizeListEntries) — anything reaching Compile
// without a `#` prefix is treated as a real entry.
package match

import (
	"net"
	"strings"
)

// Matcher is a compiled, immutable view of a list. Once built, never
// mutated — safe to share across goroutines without a mutex.
type Matcher struct {
	exact map[string]bool
	cidrs []*net.IPNet
}

// Compile builds a Matcher from a slice of entries. Order is irrelevant
// for matching but the input is preserved (entries are *not* mutated).
func Compile(entries []string) *Matcher {
	m := &Matcher{exact: make(map[string]bool, len(entries))}
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" || e[0] == '#' {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(e); err == nil {
			m.cidrs = append(m.cidrs, ipnet)
			continue
		}
		m.exact[e] = true
	}
	return m
}

// Matches reports whether candidate (a Src/Dst value from a finding) is
// covered by any entry. Empty candidates never match. nil receivers
// never match — convenient for the "no list configured" case.
func (m *Matcher) Matches(candidate string) bool {
	if m == nil || candidate == "" {
		return false
	}
	if m.exact[candidate] {
		return true
	}
	if len(m.cidrs) == 0 {
		return false
	}
	ip := net.ParseIP(candidate)
	if ip == nil {
		return false
	}
	for _, n := range m.cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
