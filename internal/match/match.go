// Package match provides the compiled-list matcher used by the allowlist,
// IOC list, and (Phase 7) feed-indicator union. Compiled once and reused
// across many Matches calls — what was previously rebuilt per
// /api/findings request.
//
// Match semantics — three tiers, checked in order:
//   - exact: IPs (canonicalized), domains, any free-form literal.
//   - globs: entries containing `*` / `?` wildcards, matched anchored
//     (whole-candidate) and case-insensitively — e.g. `*.in-addr.arpa`,
//     `185.220.*`, `*.internal.corp`. Operator-entered only; feed
//     indicators are always literal, so a feed matcher's glob tier is
//     empty and adds zero per-candidate cost (keeps the 1M-indicator
//     feed path fast).
//   - cidrs: parsed ipnets, matched against IP-shaped candidates only.
//
// CIDR is tried before the wildcard check, so `10.0.0.0/8` stays a CIDR
// match and only non-CIDR entries with `*`/`?` become globs. Whole-line
// `# ...` comments and empty entries are ignored. Inline `value # tail`
// tails are expected to have been stripped at store time (see
// internal/store.sanitizeListEntries).
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
	globs []string
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
		if strings.ContainsAny(e, "*?") {
			m.globs = append(m.globs, e)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			e = ip.String()
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
	key := candidate
	if ip := net.ParseIP(candidate); ip != nil {
		key = ip.String()
	}
	if m.exact[key] {
		return true
	}
	for _, g := range m.globs {
		if globMatch(g, candidate) {
			return true
		}
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

// globMatch reports whether s matches the wildcard pattern (anchored,
// whole-string, case-insensitive). `*` matches any run of characters,
// `?` exactly one. Linear-time backtracking — fine for the handful of
// operator wildcard entries a list carries.
func globMatch(pattern, s string) bool {
	p := []rune(strings.ToLower(pattern))
	str := []rune(strings.ToLower(s))
	ip, is := 0, 0
	star, match := -1, 0
	for is < len(str) {
		if ip < len(p) && (p[ip] == '?' || p[ip] == str[is]) {
			ip++
			is++
			continue
		}
		if ip < len(p) && p[ip] == '*' {
			star = ip
			match = is
			ip++
			continue
		}
		if star != -1 {
			ip = star + 1
			match++
			is = match
			continue
		}
		return false
	}
	for ip < len(p) && p[ip] == '*' {
		ip++
	}
	return ip == len(p)
}
