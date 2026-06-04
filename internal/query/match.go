package query

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// parseIPLiteral reports whether s is a bare IP address (not a CIDR).
func parseIPLiteral(s string) bool {
	return net.ParseIP(s) != nil
}

// numericMatch evaluates a comparison or range term against a numeric value.
// A non-numeric operand yields false (the predicate matches nothing) rather
// than matching everything.
func numericMatch(v float64, t term) bool {
	if t.op == "range" {
		lo, okLo := parseNum(t.lo)
		hi, okHi := parseNum(t.hi)
		if !okLo || !okHi {
			return false
		}
		return v >= lo && v <= hi
	}
	n, ok := parseNum(t.value)
	if !ok {
		return false
	}
	switch t.op {
	case ">=":
		return v >= n
	case "<=":
		return v <= n
	case ">":
		return v > n
	case "<":
		return v < n
	case "=", "":
		return v == n
	}
	return false
}

func parseNum(s string) (float64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// ipFieldMatch matches an IP-valued field. A CIDR value tests containment, a
// bare IP tests equality, and anything else falls back to a wildcard/substring
// match against the IP string (e.g. dst:91.218.*). Comparisons/ranges are not
// meaningful on IP fields and never match.
func ipFieldMatch(ip string, t term) bool {
	if t.op != "" {
		return false
	}
	val := t.value
	// rfc1918 / private and public / external: keywords for the internal and
	// public IP spaces, so an analyst can write src:rfc1918 / src:public instead
	// of OR-ing private CIDRs or negating them. Both resolve through the same
	// isInternalIP boundary the dir: field uses (RFC1918 + IPv6 ULA + loopback +
	// link-local), so they agree on what "internal" means. public/external is
	// the strict inverse: the address must parse AND be non-internal (an
	// unparseable field is neither private nor public, unlike NOT src:rfc1918).
	switch strings.ToLower(val) {
	case "rfc1918", "private":
		internal, ok := isInternalIP(ip)
		return ok && internal
	case "public", "external":
		internal, ok := isInternalIP(ip)
		return ok && !internal
	}
	if _, ipnet, err := net.ParseCIDR(val); err == nil {
		p := net.ParseIP(ip)
		return p != nil && ipnet.Contains(p)
	}
	if net.ParseIP(val) != nil {
		return strings.EqualFold(ip, val)
	}
	return stringPatternMatch(ip, val)
}

// portMatch tests membership in a comma-separated port list.
func portMatch(port, value string) bool {
	for _, p := range strings.Split(value, ",") {
		if strings.TrimSpace(p) == port {
			return true
		}
	}
	return false
}

// stringPatternMatch does a case-insensitive substring match. When the pattern
// contains * or ? it is matched as an unanchored wildcard (implicit leading and
// trailing stars), preserving the substring semantics of these fields while
// honouring the wildcards an analyst types — dst:91.218.* finds the prefix
// anywhere, detail:period*3600 spans the gap inside the detail text.
func stringPatternMatch(s, pattern string) bool {
	if strings.ContainsAny(pattern, "*?") {
		return globFold("*"+pattern+"*", s)
	}
	return strings.Contains(strings.ToLower(s), strings.ToLower(pattern))
}

// globFold matches s against a shell-style wildcard pattern (* and ?),
// case-insensitively, with linear-time star backtracking.
func globFold(pattern, s string) bool {
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

func boolMatch(actual bool, value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return actual
	case "false":
		return !actual
	}
	return false
}

// tsMatch matches a finding timestamp string against a date or [from TO to]
// range. The finding timestamp is read as UTC; query date literals are
// interpreted in the operator timezone (opLoc).
func tsMatch(tsStr string, t term, opLoc *time.Location) bool {
	ft, _, ok := parseTimeFlexible(tsStr, time.UTC)
	if !ok {
		return false
	}
	return tsMatchTime(ft, t, opLoc)
}

// tsMatchTime is the time-domain core shared by tsMatch (string Timestamp) and
// the detected: field (epoch DetectedAt). ft is the finding instant in UTC;
// query date literals are interpreted in opLoc.
func tsMatchTime(ft time.Time, t term, opLoc *time.Location) bool {
	if t.op == "range" {
		from, _, okF := parseTimeFlexible(t.lo, opLoc)
		hi, hiDateOnly, okT := parseTimeFlexible(t.hi, opLoc)
		if !okF || !okT {
			return false
		}
		upperExcl := hi
		if hiDateOnly {
			upperExcl = hi.AddDate(0, 0, 1)
		}
		return !ft.Before(from) && ft.Before(upperExcl)
	}
	v, dateOnly, ok := parseTimeFlexible(t.value, opLoc)
	if !ok {
		return false
	}
	// For a date-only literal a comparison is interpreted against the whole
	// day: the lower edge (start of day) for >= and <, the upper edge (start
	// of next day) for > and <=. A datetime literal compares to the instant.
	dayStart := v
	dayEnd := v.AddDate(0, 0, 1)
	switch t.op {
	case ">=":
		return !ft.Before(dayStart)
	case ">":
		if dateOnly {
			return !ft.Before(dayEnd)
		}
		return ft.After(v)
	case "<=":
		if dateOnly {
			return ft.Before(dayEnd)
		}
		return !ft.After(v)
	case "<":
		return ft.Before(dayStart)
	}
	// Bare date or "=": whole-day window for a date, exact instant otherwise.
	if dateOnly {
		return !ft.Before(dayStart) && ft.Before(dayEnd)
	}
	return ft.Equal(v)
}

// isInternalIP reports whether s is an internal (private) address and whether
// it parsed at all. "Internal" is RFC1918 / IPv6 ULA (net.IP.IsPrivate) plus
// loopback and link-local — the address space that never appears as a routable
// external peer. The second return distinguishes "parsed, external" from
// "couldn't parse" so dirMatch can refuse to classify a pair it can't place.
func isInternalIP(s string) (internal bool, ok bool) {
	ip := net.ParseIP(s)
	if ip == nil {
		return false, false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast(), true
}

// dirMatch classifies a finding's (src, dst) pair by direction relative to the
// internal/external boundary and tests it against an enumerated value:
// outbound (internal→external), inbound (external→internal), internal/lateral
// (both internal), external (both external). A pair with an unparseable
// endpoint can't be placed and matches nothing.
func dirMatch(src, dst, value string) bool {
	si, okS := isInternalIP(src)
	di, okD := isInternalIP(dst)
	if !okS || !okD {
		return false
	}
	switch strings.ToLower(value) {
	case "outbound":
		return si && !di
	case "inbound":
		return !si && di
	case "internal", "lateral":
		return si && di
	case "external":
		return !si && !di
	}
	return false
}

// parseTimeFlexible parses a date or datetime in loc, reporting whether the
// input was date-only (so callers can treat it as a whole-day window).
func parseTimeFlexible(s string, loc *time.Location) (time.Time, bool, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339} {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t, false, true
		}
	}
	if t, err := time.ParseInLocation("2006-01-02", s, loc); err == nil {
		return t, true, true
	}
	return time.Time{}, false, false
}
