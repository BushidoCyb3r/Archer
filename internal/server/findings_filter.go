package server

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// Matcher invalidation: SetAllowlist / SetIOCList rebuild the
// allowlist and operator-IOC matchers; UpsertFeedIndicators /
// RemoveStaleIndicators / DeleteFeed invalidate the per-feed
// matchers (lazy-rebuilt on next read). This filter reads
// AllowlistMatcher() and IOCSources() — no per-request compile.

// filterFindings applies every query-string filter supported by the UI to
// `findings` and returns the subset that match, with IOCMatch populated.
//
// Supported query parameters:
//
//	search      — case-insensitive substring across type/src/dst/port/detail/ts/severity
//	type        — exact finding type ("All" or "" disables)
//	severity    — exact severity  ("All" or "" disables)
//	min_score   — minimum score (integer)
//	delta       — "true" restricts to IsNew findings
//	src_ip      — IP or CIDR; matches finding.SrcIP
//	dst_ip      — IP or CIDR; matches finding.DstIP
//	sensor      — exact sensor match
//	from, to    — inclusive Timestamp window; either "2006-01-02 15:04:05" or RFC3339
//
// Allowlisted and currently-suppressed findings are always excluded —
// filtering doesn't undo those admin decisions. Shared between the findings
// listing endpoint and the export endpoints so the exported CSV/JSON matches
// exactly what the analyst sees on screen.
func (s *Server) filterFindings(findings []model.Finding, q url.Values) []model.Finding {
	search := strings.ToLower(strings.TrimSpace(q.Get("search")))
	// When the search box holds a complete IP, fall back to exact-match against
	// the Src/Dst fields. Otherwise typing "10.18.61.3" would substring-match
	// "10.18.61.37" and similar prefix collisions. CIDR/range searches use the
	// dedicated Src IP/CIDR and Dst IP/CIDR filters in the advanced bar.
	searchIsIP := search != "" && net.ParseIP(search) != nil
	typeF := q.Get("type")
	sevF := q.Get("severity")
	minScore, _ := strconv.Atoi(q.Get("min_score"))
	delta := q.Get("delta") == "true"
	sensorF := q.Get("sensor")
	statusF := q.Get("status") // "open" | "acknowledged" | "escalated"
	iocOnly := q.Get("ioc_only") == "true"

	srcMatcher := parseIPMatcher(q.Get("src_ip"))
	dstMatcher := parseIPMatcher(q.Get("dst_ip"))
	portSet := parsePortSet(q.Get("dst_port"))

	var from, to time.Time
	var haveFrom, haveTo bool
	if s := q.Get("from"); s != "" {
		if t, ok := parseFindingTime(s); ok {
			from, haveFrom = t, true
		}
	}
	if s := q.Get("to"); s != "" {
		if t, ok := parseFindingTime(s); ok {
			to, haveTo = t, true
		}
	}

	alM := s.store.AllowlistMatcher()
	// IOC sources: operator-curated list first, then each enabled feed.
	// Built once per /api/findings call; per-finding iteration short-
	// circuits on the first hit and tags the finding with the matching
	// source. A typical install has 0-3 feeds + 1 operator list, so
	// the inner loop is bounded.
	iocSources := s.store.IOCSources()

	result := make([]model.Finding, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		if typeF != "" && typeF != "All" && f.Type != typeF {
			continue
		}
		if sevF != "" && sevF != "All" && string(f.Severity) != sevF {
			continue
		}
		if f.Score < minScore {
			continue
		}
		if alM.Matches(f.SrcIP) || alM.Matches(f.DstIP) {
			continue
		}
		if s.store.IsSuppressed(f.SrcIP) || s.store.IsSuppressed(f.DstIP) {
			continue
		}
		if delta && !f.IsNew {
			continue
		}
		if sensorF != "" && f.Sensor != sensorF {
			continue
		}
		if srcMatcher != nil && !srcMatcher(f.SrcIP) {
			continue
		}
		if dstMatcher != nil && !dstMatcher(f.DstIP) {
			continue
		}
		if portSet != nil && !portSet[f.DstPort] {
			continue
		}
		if haveFrom || haveTo {
			ft, ok := parseFindingTime(f.Timestamp)
			// Findings without a parseable timestamp are excluded when a time
			// window is specified — they can't be placed.
			if !ok {
				continue
			}
			if haveFrom && ft.Before(from) {
				continue
			}
			if haveTo && ft.After(to) {
				continue
			}
		}
		if search != "" {
			if searchIsIP {
				if !strings.EqualFold(f.SrcIP, search) && !strings.EqualFold(f.DstIP, search) {
					continue
				}
			} else {
				hay := strings.ToLower(f.Type + " " + f.SrcIP + " " + f.DstIP + " " +
					f.DstPort + " " + f.Detail + " " + f.Timestamp + " " + string(f.Severity))
				if !strings.Contains(hay, search) {
					continue
				}
			}
		}
		// Tab-aware filters. status="open" matches blank/empty status;
		// status="acknowledged" / "escalated" match exactly. ioc_only mirrors
		// the IOC Hits tab logic — IP in IOC list OR finding type is a
		// Threat Intel Hit / Suspicious URL.
		if statusF != "" {
			if statusF == "open" {
				if string(f.Status) != "" {
					continue
				}
			} else if string(f.Status) != statusF {
				continue
			}
		}
		// TI Hit (IP/Domain/Hash) and Suspicious URL are produced by the
		// automatic feeds (Feodo, URLhaus, AbuseIPDB, MISP/OpenCTI) and
		// are IOC matches by definition — flag them so the per-row status
		// icon shows the IOC diamond rather than the generic "new finding"
		// indicator. The legacy unified "Threat Intel Hit" string is also
		// recognized so pre-v0.7.0 findings still classify correctly.
		isTI := model.IsThreatIntelType(f.Type)
		ioMatch := false
		ioSource := ""
		for _, sm := range iocSources {
			if sm.Matcher.Matches(f.DstIP) || sm.Matcher.Matches(f.SrcIP) {
				ioMatch = true
				ioSource = sm.Source
				break
			}
		}
		if isTI {
			ioMatch = true
			if ioSource == "" {
				ioSource = "Threat Intel"
			}
		}
		if iocOnly && !ioMatch {
			continue
		}
		f.IOCMatch = ioMatch
		f.IOCSource = ioSource
		result = append(result, *f)
	}
	return result
}

// parsePortSet accepts a single port ("443") or a comma-separated list
// ("80,443,8080"). Returns a set keyed by the canonical port string, or
// nil when the input is empty / parses to nothing usable. Non-numeric
// tokens are silently skipped so a stray comma can't blank the filter.
func parsePortSet(s string) map[string]bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	out := map[string]bool{}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if n, err := strconv.Atoi(tok); err == nil && n >= 0 && n <= 65535 {
			out[strconv.Itoa(n)] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseIPMatcher accepts an IP, a CIDR, or the empty string. Returns a
// matcher function (nil when the input is empty or unparseable).
func parseIPMatcher(s string) func(string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return func(candidate string) bool {
			ip := net.ParseIP(candidate)
			return ip != nil && ipnet.Contains(ip)
		}
	}
	if ip := net.ParseIP(s); ip != nil {
		target := ip.String()
		return func(candidate string) bool {
			ci := net.ParseIP(candidate)
			return ci != nil && ci.String() == target
		}
	}
	// Last-ditch: substring match on the raw string (covers hostnames the
	// analyzer may have stashed in SrcIP / DstIP for unresolved records).
	lower := strings.ToLower(s)
	return func(candidate string) bool {
		return strings.Contains(strings.ToLower(candidate), lower)
	}
}

// parseFindingTime handles both the analyzer's "2006-01-02 15:04:05" UTC
// format and RFC3339 inputs the UI might send from a datetime picker.
func parseFindingTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	// HTML datetime-local inputs produce "2006-01-02T15:04" with no seconds.
	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		time.RFC3339,
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
