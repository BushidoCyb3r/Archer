package server

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

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
//	dataset     — exact dataset match
//	from, to    — inclusive Timestamp window; either "2006-01-02 15:04:05" or RFC3339
//
// Allowlisted and currently-suppressed findings are always excluded —
// filtering doesn't undo those admin decisions. Shared between the findings
// listing endpoint and the export endpoints so the exported CSV/JSON matches
// exactly what the analyst sees on screen.
func (s *Server) filterFindings(findings []model.Finding, q url.Values) []model.Finding {
	search := strings.ToLower(q.Get("search"))
	typeF := q.Get("type")
	sevF := q.Get("severity")
	minScore, _ := strconv.Atoi(q.Get("min_score"))
	delta := q.Get("delta") == "true"
	datasetF := q.Get("dataset")
	statusF := q.Get("status")     // "open" | "acknowledged" | "escalated"
	iocOnly := q.Get("ioc_only") == "true"

	srcMatcher := parseIPMatcher(q.Get("src_ip"))
	dstMatcher := parseIPMatcher(q.Get("dst_ip"))

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

	allowlist := s.store.GetAllowlist()
	alSet := make(map[string]bool, len(allowlist))
	for _, e := range allowlist {
		alSet[e] = true
	}
	iocList := s.store.GetIOCList()
	iocSet := make(map[string]bool, len(iocList))
	for _, e := range iocList {
		iocSet[e] = true
	}

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
		if alSet[f.DstIP] || alSet[f.SrcIP] {
			continue
		}
		if s.store.IsSuppressed(f.SrcIP) || s.store.IsSuppressed(f.DstIP) {
			continue
		}
		if delta && !f.IsNew {
			continue
		}
		if datasetF != "" && f.Dataset != datasetF {
			continue
		}
		if srcMatcher != nil && !srcMatcher(f.SrcIP) {
			continue
		}
		if dstMatcher != nil && !dstMatcher(f.DstIP) {
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
			hay := strings.ToLower(f.Type + " " + f.SrcIP + " " + f.DstIP + " " +
				f.DstPort + " " + f.Detail + " " + f.Timestamp + " " + string(f.Severity))
			if !strings.Contains(hay, search) {
				continue
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
		ioMatch := iocSet[f.DstIP] || iocSet[f.SrcIP]
		if iocOnly {
			isTI := f.Type == "Threat Intel Hit" || f.Type == "Suspicious URL"
			if !ioMatch && !isTI {
				continue
			}
		}
		f.IOCMatch = ioMatch
		result = append(result, *f)
	}
	return result
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
