package server

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/query"
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
//	search        — case-insensitive substring across type/src/dst/port/detail/ts/severity
//	type          — exact finding type ("All" or "" disables); the
//	                pseudo-value "beacons" matches the whole beacon
//	                family (model.IsBeaconType) — used by the beacon
//	                export target and the all-beacons Findings filter
//	severity      — exact severity  ("All" or "" disables)
//	min_score     — minimum score (integer)
//	delta         — "true" restricts to IsNew findings
//	src_ip        — IP or CIDR; matches finding.SrcIP
//	dst_ip        — IP or CIDR; matches finding.DstIP
//	sensor        — exact sensor match
//	from, to      — inclusive Timestamp window; either "2006-01-02 15:04:05" or RFC3339
//	spectral_only — "true" restricts to findings carrying a spectral signal
//	                (SpectralRescued flag set). Spectral is annotation-only:
//	                it flags possible jittered periodicity for analyst review
//	                but does not affect the score.
//	ts_min/ts_max, ds_min/ds_max, hist_min/hist_max, dur_min/dur_max
//	              — inclusive [min,max] bounds on the four beacon sub-scores
//	                (each axis is 0–1; either bound may be omitted). Setting
//	                ANY of these implicitly scopes the result to beacon
//	                findings (model.IsBeaconType) — a bare "dur_max=0.3"
//	                would otherwise surface every non-beacon, whose dur_score
//	                is a structural 0 ≤ 0.3, which is never the intent. A
//	                non-numeric bound disables that one axis rather than
//	                blanking the filter.
//	ja3           — exact JA3 client-fingerprint match (case-insensitive;
//	                JA3 is stored lowercased at emit). Powers the detail-
//	                pane "matched N other beacons" pivot — clicking the
//	                JA3 line filters to every finding carrying that
//	                fingerprint.
//	ja4           — exact JA4 client-fingerprint match (case-insensitive;
//	                stored lowercased at emit). Available when sensors
//	                run the Zeek JA4+ plugin. Powers the TLS Pivot action
//	                for JA4-capable sensors.
//
// Allowlisted and currently-suppressed findings are always excluded —
// filtering doesn't undo those admin decisions. Shared between the findings
// listing endpoint and the export endpoints so the exported CSV/JSON matches
// exactly what the analyst sees on screen.
// deltaSince is the "New only" cutoff: when delta=true a finding is kept only
// if it was first detected (detected_at) after deltaSince — the requesting
// analyst's session new-findings boundary (their previous login time). This
// is the same boundary the new-findings modal counts against, so the button
// and the modal agree. Callers pass newBoundaryFromCtx(r); a zero deltaSince
// keeps every finding with a detected_at set (the no-session fallback).
func (s *Server) filterFindings(findings []model.Finding, q url.Values, deltaSince int64) ([]model.Finding, error) {
	// `q` is the Lucene-style query language — the primary filter surface. When
	// present it is ANDed on top of the view scoping and always-on exclusions
	// below. A parse error is returned to the caller so the handler can surface
	// it; it must never read as match-all or match-nothing.
	var lucene *query.Query
	if raw := strings.TrimSpace(q.Get("q")); raw != "" {
		parsed, err := query.Parse(raw)
		if err != nil {
			return nil, err
		}
		lucene = parsed
	}
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
	statusF := q.Get("status") // "open" | "acknowledged" | "escalated" | "dismissed"
	iocOnly := q.Get("ioc_only") == "true"
	spectralOnly := q.Get("spectral_only") == "true"
	// includeDismissed lets internal callers (handleFindingsCounts)
	// keep dismissed findings in the filter result so they can be
	// bucketed separately. User-facing tabs default to excluding
	// dismissed (the "I don't want to see this again" semantic):
	// when statusF is empty AND includeDismissed is false, dismissed
	// findings are filtered out below. Only the Dismissed tab
	// (status=dismissed) and the counts endpoint
	// (include_dismissed=true) bypass that.
	includeDismissed := q.Get("include_dismissed") == "true"

	srcMatcher := parseIPMatcher(q.Get("src_ip"))
	dstMatcher := parseIPMatcher(q.Get("dst_ip"))
	portSet := parsePortSet(q.Get("dst_port"))

	// Beacon sub-score range filters. Sub-scores are only meaningful for
	// beacon findings (zero on every other type and on pre-0018 legacy
	// beacon rows); when any bound is set the filter implicitly scopes to
	// beacon types so a bare upper bound can't surface non-beacons whose
	// sub-scores are a structural zero.
	ssTS := parseScoreRange(q.Get("ts_min"), q.Get("ts_max"))
	ssDS := parseScoreRange(q.Get("ds_min"), q.Get("ds_max"))
	ssHist := parseScoreRange(q.Get("hist_min"), q.Get("hist_max"))
	ssDur := parseScoreRange(q.Get("dur_min"), q.Get("dur_max"))
	anySubScore := ssTS != nil || ssDS != nil || ssHist != nil || ssDur != nil
	// JA3/JA4 are stored lowercased at emit (strings.ToLower in analyzeSSL);
	// lowercase query values so a pasted upper/mixed-case fingerprint matches.
	ja3F := strings.ToLower(strings.TrimSpace(q.Get("ja3")))
	ja4F := strings.ToLower(strings.TrimSpace(q.Get("ja4")))

	// User-supplied datetime-local strings are parsed in the operator's
	// configured timezone; the analyzer's own Timestamp field stays UTC.
	opLoc := s.operatorLocation()
	var from, to time.Time
	var haveFrom, haveTo bool
	if str := q.Get("from"); str != "" {
		if t, ok := parseFindingTime(str, opLoc); ok {
			from, haveFrom = t, true
		}
	}
	if str := q.Get("to"); str != "" {
		if t, ok := parseFindingTime(str, opLoc); ok {
			to, haveTo = t, true
		}
	}

	alM := s.store.AllowlistMatcher()
	// Benign-fingerprint snapshot, frozen once here (not re-locked per finding)
	// so the `benign:` query field can be evaluated without lock churn.
	fpBenign := s.store.FingerprintAllowSnapshot()
	// IOC sources: operator-curated list first, then each enabled feed.
	// Built once per /api/findings call; per-finding iteration short-
	// circuits on the first hit and tags the finding with the matching
	// source. A typical install has 0-3 feeds + 1 operator list, so
	// the inner loop is bounded.
	iocSources := s.store.IOCSources()
	// Suppression + pair-allow state frozen once here rather than three
	// lock acquisitions per finding inside the loop below.
	hidden := s.store.NewFilterSnapshot()

	result := make([]model.Finding, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		if typeF == "beacons" {
			// Pseudo-type: the beacon family (Beacon / HTTP Beacon /
			// DNS Beacon / Port-Hopping Beacon) as one selector. Powers "export just the
			// beacons" and an all-beacons Findings filter without three
			// separate passes.
			if !model.IsBeaconType(f.Type) {
				continue
			}
		} else if typeF != "" && typeF != "All" && f.Type != typeF {
			continue
		}
		if sevF != "" && sevF != "All" && string(f.Severity) != sevF {
			continue
		}
		if f.Score < minScore {
			continue
		}
		if anySubScore {
			if !model.IsBeaconType(f.Type) {
				continue
			}
			if ssTS != nil && !ssTS(f.TSScore) {
				continue
			}
			if ssDS != nil && !ssDS(f.DSScore) {
				continue
			}
			if ssHist != nil && !ssHist(f.HistScore) {
				continue
			}
			if ssDur != nil && !ssDur(f.DurScore) {
				continue
			}
		}
		if ja3F != "" && f.JA3 != ja3F {
			continue
		}
		if ja4F != "" && f.JA4 != ja4F {
			continue
		}
		if alM.Matches(f.SrcIP) || alM.Matches(f.DstIP) {
			continue
		}
		if hidden.IsSuppressed(f.SrcIP) || hidden.IsSuppressed(f.DstIP) {
			continue
		}
		if hidden.IsPairAllowed(f.SrcIP, f.DstIP, f.DstPort, f.Type, f.Sensor) {
			continue
		}
		if delta && f.DetectedAt <= deltaSince {
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
			// Finding.Timestamp is the analyzer's UTC emit format.
			ft, ok := parseFindingTime(f.Timestamp, time.UTC)
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
		// status="acknowledged" / "escalated" / "dismissed" match exactly.
		// ioc_only mirrors the IOC Hits tab logic — IP in IOC list OR
		// finding type is a Threat Intel Hit / Suspicious URL.
		if statusF != "" {
			if statusF == "open" {
				if string(f.Status) != "" {
					continue
				}
			} else if string(f.Status) != statusF {
				continue
			}
		} else if !includeDismissed && f.Status == model.StatusDismissed {
			// No explicit status filter and the caller hasn't opted
			// into the counts-style include_dismissed flag → dismissed
			// findings are invisible. Keeps the IOC tab (which sets
			// ioc_only without a status) from accidentally surfacing
			// dismissed rows.
			continue
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
		// Spectral filter: matches the structured SpectralRescued flag set
		// at emit time, not a Detail substring (which the flag tracks but
		// which can change wording). Spectral is annotation-only, so this
		// selects findings carrying a spectral signal, not score-boosted ones.
		if spectralOnly && !f.SpectralRescued {
			continue
		}
		f.IOCMatch = ioMatch
		f.IOCSource = ioSource
		// Lucene query last: it sees the fully-populated finding (incl. the
		// IOCMatch just computed, which the ioc: field reads, and the benign
		// stamp the channel/benign fields read). Stamped on the local copy in
		// the (request-private) findings slice; never written back to the store.
		if lucene != nil {
			f.TLSAllowlisted = fpBenign("ja4", f.JA4) || fpBenign("ja3", f.JA3)
			if !lucene.Match(*f, opLoc) {
				continue
			}
		}
		result = append(result, *f)
	}
	return result, nil
}

// parseScoreRange builds an inclusive [min,max] predicate over a beacon
// sub-score (each sub-score is in [0,1]). Either bound may be omitted.
// Returns nil when neither bound parses as a float, so the caller skips
// that axis entirely — a stray non-numeric value disables one axis
// rather than filtering everything out (same defensive shape as
// parsePortSet / parseIPMatcher).
func parseScoreRange(minS, maxS string) func(float64) bool {
	lo, okLo := parseFloatBound(minS)
	hi, okHi := parseFloatBound(maxS)
	if !okLo && !okHi {
		return nil
	}
	return func(v float64) bool {
		if okLo && v < lo {
			return false
		}
		if okHi && v > hi {
			return false
		}
		return true
	}
}

func parseFloatBound(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return f, true
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

// parseIPMatcher accepts an IP, a CIDR, a hostname pattern, or the
// empty string. Returns a matcher function (nil when the input is
// empty or doesn't plausibly represent a host).
//
// The substring fallback covers hostnames the analyzer may have
// stashed in SrcIP / DstIP for unresolved records, but is gated on
// "looks like a hostname" — at least one ASCII letter present, OR a
// dot inside a non-numeric token. Pre-fix the fallback fired on any
// input: typing "1" in the Src IP filter substring-matched every
// finding whose IP contained a 1 (most of the dataset); typing "19"
// while building "192.168.x.x" did the same. Audit 2026-05-10
// NEW-5. The new gate refuses purely-numeric inputs that aren't
// valid IPs/CIDRs — a typo in the middle of typing an IP now
// returns nil (no filter applied) rather than matching everything.
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
	// Hostname-shaped fallback: must contain at least one ASCII
	// letter, otherwise refuse rather than substring-matching every
	// finding. Hyphen/dot/digit-only inputs without a letter are
	// almost always partial IP addresses being typed.
	hasLetter := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
			break
		}
	}
	if !hasLetter {
		return nil
	}
	lower := strings.ToLower(s)
	return func(candidate string) bool {
		return strings.Contains(strings.ToLower(candidate), lower)
	}
}

// parseFindingTime parses a timestamp string in the supplied location.
// Layouts include the analyzer's "2006-01-02 15:04:05" emit format,
// HTML datetime-local input shape ("2006-01-02T15:04"), and RFC3339.
//
// Callers parsing the analyzer's own emitted Timestamp pass time.UTC
// (the analyzer always writes in UTC). Callers parsing operator-
// supplied filter inputs from the UI's datetime-local picker pass
// the operator's configured timezone — pre-fix the function used
// time.Parse with no location, which Go silently treats as UTC, so
// a Tampa operator entering "9:00 AM" got findings between
// 04:00–12:00 UTC (i.e. 23:00 the previous day to 07:00 local) —
// off by 5 hours. Audit 2026-05-10 NEW-4. The off-hours detector
// already respected cfg.Timezone; the findings filter didn't.
//
// Output is normalized to UTC so the result compares directly with
// the analyzer's UTC-emitted Timestamp field.
func parseFindingTime(s string, loc *time.Location) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if loc == nil {
		loc = time.UTC
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
		if t, err := time.ParseInLocation(l, s, loc); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// operatorLocation returns the operator's configured timezone, or
// UTC when the config string is empty or unparseable. Mirrors the
// fallback shape analyzeConn uses for off-hours detection — a bad
// timezone config falls back to UTC silently rather than disabling
// the dependent feature.
func (s *Server) operatorLocation() *time.Location {
	tz := strings.TrimSpace(s.store.GetConfig().Timezone)
	if tz == "" {
		return time.UTC
	}
	if loc, err := time.LoadLocation(tz); err == nil {
		return loc
	}
	return time.UTC
}
