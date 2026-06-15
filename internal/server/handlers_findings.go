package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/analysis"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// handleFindingsUnseen reports the requesting analyst's "new since you last
// looked" count — findings first detected (detected_at) after their session's
// frozen new-findings boundary (the start of their previous session), roll-ups
// excluded. This is the per-user, retention-invariant replacement for the old
// global per-run is_new count the modal used: it accumulates across the hourly
// watch passes between one login and the next instead of resetting every tick,
// and matches exactly what the "New only" table filter shows.
func (s *Server) handleFindingsUnseen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	since := newBoundaryFromCtx(r)
	unseen, total := s.store.CountUnseen(since)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"count":      unseen,
		"total":      total,
		"since":      since,
		"seen_count": s.users.SessionModalHighWater(sessionTokenFromCtx(r)),
	})
}

// handleFindingsModalAck records that the new-findings modal was shown for
// this session at the current unseen count, so a page refresh (same session)
// doesn't re-pop it. The count is recomputed server-side rather than trusted
// from the client. The boundary is untouched, so the "New only" filter still
// surfaces the findings — only the modal pop is suppressed until the count
// climbs higher (genuinely new findings) or a fresh login starts a new session.
func (s *Server) handleFindingsModalAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	unseen, _ := s.store.CountUnseen(newBoundaryFromCtx(r))
	s.users.MarkSessionModalShown(sessionTokenFromCtx(r), unseen)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"seen_count": unseen})
}

// handleFindings returns filtered and sorted findings.
//
// Pagination: ?limit=N&offset=K page through the result. Default limit
// is 1000 (the analyst-table sweet spot for hunt workflows that go
// top-down by score); cap is 50000 (above that we'd be back to the
// pre-pagination payload sizes). The total result-set size is
// surfaced via X-Total-Count and X-Has-More response headers so the
// UI can render an accurate "Load more" affordance without a second
// round-trip.
//
// Export endpoints (/api/export/csv, /api/export/json) deliberately
// do NOT paginate — they go through filterFindings directly and dump
// the full set as a single download, which is the right behavior for
// "give me everything for this hunt" workflows.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	sortCol := q.Get("sort")
	if sortCol == "" {
		sortCol = "score"
	}
	sortDir := q.Get("dir")

	limit, offset := parseListPagination(q)

	result, err := s.filterFindings(s.store.GetFindings(), q, newBoundaryFromCtx(r))
	if err != nil {
		jsonError(w, "invalid query: "+err.Error(), http.StatusBadRequest)
		return
	}
	sortFindings(result, sortCol, sortDir)

	total := len(result)
	page := result
	if offset >= total {
		page = nil
	} else {
		end := offset + limit
		if end > total {
			end = total
		}
		page = result[offset:end]
	}
	hasMore := offset+len(page) < total

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	if hasMore {
		w.Header().Set("X-Has-More", "true")
	} else {
		w.Header().Set("X-Has-More", "false")
	}
	w.Header().Set("Access-Control-Expose-Headers", "X-Total-Count, X-Has-More")
	json.NewEncoder(w).Encode(projectFindingList(page, newBoundaryFromCtx(r), s.store.IsFingerprintAllowed))
}

// sortFindings sorts the slice in place by the same column / direction
// rules used by /api/findings. Shared with the position lookup so the
// "where is finding X" answer matches the ordering of the listing.
func sortFindings(findings []model.Finding, sortCol, sortDir string) {
	// keyLess reports a<b on the chosen column and whether the keys are equal.
	keyLess := func(a, b model.Finding) (less, equal bool) {
		switch sortCol {
		case "severity":
			oa, ob := severityOrder(a.Severity), severityOrder(b.Severity)
			return oa < ob, oa == ob
		case "type":
			return a.Type < b.Type, a.Type == b.Type
		case "src_ip":
			return a.SrcIP < b.SrcIP, a.SrcIP == b.SrcIP
		case "dst_ip":
			return a.DstIP < b.DstIP, a.DstIP == b.DstIP
		case "dst_port":
			// DstPort is a string; lexicographic compare matches the prior
			// client-side sort. Not numeric — keep parity, don't "fix" it here.
			return a.DstPort < b.DstPort, a.DstPort == b.DstPort
		case "status":
			return a.Status < b.Status, a.Status == b.Status
		case "sensor":
			return a.Sensor < b.Sensor, a.Sensor == b.Sensor
		case "timestamp":
			return a.Timestamp < b.Timestamp, a.Timestamp == b.Timestamp
		default: // "score" and any unknown column
			return a.Score < b.Score, a.Score == b.Score
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		less, equal := keyLess(a, b)
		if equal {
			// Tied keys get a deterministic tiebreak (ID ascending, both
			// directions). Without it the descending branch returned `!less`,
			// which reports a<b AND b<a for equal keys — not a strict weak
			// ordering, so tie order was undefined and could differ between
			// the listing and position endpoints, breaking Jump's landing
			// page. Score is the default sort and heavily tied.
			return a.ID < b.ID
		}
		if sortDir == "asc" {
			return less
		}
		return !less
	})
}

// parseListPagination reads ?limit and ?offset from the query string,
// applies sane defaults (limit 1000, offset 0), and clamps to safe
// bounds (limit max 50000, offset min 0). Anything unparseable falls
// back to the defaults rather than erroring — pagination should never
// be the reason a request fails.
func parseListPagination(q url.Values) (limit, offset int) {
	const (
		defaultLimit = 1000
		maxLimit     = 50000
	)
	limit = defaultLimit
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

// listFinding mirrors model.Finding for the list endpoint but omits the
// per-finding chart/evidence payload that bloats the response. The
// analyst's table view uses none of TSData / Intervals / Notes — those
// are read by the detail panel via /api/findings/{id}, which keeps the
// full shape. On a corpus with thousands of Beacon findings, omitting
// TSData alone cut the list response by ~100 MB in measurement.
//
// Field tags match model.Finding so existing UI code reads the same JSON
// keys; only the three heavy fields are absent from the wire format.
type listFinding struct {
	ID          int            `json:"id"`
	Type        string         `json:"type"`
	Severity    model.Severity `json:"severity"`
	Score       int            `json:"score"`
	SrcIP       string         `json:"src_ip"`
	DstIP       string         `json:"dst_ip"`
	DstPort     string         `json:"dst_port"`
	Detail      string         `json:"detail"`
	Timestamp   string         `json:"timestamp"`
	SourceFile  string         `json:"source_file"`
	Status      model.Status   `json:"status"`
	Analyst     string         `json:"analyst"`
	AnalystNote string         `json:"analyst_note"`
	StatusTS    string         `json:"status_ts"`
	IOCMatch    bool           `json:"ioc_match"`
	IOCSource   string         `json:"ioc_source,omitempty"`
	IsNew       bool           `json:"is_new"`
	IsNewToMe   bool           `json:"is_new_to_me,omitempty"`
	Sensor      string         `json:"sensor,omitempty"`
	// TLSAllowlisted marks that the finding's JA3/JA4 client fingerprint has
	// been marked benign on the TLS Fingerprints wall — a hint for the table,
	// not a filter (the finding still shows). Transient, set at projection.
	TLSAllowlisted bool `json:"tls_allowlisted,omitempty"`
}

// projectFindingList trims findings to the list shape. newBoundary is the
// requesting session's new-findings cutoff: each row's IsNewToMe is set when
// it was first detected after that boundary, so the table's "new" dot lights
// for everything new since the analyst last logged in — the same set the
// "New only" filter and the new-findings modal use — not just the most recent
// run's IsNew. fpAllowed reports whether a (kind, fingerprint) has been marked
// benign on the TLS Fingerprints wall; nil disables the marker.
func projectFindingList(in []model.Finding, newBoundary int64, fpAllowed func(kind, fp string) bool) []listFinding {
	out := make([]listFinding, len(in))
	for i, f := range in {
		allowlisted := fpAllowed != nil &&
			((f.JA4 != "" && fpAllowed("ja4", f.JA4)) || (f.JA3 != "" && fpAllowed("ja3", f.JA3)))
		out[i] = listFinding{
			ID: f.ID, Type: f.Type, Severity: f.Severity, Score: f.Score,
			SrcIP: f.SrcIP, DstIP: f.DstIP, DstPort: f.DstPort,
			Detail: f.Detail, Timestamp: f.Timestamp, SourceFile: f.SourceFile,
			Status: f.Status, Analyst: f.Analyst, AnalystNote: f.AnalystNote,
			StatusTS: f.StatusTS, IOCMatch: f.IOCMatch, IOCSource: f.IOCSource,
			IsNew: f.IsNew, IsNewToMe: f.DetectedAt > newBoundary, Sensor: f.Sensor,
			TLSAllowlisted: allowlisted,
		}
	}
	return out
}

// handleFindingsCounts returns per-status totals (open / acknowledged /
// escalated / dismissed / ioc-matched) under the current filter. Used
// by the dashboard's tab counter so analysts see accurate totals on
// every tab without having to visit each one. Filters honored: search,
// type, severity, min_score, src_ip, dst_ip, dst_port, sensor, from,
// to, delta. Status / ioc_only filters are stripped — the endpoint
// computes those buckets internally.
//
// `total` is the count of non-dismissed findings (the steady-state
// "things that aren't yet closed-and-gone"). Dismissed are tracked as
// their own `dis` bucket and not folded into `total` so the UI's
// summary number doesn't grow forever as analysts dismiss noise.
func (s *Server) handleFindingsCounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	// Strip the bucket-defining params so filterFindings doesn't apply
	// them — we want every finding the broader filter accepts so we can
	// bucket by status. include_dismissed=true keeps dismissed findings
	// in the result so we can count them as their own bucket; without
	// it the default-exclude rule in filterFindings would hide them
	// and the dis count would always read 0.
	q.Del("status")
	q.Del("ioc_only")
	q.Del("limit")
	q.Del("offset")
	q.Set("include_dismissed", "true")

	all, err := s.filterFindings(s.store.GetFindings(), q, newBoundaryFromCtx(r))
	if err != nil {
		jsonError(w, "invalid query: "+err.Error(), http.StatusBadRequest)
		return
	}
	var open, ack, esc, dis, ioc int
	nonDismissed := make([]model.Finding, 0, len(all))
	for _, f := range all {
		switch f.Status {
		case model.StatusOpen:
			open++
		case model.StatusAcknowledged:
			ack++
		case model.StatusEscalated:
			esc++
		case model.StatusDismissed:
			dis++
		}
		if f.Status != model.StatusDismissed {
			nonDismissed = append(nonDismissed, f)
		}
		if (f.IOCMatch || model.IsThreatIntelType(f.Type)) && f.Status != model.StatusDismissed {
			ioc++
		}
	}
	// Campaigns/Hosts chip counts — built from the same filtered set with the
	// shared rollup builders (identical rules to the views), so the sidebar
	// chips stay live on every filter change like the status chips, without the
	// client fetching + aggregating the full findings set. Dismissed is
	// excluded to match the top-level Campaigns/Hosts views.
	campaigns := len(buildCampaignsRollup(nonDismissed))
	hosts := len(buildHostsRollup(nonDismissed, s.store.GetConfig().OrgInternalCIDRs))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"open":      open,
		"ack":       ack,
		"esc":       esc,
		"dis":       dis,
		"ioc":       ioc,
		"total":     len(all) - dis,
		"campaigns": campaigns,
		"hosts":     hosts,
	})
}

// handleFindingsFacets returns the distinct values of low-cardinality
// columns (type, sensor) across the *entire* findings set, ignoring
// pagination and current type/sensor selection. The dashboard's filter
// dropdowns use this so they always show every available type / sensor,
// not just the ones present on the currently-rendered page.
//
// Status / ioc_only / delta / type / sensor query params are stripped —
// the rest of the filter set still applies (so a time-range or score
// filter narrows the dropdown options to "types observed in this
// window"). That keeps the dropdown options consistent with what the
// rest of the filter bar will surface.
func (s *Server) handleFindingsFacets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	q.Del("status")
	q.Del("ioc_only")
	q.Del("delta")
	q.Del("type")
	q.Del("sensor")
	q.Del("limit")
	q.Del("offset")

	all, err := s.filterFindings(s.store.GetFindings(), q, newBoundaryFromCtx(r))
	if err != nil {
		jsonError(w, "invalid query: "+err.Error(), http.StatusBadRequest)
		return
	}
	typeSet := make(map[string]struct{})
	sensorSet := make(map[string]struct{})
	for _, f := range all {
		if f.Type != "" {
			typeSet[f.Type] = struct{}{}
		}
		if f.Sensor != "" {
			sensorSet[f.Sensor] = struct{}{}
		}
	}
	types := make([]string, 0, len(typeSet))
	for t := range typeSet {
		types = append(types, t)
	}
	sort.Strings(types)
	sensors := make([]string, 0, len(sensorSet))
	for s := range sensorSet {
		sensors = append(sensors, s)
	}
	sort.Strings(sensors)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"types":   types,
		"sensors": sensors,
	})
}

// trendFamilies is the fixed series order for /api/findings/trend. The
// roll-up from ~30 finding types to seven families keeps the chart legend
// readable; the mapping lives in trendFamilyOf.
var trendFamilies = []struct{ Key, Label string }{
	{"beaconing", "Beaconing"},
	{"ti", "Threat Intel"},
	{"exfil", "Exfil"},
	{"dns", "DNS"},
	{"lateral", "Lateral"},
	{"tls", "TLS/Cert"},
	{"other", "Other"},
}

// trendFamilyOf maps a finding type to its trend-chart family key. Every
// non-roll-up analyzer type maps somewhere; unknown/future types land in
// "other" rather than vanishing from the chart.
func trendFamilyOf(t string) string {
	if model.IsThreatIntelType(t) {
		return "ti"
	}
	switch t {
	case "Beacon", "DNS Beacon", "HTTP Beacon", "Port-Hopping Beacon", "Strobe":
		return "beaconing"
	case "Malicious JA3", "Malicious JA4":
		return "ti"
	case "Data Exfiltration", "Off-Hours Transfer", "Database Protocol Egress", "Admin Protocol Egress":
		return "exfil"
	case "DNS Tunneling", "DNS NXDOMAIN Flood", "DNS Subdomain DGA":
		return "dns"
	case "Lateral Movement":
		return "lateral"
	case "Weak TLS", "SSL No-SNI", "SSL No-SNI on C2 Port", "Suspicious Certificate", "DoH Bypass", "Domain Fronting":
		return "tls"
	}
	return "other"
}

// trendSeverities is the fixed series order for the trend chart's severity
// lens — same shape as trendFamilies, keyed by model.Severity values.
var trendSeverities = []struct {
	Sev   model.Severity
	Key   string
	Label string
}{
	{model.SevCritical, "critical", "Critical"},
	{model.SevHigh, "high", "High"},
	{model.SevMedium, "medium", "Medium"},
	{model.SevLow, "low", "Low"},
	{model.SevInfo, "info", "Info"},
}

// handleFindingsTrend returns per-UTC-day finding counts, grouped two ways
// over the same zero-filled day axis: by detection family (`series`) and by
// severity tier (`severity_series`) — the chart's two lenses, computed in
// one pass so they can never disagree. It honors the exact filter surface
// of /api/findings (including status and delta) so the chart always agrees
// with the table below it. Groups with no findings in range are omitted.
// Roll-up types are excluded — they're derived from the per-record
// detections already counted, and would double-count.
func (s *Server) handleFindingsTrend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	q.Del("limit")
	q.Del("offset")
	q.Del("sort")
	q.Del("dir")

	all, err := s.filterFindings(s.store.GetFindings(), q, newBoundaryFromCtx(r))
	if err != nil {
		jsonError(w, "invalid query: "+err.Error(), http.StatusBadRequest)
		return
	}

	// byDay[day][familyKey] and sevByDay[day][severityKey]. Day is the UTC
	// date prefix of the finding's event timestamp
	// ("2006-01-02 15:04:05[ UTC]").
	byDay := make(map[string]map[string]int)
	sevByDay := make(map[string]map[model.Severity]int)
	var minDay, maxDay string
	for _, f := range all {
		if model.IsRollupType(f.Type) || len(f.Timestamp) < 10 {
			continue
		}
		day := f.Timestamp[:10]
		if _, err := time.Parse("2006-01-02", day); err != nil {
			continue
		}
		if minDay == "" || day < minDay {
			minDay = day
		}
		if day > maxDay {
			maxDay = day
		}
		m := byDay[day]
		if m == nil {
			m = make(map[string]int)
			byDay[day] = m
		}
		m[trendFamilyOf(f.Type)]++
		sm := sevByDay[day]
		if sm == nil {
			sm = make(map[model.Severity]int)
			sevByDay[day] = sm
		}
		sm[f.Severity]++
	}

	type trendSeries struct {
		Key    string `json:"key"`
		Label  string `json:"label"`
		Counts []int  `json:"counts"`
	}
	days := []string{}
	series := []trendSeries{}
	sevSeries := []trendSeries{}
	if minDay != "" {
		start, _ := time.Parse("2006-01-02", minDay)
		end, _ := time.Parse("2006-01-02", maxDay)
		// A single corrupt-but-parseable timestamp (a stray epoch-zero or
		// far-future Zeek ts) would otherwise zero-fill decades of days.
		const maxTrendDays = 3660
		if end.Sub(start) > maxTrendDays*24*time.Hour {
			start = end.AddDate(0, 0, -(maxTrendDays - 1))
		}
		for d := start; !d.After(end); d = d.AddDate(0, 0, 1) {
			days = append(days, d.Format("2006-01-02"))
		}
		for _, fam := range trendFamilies {
			counts := make([]int, len(days))
			total := 0
			for i, day := range days {
				c := byDay[day][fam.Key]
				counts[i] = c
				total += c
			}
			if total > 0 {
				series = append(series, trendSeries{Key: fam.Key, Label: fam.Label, Counts: counts})
			}
		}
		for _, tier := range trendSeverities {
			counts := make([]int, len(days))
			total := 0
			for i, day := range days {
				c := sevByDay[day][tier.Sev]
				counts[i] = c
				total += c
			}
			if total > 0 {
				sevSeries = append(sevSeries, trendSeries{Key: tier.Key, Label: tier.Label, Counts: counts})
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"days":            days,
		"series":          series,
		"severity_series": sevSeries,
	})
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	parts := strings.SplitN(rest, "/", 2)
	idStr := parts[0]
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	// Sub-resource dispatch: /api/findings/{id}/raw → raw-log pivot;
	// /api/findings/{id}/position → page-offset lookup for bell jumps;
	// /api/findings/{id}/history → 30-day beacon evolution chart data.
	if len(parts) > 1 {
		switch parts[1] {
		case "raw":
			s.handleFindingRaw(w, r, id)
		case "position":
			s.handleFindingPosition(w, r, id)
		case "history":
			s.handleFindingHistory(w, r, id)
		default:
			http.NotFound(w, r)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		f, ok := s.store.GetFinding(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		// TLS fingerprint cross-reference: only the single-finding
		// detail view pays for this scan. JA4 preferred when both are
		// present (JA4+ plugin present on sensor); JA3 is the fallback
		// for sensors on stock Zeek. Empty fingerprint → count returns
		// 0 and the field is omitted from the JSON response.
		if f.JA4 != "" && model.IsBeaconType(f.Type) {
			f.JA4SiblingCount = s.store.CountBeaconsWithJA4(f.JA4, f.ID)
		}
		if f.JA3 != "" && model.IsBeaconType(f.Type) {
			f.JA3SiblingCount = s.store.CountBeaconsWithJA3(f.JA3, f.ID)
		}
		// TLS-fingerprint rarity / cross-host-cluster concern (colour-coded
		// row in the detail pane). Derived from the prevalence snapshot over
		// all ssl.log, so it sees rarity and sub-floor siblings the emitted-
		// beacon sibling counts above cannot. Conn-level Beacon only —
		// that's where the seed-connection fingerprint is lifted.
		if f.Type == "Beacon" && (f.JA4 != "" || f.JA3 != "") {
			f.FPConcern, f.FPDetail = s.store.FingerprintConcern(f.JA4, f.JA3)
		}
		// Known-bad C2 flag for the detail-pane mark buttons: built-in tables OR
		// the operator JA3/JA4 IOC list — the same union the TLS wall uses to
		// withhold its mark buttons. detail.js suppresses Benign/Malicious for a
		// known-bad fingerprint so the two surfaces behave identically.
		if f.JA4 != "" || f.JA3 != "" {
			opJA3, opJA4 := analysis.ClassifyFingerprints(s.store.GetIOCFingerprints())
			_, badJA4Builtin := analysis.KnownBadJA4[f.JA4]
			_, badJA4Op := opJA4[f.JA4]
			_, badJA3Builtin := analysis.KnownBadJA3[f.JA3]
			_, badJA3Op := opJA3[f.JA3]
			if (f.JA4 != "" && (badJA4Builtin || badJA4Op)) || (f.JA3 != "" && (badJA3Builtin || badJA3Op)) {
				f.FPKnownBad = true
			}
		}
		// New-to-this-viewer flag for the detail pane's "new" badge — same
		// session boundary the table dot and the "New only" filter use.
		f.IsNewToMe = f.DetectedAt > newBoundaryFromCtx(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f)

	case http.MethodPatch:
		if u := userFromCtx(r); u.Role != model.RoleAnalyst && u.Role != model.RoleAdmin {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		var req struct {
			Status string `json:"status"`
			Note   string `json:"note"`
		}
		if err := decodeJSONBody(w, r, &req, noteBodyMaxBytes); err != nil {
			return
		}
		// Validate the status string against the known enum so a buggy
		// automation client or a compromised analyst session can't
		// silently write "archived" or any other free-form value into
		// the findings table — which would persist faithfully and
		// disappear from the UI's tab filters. Mirrors the validation
		// validateImportedFinding already applies on /api/import.
		// v0.14.3 NEW-37.
		switch model.Status(req.Status) {
		case model.StatusOpen, model.StatusAcknowledged, model.StatusEscalated, model.StatusDismissed:
			// ok
		default:
			jsonError(w, "invalid status — must be \"\" (open), \"acknowledged\", \"escalated\", or \"dismissed\"", http.StatusBadRequest)
			return
		}
		user := userFromCtx(r)
		ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
		// UpdateFinding returns the pre-mutation snapshot under the
		// same mutex as the write, so the audit row's BeforeValue is
		// the actual prior state — no race against a concurrent PATCH
		// landing between a separate GetFinding and UpdateFinding.
		// v0.14.2 NEW-36.
		before, found, err := s.store.UpdateFinding(id, model.Status(req.Status), user.DisplayName(), req.Note, ts)
		if !found {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			jsonError(w, "store error", http.StatusInternalServerError)
			return
		}
		if req.Note != "" {
			_, _ = s.store.AddNote(id, model.Note{
				Text:        req.Note,
				Author:      user.DisplayName(),
				AuthorEmail: user.Email,
				Timestamp:   ts,
			})
		}
		s.recordAudit(r, "finding_status_change", auditEvent{
			TargetType:  "finding",
			TargetID:    strconv.Itoa(id),
			TargetName:  findingAuditName(before),
			BeforeValue: map[string]any{"status": string(before.Status)},
			AfterValue:  map[string]any{"status": req.Status},
			Details:     map[string]any{"note_length": len(strings.TrimSpace(req.Note))},
		})
		jsonOK(w)

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFindingsBulk applies a status transition (acknowledge / escalate /
// dismiss) to many findings at once — the batched analog of the single-finding
// PATCH and the generalization of the campaign bulk-dismiss. The target set is
// either an explicit list of `ids` (the table's checkbox selection) or, when
// `ids` is empty, every finding matching the request's filter query params (the
// "select all N matching" path, reusing the exact /api/findings filter surface).
//
// Escalate here is a triage action: it flips status and forwards each newly-
// escalated finding to the SIEM (cheap, best-effort), but deliberately does NOT
// run the per-finding TI vendor enrichment the single /escalate does — fanning
// out hundreds of VirusTotal/OTX/AbuseIPDB lookups from one click is a
// rate-limit and cost footgun. Enrichment stays a deliberate single-finding act.
// Route is write-gated (analyst+).
func (s *Server) handleFindingsBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Action string `json:"action"`
		IDs    []int  `json:"ids"`
		Note   string `json:"note"`
	}
	if err := decodeJSONBody(w, r, &req, bulkBodyMaxBytes); err != nil {
		return
	}
	var status model.Status
	switch req.Action {
	case "ack":
		status = model.StatusAcknowledged
	case "esc":
		status = model.StatusEscalated
	case "dismiss":
		status = model.StatusDismissed
	case "open":
		// Reopen — also the target the undo toast replays into for findings
		// whose prior status was open.
		status = model.StatusOpen
	default:
		jsonError(w, `action must be "ack", "esc", "dismiss", or "open"`, http.StatusBadRequest)
		return
	}

	// Target set: explicit ids, else every finding matching the filter query.
	ids := req.IDs
	if len(ids) == 0 {
		matched, err := s.filterFindings(s.store.GetFindings(), r.URL.Query(), newBoundaryFromCtx(r))
		if err != nil {
			jsonError(w, "invalid query: "+err.Error(), http.StatusBadRequest)
			return
		}
		ids = make([]int, 0, len(matched))
		for _, f := range matched {
			ids = append(ids, f.ID)
		}
	}

	user := userFromCtx(r)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	befores, n := s.store.BulkUpdateStatus(ids, status, user.DisplayName(), req.Note, ts)

	// One audit row per finding (matching the single-PATCH and campaign-dismiss
	// trail), tagged bulk:<action> so the aggregate action is filterable. befores
	// are the pre-change snapshots captured under the store lock.
	auditAction := "finding_status_change"
	if status == model.StatusEscalated {
		auditAction = "finding_escalate"
	}
	noteLen := len(strings.TrimSpace(req.Note))
	for _, before := range befores {
		s.recordAudit(r, auditAction, auditEvent{
			TargetType:  "finding",
			TargetID:    strconv.Itoa(before.ID),
			TargetName:  findingAuditName(before),
			BeforeValue: map[string]any{"status": string(before.Status)},
			AfterValue:  map[string]any{"status": string(status)},
			Details:     map[string]any{"note_length": noteLen, "bulk": req.Action},
		})
	}

	// Escalate: forward each newly-escalated finding to the SIEM, best-effort
	// and off the response path. No TI vendor enrichment — see the doc comment.
	if status == model.StatusEscalated {
		cfg := s.store.GetConfig()
		for _, before := range befores {
			before.IOCMatch, before.IOCSource = s.iocStatusFor(before)
			go s.forwardEscalationToSIEM(cfg, before, user.DisplayName(), siemDeepLink(r, before.ID))
		}
	}

	// Return the per-finding prior statuses so the client's undo toast can
	// restore each finding to its OWN previous status (a bulk-ack may include
	// findings that were escalated — blanket-reopen would corrupt them). Undo
	// replays these grouped by status back through this same endpoint.
	prior := make([]map[string]any, 0, len(befores))
	for _, b := range befores {
		prior = append(prior, map[string]any{"id": b.ID, "status": string(b.Status)})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"affected": n, "prior": prior})
}

// handleFindingPosition returns the absolute zero-indexed position of a
// finding within /api/findings under the same filter + sort parameters.
// The bell-notification "Jump" action uses it to navigate to the page
// containing the target finding regardless of the analyst's current
// pagination offset. 404 means the finding does not match the supplied
// filter (deleted, archived, or status mismatch).
func (s *Server) handleFindingPosition(w http.ResponseWriter, r *http.Request, id int) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	sortCol := q.Get("sort")
	if sortCol == "" {
		sortCol = "score"
	}
	sortDir := q.Get("dir")

	result, err := s.filterFindings(s.store.GetFindings(), q, newBoundaryFromCtx(r))
	if err != nil {
		jsonError(w, "invalid query: "+err.Error(), http.StatusBadRequest)
		return
	}
	sortFindings(result, sortCol, sortDir)

	pos := -1
	for i, f := range result {
		if f.ID == id {
			pos = i
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if pos < 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{
			"found": false,
			"total": len(result),
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"found":  true,
		"offset": pos,
		"total":  len(result),
	})
}

// iocStatusFor recomputes whether a finding's src/dst matches an IOC source —
// the operator IOC list, a TI feed, or an intrinsic threat-intel finding type.
// Mirrors the read-path logic in filterFindings (IOCSource is not persisted).
func (s *Server) iocStatusFor(f model.Finding) (bool, string) {
	for _, sm := range s.store.IOCSources() {
		if sm.Matcher.Matches(f.DstIP) || sm.Matcher.Matches(f.SrcIP) {
			return true, sm.Source
		}
	}
	if model.IsThreatIntelType(f.Type) {
		return true, "Threat Intel"
	}
	return false, ""
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetNotifications())
	case http.MethodPost:
		// Notifications are store-global, so a viewer dismissing them clears
		// live CRITICAL / TI / unauthorized-sensor alerts for every analyst.
		// Dismissal is a write action; viewers get read-only GET above.
		if u := userFromCtx(r); u.Role == model.RoleViewer {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		var req struct {
			Action string `json:"action"` // "dismiss", "dismiss_all"
			ID     int    `json:"id"`
		}
		if err := decodeJSONBody(w, r, &req, 1<<10); err != nil {
			return
		}
		switch req.Action {
		case "dismiss":
			s.store.DismissNotification(req.ID)
		case "dismiss_all":
			s.store.DismissAllNotifications()
		default:
			// NEW-63: unrecognized action silently returned 200 OK with
			// no observable effect. Clients couldn't tell their request
			// did nothing. Now it's a clear 400.
			jsonError(w, "unknown action — expected dismiss or dismiss_all", http.StatusBadRequest)
			return
		}
		jsonOK(w)
	default:
		// NEW-63: pre-fix any verb other than GET / POST got an empty
		// response that net/http defaulted to 200 OK — confusing API
		// surface. Reject explicitly.
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAddNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role == model.RoleViewer {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	path = strings.TrimSuffix(path, "/notes")
	id, err := strconv.Atoi(path)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := decodeJSONBody(w, r, &req, noteBodyMaxBytes); err != nil {
		return
	}
	if strings.TrimSpace(req.Text) == "" {
		jsonError(w, "note text required", http.StatusBadRequest)
		return
	}
	user := userFromCtx(r)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	noteText := strings.TrimSpace(req.Text)
	found, err := s.store.AddNote(id, model.Note{
		Text:        noteText,
		Author:      user.DisplayName(),
		AuthorEmail: user.Email,
		Timestamp:   ts,
	})
	if !found {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}
	// Note text itself stays out of the audit log — it's preserved
	// in the finding's notes array, and may contain operationally
	// sensitive analyst observations. v0.14.1 NEW-32.
	f, _ := s.store.GetFinding(id)
	s.recordAudit(r, "finding_note_add", auditEvent{
		TargetType: "finding",
		TargetID:   strconv.Itoa(id),
		TargetName: findingAuditName(f),
		Details:    map[string]any{"note_length": len(noteText)},
	})
	jsonOK(w)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func severityOrder(sev model.Severity) int {
	switch sev {
	case model.SevCritical:
		return 4
	case model.SevHigh:
		return 3
	case model.SevMedium:
		return 2
	case model.SevLow:
		return 1
	}
	return 0
}
