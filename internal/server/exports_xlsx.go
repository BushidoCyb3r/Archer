package server

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// handleExportXLSX writes a multi-sheet workbook containing every tab's
// view in one file. Six sheets:
//
//	Findings, Acknowledged, Escalated  — the three status buckets
//	IOC Hits                           — findings tagged as IOC matches
//	Campaigns                          — destinations contacted by ≥ 2 src IPs
//	Hosts                              — per-org-host risk roll-up
//
// Filters and pagination are intentionally ignored — this endpoint is
// the "give me everything" surface, parallel to the existing CSV/JSON
// /api/export endpoints. The single-tab CSV/JSON exports honor filters;
// this one doesn't.
func (s *Server) handleExportXLSX(w http.ResponseWriter, r *http.Request) {
	all := s.store.GetFindings()

	// Filter once: same allowlist + suppression rules the listing
	// endpoint applies. Without this the export includes findings the
	// UI would never show, which surprises analysts comparing the file
	// to what's on screen.
	alM := s.store.AllowlistMatcher()
	visible := make([]model.Finding, 0, len(all))
	for i := range all {
		f := all[i]
		if alM.Matches(f.SrcIP) || alM.Matches(f.DstIP) {
			continue
		}
		if s.store.IsSuppressed(f.SrcIP) || s.store.IsSuppressed(f.DstIP) {
			continue
		}
		visible = append(visible, f)
	}

	// IOC tagging mirrors filterFindings but stays inline — we want to
	// tag every finding (for the IOC sheet) regardless of which tab the
	// JS would have surfaced it on.
	iocSources := s.store.IOCSources()
	for i := range visible {
		f := &visible[i]
		isTI := model.IsThreatIntelType(f.Type)
		ioMatch := isTI
		ioSource := ""
		if isTI {
			ioSource = "Threat Intel"
		}
		for _, sm := range iocSources {
			if sm.Matcher.Matches(f.DstIP) || sm.Matcher.Matches(f.SrcIP) {
				ioMatch = true
				ioSource = sm.Source
				break
			}
		}
		f.IOCMatch = ioMatch
		f.IOCSource = ioSource
	}

	// Bucket by status / IOC. Open = empty status string.
	var open, ack, esc, ioc []model.Finding
	for _, f := range visible {
		switch string(f.Status) {
		case "":
			open = append(open, f)
		case string(model.StatusAcknowledged):
			ack = append(ack, f)
		case string(model.StatusEscalated):
			esc = append(esc, f)
		}
		if f.IOCMatch {
			ioc = append(ioc, f)
		}
	}

	xf := excelize.NewFile()
	defer xf.Close()
	// excelize creates a default "Sheet1"; we'll write our six and
	// remove the default at the end.
	writeFindingsSheet(xf, "Findings", open)
	writeFindingsSheet(xf, "Acknowledged", ack)
	writeFindingsSheet(xf, "Escalated", esc)
	writeFindingsSheet(xf, "IOC Hits", ioc)
	writeCampaignsSheet(xf, "Campaigns", buildCampaignsRollup(visible))
	writeHostsSheet(xf, "Hosts", buildHostsRollup(visible, s.store.GetConfig().OrgInternalCIDRs))

	if idx, err := xf.GetSheetIndex("Findings"); err == nil {
		xf.SetActiveSheet(idx)
	}
	_ = xf.DeleteSheet("Sheet1")

	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="archer_%s.xlsx"`, time.Now().Format("20060102_150405")))
	if err := xf.Write(w); err != nil {
		// Body may already be partially written; the best we can do is
		// log and abandon the response.
		fmt.Fprintf(w, "\nexport failed: %v\n", err)
	}
}

// findingsHeader is the column order used on the three status sheets and
// the IOC Hits sheet. Mirrors the existing CSV export plus columns the
// xlsx format makes practical to include (IOC source, is_new flag).
var findingsHeader = []string{
	"score", "severity", "type",
	"src_ip", "dst_ip", "dst_port",
	"timestamp", "detail",
	"sensor", "source_file",
	"status", "analyst", "analyst_note",
	"ioc_match", "ioc_source", "is_new",
}

func writeFindingsSheet(xf *excelize.File, name string, findings []model.Finding) {
	if _, err := xf.NewSheet(name); err != nil {
		return
	}
	for col, h := range findingsHeader {
		cell, _ := excelize.CoordinatesToCellName(col+1, 1)
		_ = xf.SetCellValue(name, cell, h)
	}
	for row, f := range findings {
		vals := []any{
			f.Score, string(f.Severity), f.Type,
			f.SrcIP, f.DstIP, f.DstPort,
			f.Timestamp, f.Detail,
			f.Sensor, f.SourceFile,
			string(f.Status), f.Analyst, f.AnalystNote,
			f.IOCMatch, f.IOCSource, f.IsNew,
		}
		for col, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(col+1, row+2)
			_ = xf.SetCellValue(name, cell, v)
		}
	}
}

// campaignRollup mirrors the JS _computeCampaigns shape. Sorted score
// desc to match the default Campaigns tab ordering.
type campaignRollup struct {
	Dst       string
	Port      string
	SrcCount  int
	MaxScore  int
	HostCount int
	Types     []string
}

func buildCampaignsRollup(findings []model.Finding) []campaignRollup {
	type bucket struct {
		dst, port string
		srcs      map[string]bool
		maxScore  int
		types     map[string]bool
	}
	by := make(map[string]*bucket)
	for _, f := range findings {
		dst := f.DstIP
		if dst == "" || dst == "(network)" {
			continue
		}
		key := dst + ":" + f.DstPort
		b, ok := by[key]
		if !ok {
			b = &bucket{
				dst: dst, port: f.DstPort,
				srcs: map[string]bool{}, types: map[string]bool{},
			}
			by[key] = b
		}
		if f.SrcIP != "" {
			b.srcs[f.SrcIP] = true
		}
		if f.Score > b.maxScore {
			b.maxScore = f.Score
		}
		if f.Type != "" {
			b.types[f.Type] = true
		}
	}
	out := make([]campaignRollup, 0, len(by))
	for _, b := range by {
		if len(b.srcs) < 2 {
			// Mirrors the JS filter: campaigns require ≥ 2 distinct sources
			continue
		}
		types := make([]string, 0, len(b.types))
		for t := range b.types {
			types = append(types, t)
		}
		sort.Strings(types)
		out = append(out, campaignRollup{
			Dst: b.dst, Port: b.port,
			SrcCount: len(b.srcs), MaxScore: b.maxScore,
			HostCount: len(b.srcs), Types: types,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MaxScore > out[j].MaxScore })
	return out
}

func writeCampaignsSheet(xf *excelize.File, name string, rows []campaignRollup) {
	if _, err := xf.NewSheet(name); err != nil {
		return
	}
	header := []string{"score", "destination", "port", "hosts", "finding_types"}
	for col, h := range header {
		cell, _ := excelize.CoordinatesToCellName(col+1, 1)
		_ = xf.SetCellValue(name, cell, h)
	}
	for row, r := range rows {
		vals := []any{r.MaxScore, r.Dst, r.Port, r.HostCount, strings.Join(r.Types, " ")}
		for col, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(col+1, row+2)
			_ = xf.SetCellValue(name, cell, v)
		}
	}
}

// hostRollup mirrors the JS _computeHosts shape. Severity ordering
// follows the JS SEV_ORDER map so descending sort lands CRITICAL first.
type hostRollup struct {
	IP       string
	Score    int
	Count    int
	TopSev   string
	Types    []string
	sevOrder int // private — used only for sorting
}

var hostSevOrder = map[string]int{
	"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "IOC_HIT": 5,
}

func buildHostsRollup(findings []model.Finding, orgCIDRs []string) []hostRollup {
	parsedCIDRs := make([]*net.IPNet, 0, len(orgCIDRs))
	for _, c := range orgCIDRs {
		// Allow bare IPs by appending /32 or /128 — matches the JS UI.
		if !strings.Contains(c, "/") {
			if strings.Contains(c, ":") {
				c += "/128"
			} else {
				c += "/32"
			}
		}
		if _, ipnet, err := net.ParseCIDR(c); err == nil {
			parsedCIDRs = append(parsedCIDRs, ipnet)
		}
	}
	isOrg := func(ip string) bool {
		if ip == "" {
			return false
		}
		if isPrivateIP(ip) {
			return true
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return false
		}
		for _, n := range parsedCIDRs {
			if n.Contains(parsed) {
				return true
			}
		}
		return false
	}

	type bucket struct {
		ip       string
		score    int
		count    int
		topSev   string
		topOrder int
		types    map[string]bool
	}
	by := make(map[string]*bucket)
	for _, f := range findings {
		if !isOrg(f.SrcIP) {
			continue
		}
		b, ok := by[f.SrcIP]
		if !ok {
			b = &bucket{ip: f.SrcIP, topSev: "INFO", topOrder: hostSevOrder["INFO"], types: map[string]bool{}}
			by[f.SrcIP] = b
		}
		b.count++
		if f.Type != "" {
			b.types[f.Type] = true
		}
		if f.Score > b.score {
			b.score = f.Score
		}
		ord := hostSevOrder[string(f.Severity)]
		// Unknown severities sort last; matches the JS `?? 99` fallback
		if _, ok := hostSevOrder[string(f.Severity)]; !ok {
			ord = 99
		}
		if ord < b.topOrder {
			b.topSev = string(f.Severity)
			b.topOrder = ord
		}
	}
	out := make([]hostRollup, 0, len(by))
	for _, b := range by {
		types := make([]string, 0, len(b.types))
		for t := range b.types {
			types = append(types, t)
		}
		sort.Strings(types)
		out = append(out, hostRollup{
			IP: b.ip, Score: b.score, Count: b.count,
			TopSev: b.topSev, Types: types, sevOrder: b.topOrder,
		})
	}
	// Default sort: risk score desc — matches the Hosts tab default.
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// isPrivateIP duplicates the analysis package's helper. The server
// can't import internal/analysis without a circular dep, and the
// rule set is small enough that copying it is cheaper than wiring a
// shared helper package.
func isPrivateIP(ip string) bool {
	if ip == "" {
		return false
	}
	private := []string{
		"10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"127.", "169.254.", "::1", "fc", "fd", "fe80",
	}
	for _, p := range private {
		if len(ip) >= len(p) && ip[:len(p)] == p {
			return true
		}
	}
	return false
}

func writeHostsSheet(xf *excelize.File, name string, rows []hostRollup) {
	if _, err := xf.NewSheet(name); err != nil {
		return
	}
	// Column order matches the Hosts tab UI: risk_score, host_ip, ...
	header := []string{"risk_score", "host_ip", "findings", "severity", "finding_types"}
	for col, h := range header {
		cell, _ := excelize.CoordinatesToCellName(col+1, 1)
		_ = xf.SetCellValue(name, cell, h)
	}
	for row, r := range rows {
		vals := []any{r.Score, r.IP, r.Count, r.TopSev, strings.Join(r.Types, " ")}
		for col, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(col+1, row+2)
			_ = xf.SetCellValue(name, cell, v)
		}
	}
}
