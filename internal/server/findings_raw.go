package server

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/parser"
)

// logTypesForFinding maps a finding's Type to the Zeek log type(s) most
// likely to contain the source records. Used by the raw-log pivot.
var logTypesForFinding = map[string][]string{
	"Beaconing":                {"conn"},
	"Long Connection":          {"conn"},
	"Strobe":                   {"conn"},
	"Data Exfiltration":        {"conn"},
	"Lateral Movement":         {"conn"},
	"C2 Port":                  {"conn"},
	"Off-Hours Transfer":       {"conn"},
	"HTTP Beaconing":           {"http"},
	"Suspicious UA":            {"http"},
	"Cobalt Strike URI":        {"http"},
	"C2 URI Pattern":           {"http"},
	"Domain Fronting":          {"http", "ssl"},
	"Suspicious File Download": {"http", "files"},
	"Suspicious URL":           {"http"},
	"DNS Tunnel":               {"dns"},
	"NXDOMAIN Flood":           {"dns"},
	"Suspicious TLD":           {"dns"},
	"DoH Bypass":               {"dns"},
	"Malicious JA3":            {"ssl"},
	"Weak TLS":                 {"ssl"},
	"No-SNI":                   {"ssl"},
	"Suspicious Certificate":   {"x509"},
	"Weird Event":              {"weird"},
	"Zeek Notice":              {"notice"},
	"TI Hit (IP)":              {"conn", "http", "ssl"},
	"TI Hit (Domain)":          {"dns", "http"},
	"TI Hit (Hash)":            {"files", "http"},
	"Threat Intel Hit":         {"conn", "http", "dns", "ssl"}, // legacy pre-v0.7.0
}

// handleFindingRaw serves GET /api/findings/{id}/raw. It walks the scan root
// (/logs plus /data/archive) for log types relevant to the finding, parses
// each matching file, and returns up to `limit` records whose (src, dst) pair
// matches the finding's SrcIP/DstIP. Bounded-time pivot: useful for analyst
// "ok but what did the actual traffic look like" verification without needing
// to drop into the SIEM.
func (s *Server) handleFindingRaw(w http.ResponseWriter, r *http.Request, id int) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f, ok := s.store.GetFinding(id)
	if !ok {
		http.NotFound(w, r)
		return
	}

	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	// Time window bounds how far from the finding's timestamp we're willing to
	// search — the single biggest perf win since it lets us skip files whose
	// mtime is far from the window of interest. Passing window_hours=0
	// explicitly disables the filter (scan every matching file).
	windowHours := 6
	noWindow := false
	if raw := q.Get("window_hours"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err == nil {
			if n == 0 {
				noWindow = true
			} else if n > 0 {
				windowHours = n
			}
		}
	}

	logTypes := logTypesForFinding[f.Type]
	if len(logTypes) == 0 {
		logTypes = []string{"conn", "http", "dns", "ssl"}
	}

	scanRoots := []string{}
	if s.logsDir != "" {
		scanRoots = append(scanRoots, s.logsDir)
	}
	if _, err := os.Stat(archiveDir); err == nil {
		scanRoots = append(scanRoots, archiveDir)
	}

	// Parse the finding's timestamp to scope which files are worth reading.
	// 2h buffer on either side of the window covers rotation-boundary fuzz.
	var winStart, winEnd time.Time
	var haveWindow bool
	if !noWindow {
		if ft, ok := parseFindingTime(f.Timestamp); ok {
			winStart = ft.Add(-time.Duration(windowHours) * time.Hour).Add(-2 * time.Hour)
			winEnd = ft.Add(time.Duration(windowHours) * time.Hour).Add(2 * time.Hour)
			haveWindow = true
		}
	}

	// Pre-collect the candidate files (respecting the time window) before
	// spinning up workers, so we know the workload upfront.
	type fileJob struct {
		path    string
		logType string
	}
	var jobs []fileJob
	for _, root := range scanRoots {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !isLogTypeMatch(info.Name(), logTypes) {
				return nil
			}
			if haveWindow {
				mt := info.ModTime()
				if mt.Before(winStart) || mt.After(winEnd) {
					return nil
				}
			}
			jobs = append(jobs, fileJob{path: path, logType: detectLogType(info.Name())})
			return nil
		})
	}

	// Parallel parse. Bounded to avoid overwhelming disk + memory.
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if workers < 1 {
		workers = 1
	}

	matches := make([]map[string]any, 0, limit)
	var mu sync.Mutex
	var stop bool

	jobCh := make(chan fileJob, len(jobs))
	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				mu.Lock()
				done := stop
				mu.Unlock()
				if done {
					return
				}
				if err := parser.ParseLog(j.path, func(rec map[string]any) bool {
					mu.Lock()
					if stop || len(matches) >= limit {
						mu.Unlock()
						return false
					}
					mu.Unlock()
					src := parser.GetStr(rec, "id.orig_h")
					dst := parser.GetStr(rec, "id.resp_h")
					if f.SrcIP != "" && src != f.SrcIP {
						return true
					}
					if f.DstIP != "" && dst != f.DstIP {
						return true
					}
					rec["_source_file"] = j.path
					rec["_log_type"] = j.logType
					mu.Lock()
					if len(matches) < limit {
						matches = append(matches, rec)
					}
					if len(matches) >= limit {
						stop = true
					}
					mu.Unlock()
					return true
				}); err != nil {
					// Raw-log pivot is a best-effort lookup over the archive
					// fleet; one bad file should not blank the whole search.
					// Log it so an operator inspecting server logs can spot
					// the file that needs investigation.
					log.Printf("findings_raw: parser failed on %s: %v", j.path, err)
				}
			}
		}()
	}
	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"finding_id":   id,
		"log_types":    logTypes,
		"record_count": len(matches),
		"limit":        limit,
		"truncated":    len(matches) >= limit,
		"records":      matches,
		"generated":    time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	})
}

// isLogTypeMatch reports whether `basename` looks like a Zeek log of any of
// the given types. Matches "conn.log", "conn.00-01.log.gz", "conn_main.log",
// etc. — the same heuristic the analyzer's filterFiles uses.
func isLogTypeMatch(basename string, logTypes []string) bool {
	name := strings.TrimSuffix(basename, ".gz")
	name = strings.TrimSuffix(name, ".log")
	for _, lt := range logTypes {
		if name == lt || strings.HasPrefix(name, lt+".") || strings.HasPrefix(name, lt+"_") {
			return true
		}
	}
	return false
}

func detectLogType(basename string) string {
	name := strings.TrimSuffix(basename, ".gz")
	name = strings.TrimSuffix(name, ".log")
	if i := strings.IndexAny(name, "._"); i > 0 {
		return name[:i]
	}
	return name
}
