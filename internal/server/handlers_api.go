package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/version"
)

// JSON body-size caps for analyst-facing mutation endpoints (consumers
// live in the handlers_*.go files split out of this one). Pre-fix every
// such decoder read unbounded, so a compromised analyst
// session (or a buggy automation script) could write a multi-MB
// note onto a finding, replace the allowlist with a 100MB array, or
// have the JSON decoder consume a 1GB body just to PATCH a status.
// All persisted to disk and copied through every SetFindings merge.
// Bounds are sized to the realistic content shape with generous
// headroom; the import endpoint has its own larger cap because that
// genuinely carries a bundle. The Quiver and sensor-management
// endpoints already had matching caps. Audit 2026-05-10 NEW-35.
const (
	noteBodyMaxBytes     = 64 << 10  // PATCH /api/findings/{id}, POST /notes — note + status
	escalateBodyMaxBytes = 256 << 10 // POST /escalate — note + ips/services arrays
	listBodyMaxBytes     = 4 << 20   // PUT /allowlist, /ioc-list — room for ~150K entries
	suppressBodyMaxBytes = 8 << 10   // POST /suppressions — tiny payload
	configBodyMaxBytes   = 16 << 10  // PUT /config — fixed-shape struct
	bulkBodyMaxBytes     = 1 << 20   // POST /api/findings/bulk — note + an explicit id list (undo replays many ids)

	// maxTIEscalationResponse caps each third-party TI lookup response read
	// during escalation. Per-IP JSON responses are small; this bounds memory
	// against a misbehaving or hostile endpoint.
	maxTIEscalationResponse = 8 << 20 // 8 MiB
)

// sensorFromPath returns the first path component under logsDir, which is
// the sensor name in a Quiver-fed deployment. Pre-Quiver / manual uploads
// dropped logs into top-level subdirectories that served the same role —
// the field's logical meaning is the same, only the source has changed.
// e.g. logsDir=/logs  path=/logs/zeek-01/2024-01-01/conn.log  →  "zeek-01"
func sensorFromPath(logsDir, filePath string) string {
	logsDir = filepath.Clean(logsDir)
	filePath = filepath.Clean(filePath)
	rel, err := filepath.Rel(logsDir, filePath)
	if err != nil || rel == "." {
		return ""
	}
	parts := strings.SplitN(rel, string(filepath.Separator), 2)
	if len(parts) > 0 && parts[0] != "." {
		return parts[0]
	}
	return ""
}

// handleVersion exposes the build identifier (release tag, git commit, build
// time) so the UI's About dialog and any external operator tooling can read
// it without going through the export flow. Unauthenticated by design — it's
// diagnostic, not sensitive, and is the same kind of endpoint as a future
// /api/health.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{
		"version":    version.Version,
		"commit":     version.Commit,
		"build_time": version.BuildTime,
	})
}

// handleLogsTree returns the sensor/date layout under the configured logs
// directory so the dashboard can render a read-only preview of what watch
// mode and "Analyze sensor logs" will pick up.
func (s *Server) handleLogsTree(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type dateNode struct {
		Date        string `json:"date"`
		Files       int    `json:"files"`
		SizeBytes   int64  `json:"size_bytes"`
		NewestMtime int64  `json:"newest_mtime"`
	}
	type sensorNode struct {
		Name           string     `json:"name"`
		Dates          []dateNode `json:"dates"`
		TotalFiles     int        `json:"total_files"`
		TotalSizeBytes int64      `json:"total_size_bytes"`
	}
	type response struct {
		LogsDir string       `json:"logs_dir"`
		Sensors []sensorNode `json:"sensors"`
	}

	out := response{LogsDir: s.logsDir, Sensors: []sensorNode{}}
	if s.logsDir == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	}

	sensorEntries, err := os.ReadDir(s.logsDir)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	}

	for _, se := range sensorEntries {
		if !se.IsDir() {
			continue
		}
		// Skip the purge bucket — /logs/_archived/<name>-<timestamp>/
		// holds disenrolled sensors' aside-rotated data, intentionally
		// out of scope for the live tree (and for analysis below).
		if se.Name() == "_archived" {
			continue
		}
		sensor := sensorNode{Name: se.Name(), Dates: []dateNode{}}
		sensorPath := filepath.Join(s.logsDir, se.Name())
		dateEntries, err := os.ReadDir(sensorPath)
		if err != nil {
			continue
		}
		for _, de := range dateEntries {
			if !de.IsDir() {
				continue
			}
			node := dateNode{Date: de.Name()}
			datePath := filepath.Join(sensorPath, de.Name())
			fileEntries, err := os.ReadDir(datePath)
			if err != nil {
				continue
			}
			for _, fe := range fileEntries {
				if fe.IsDir() {
					continue
				}
				name := fe.Name()
				if !(strings.HasSuffix(name, ".log") ||
					strings.HasSuffix(name, ".log.gz") ||
					strings.HasSuffix(name, ".gz") ||
					strings.HasSuffix(name, ".json") ||
					strings.HasSuffix(name, ".ndjson")) {
					continue
				}
				info, err := fe.Info()
				if err != nil {
					continue
				}
				node.Files++
				node.SizeBytes += info.Size()
				if mt := info.ModTime().Unix(); mt > node.NewestMtime {
					node.NewestMtime = mt
				}
			}
			if node.Files == 0 {
				continue
			}
			sensor.Dates = append(sensor.Dates, node)
			sensor.TotalFiles += node.Files
			sensor.TotalSizeBytes += node.SizeBytes
		}
		sort.Slice(sensor.Dates, func(i, j int) bool {
			return sensor.Dates[i].Date > sensor.Dates[j].Date
		})
		out.Sensors = append(out.Sensors, sensor)
	}
	sort.Slice(out.Sensors, func(i, j int) bool {
		return out.Sensors[i].Name < out.Sensors[j].Name
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func jsonOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
