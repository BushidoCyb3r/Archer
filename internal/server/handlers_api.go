package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/analysis"
	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/store"
	"github.com/BushidoCyb3r/Archer/internal/version"
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

// handleAnalyze starts analysis in a background goroutine.
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.store.IsAnalyzing() {
		jsonError(w, "analysis already running", http.StatusConflict)
		return
	}

	var req struct {
		Files  []string        `json:"files"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	files := req.Files
	if len(files) == 0 {
		files = s.store.GetUploadedFiles()
	}
	if len(files) == 0 {
		jsonError(w, "no files to analyze", http.StatusBadRequest)
		return
	}

	if req.Config != nil {
		cfg := s.store.GetConfig()
		_ = json.Unmarshal(req.Config, &cfg)
		s.store.SetConfig(cfg)
	}

	s.launchAnalysis(files)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

// handleAnalyzeReset clears the findings table and relaunches analysis from
// scratch. Admin-only. Intended for "the config changed, I want a clean
// baseline" workflows where preserving old findings would be misleading.
func (s *Server) handleAnalyzeReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	if s.store.IsAnalyzing() {
		jsonError(w, "analysis already running", http.StatusConflict)
		return
	}
	files := s.store.GetUploadedFiles()
	if len(files) == 0 {
		files = s.scanLogsDir()
	}
	if len(files) == 0 {
		jsonError(w, "no files to analyze", http.StatusBadRequest)
		return
	}
	cleared := s.store.ClearFindings()
	s.launchAnalysis(files)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{
		"status":           "started",
		"findings_cleared": cleared,
	})
}

// handleAnalyzeStatus returns whether analysis is currently running/paused.
func (s *Server) handleAnalyzeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.analyzerMu.Lock()
	az := s.activeAnalyzer
	s.analyzerMu.Unlock()

	running := az != nil
	paused := running && az.IsPaused()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"running": running, "paused": paused})
}

// handleAnalyzeCancel stops the running analysis.
func (s *Server) handleAnalyzeCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.analyzerMu.Lock()
	az := s.activeAnalyzer
	s.analyzerMu.Unlock()
	if az == nil {
		jsonError(w, "no analysis running", http.StatusConflict)
		return
	}
	az.Cancel()
	w.WriteHeader(http.StatusOK)
}

// handleAnalyzePause pauses the running analysis.
func (s *Server) handleAnalyzePause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.analyzerMu.Lock()
	az := s.activeAnalyzer
	s.analyzerMu.Unlock()
	if az == nil {
		jsonError(w, "no analysis running", http.StatusConflict)
		return
	}
	az.Pause()
	w.WriteHeader(http.StatusOK)
}

// handleAnalyzeResume resumes a paused analysis.
func (s *Server) handleAnalyzeResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.analyzerMu.Lock()
	az := s.activeAnalyzer
	s.analyzerMu.Unlock()
	if az == nil {
		jsonError(w, "no analysis running", http.StatusConflict)
		return
	}
	az.Resume()
	w.WriteHeader(http.StatusOK)
}

// handleFindings returns filtered and sorted findings.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	sortCol := q.Get("sort")
	if sortCol == "" {
		sortCol = "score"
	}
	sortDir := q.Get("dir")

	result := s.filterFindings(s.store.GetFindings(), q)

	// Sort
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		var less bool
		switch sortCol {
		case "score":
			less = a.Score < b.Score
		case "severity":
			less = severityOrder(a.Severity) < severityOrder(b.Severity)
		case "type":
			less = a.Type < b.Type
		case "src_ip":
			less = a.SrcIP < b.SrcIP
		case "dst_ip":
			less = a.DstIP < b.DstIP
		case "timestamp":
			less = a.Timestamp < b.Timestamp
		default:
			less = a.Score < b.Score
		}
		if sortDir == "asc" {
			return less
		}
		return !less
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
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

	// Sub-resource dispatch: /api/findings/{id}/raw → raw-log pivot
	if len(parts) > 1 {
		switch parts[1] {
		case "raw":
			s.handleFindingRaw(w, r, id)
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f)

	case http.MethodPatch:
		if u := userFromCtx(r); u.Role != model.RoleAnalyst && u.Role != model.RoleAdmin {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var req struct {
			Status string `json:"status"`
			Note   string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		user := userFromCtx(r)
		ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
		ok := s.store.UpdateFinding(id, model.Status(req.Status), user.DisplayName(), req.Note, ts)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if req.Note != "" {
			s.store.AddNote(id, model.Note{
				Text:        req.Note,
				Author:      user.DisplayName(),
				AuthorEmail: user.Email,
				Timestamp:   ts,
			})
		}
		jsonOK(w)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTIServices reports which TI services have API keys configured,
// without exposing the keys themselves. GreyNoise reports true
// unconditionally — its Community API works without a key (rate-limited),
// so the service is always available regardless of config state.
func (s *Server) handleTIServices(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.GetConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"vt":        cfg.VirusTotalAPIKey != "",
		"crowdsec":  cfg.CrowdSecAPIKey != "",
		"otx":       cfg.OTXAPIKey != "",
		"abuseipdb": cfg.AbuseIPDBAPIKey != "",
		"greynoise": true,
		"censys":    cfg.CensysAPIID != "" && cfg.CensysAPISecret != "",
	})
}

func (s *Server) handleEscalate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role == model.RoleViewer {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}
	// Extract ID from path: /api/findings/{id}/escalate
	path := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	path = strings.TrimSuffix(path, "/escalate")
	id, err := strconv.Atoi(path)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct {
		Note     string   `json:"note"`
		IPs      []string `json:"ips"`
		Services []string `json:"services"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	user := userFromCtx(r)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	ok := s.store.UpdateFinding(id, model.StatusEscalated, user.DisplayName(), req.Note, ts)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if req.Note != "" {
		s.store.AddNote(id, model.Note{
			Text:        req.Note,
			Author:      user.DisplayName(),
			AuthorEmail: user.Email,
			Timestamp:   ts,
		})
	}

	// Background TI lookup using analyst-selected artifacts and services.
	if len(req.IPs) > 0 && len(req.Services) > 0 {
		svcSet := make(map[string]bool, len(req.Services))
		for _, svc := range req.Services {
			svcSet[svc] = true
		}
		f, _ := s.store.GetFinding(id)
		go s.runTIEscalation(f, req.IPs, svcSet)
	}
	jsonOK(w)
}

func (s *Server) runTIEscalation(f model.Finding, ips []string, svcs map[string]bool) {
	cfg := s.store.GetConfig()
	client := &http.Client{Timeout: 8 * time.Second}
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	hitCount := 0

	// Per-IP grouping buffer. Every publishHit/publishInfo/publishClean call
	// appends a line here; once the full IP×service loop finishes we write one
	// consolidated note instead of N small ones (the previous design left
	// the notes thread cluttered with one row per service per IP).
	//
	// `informative` is the cross-annotation gate: hits and substantive non-hit
	// findings (e.g. GreyNoise classifying an IP as CiscoOpenDNS, Censys
	// returning a host's service list) get the flag set; "no record found",
	// "lookup failed", and "request failed" stay false so they don't pollute
	// other findings with empty noise.
	type lineEntry struct {
		ip, text         string
		hit, informative bool
	}
	var lines []lineEntry

	doReq := func(req *http.Request) ([]byte, bool) {
		resp, err := client.Do(req)
		if err != nil {
			return nil, false
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return body, true
	}

	// currentIP is set by the per-IP loop below so publishHit/publishClean
	// know which IP a result belongs to without threading it through every
	// call site. Cleaner than passing dst through every nested closure.
	var currentIP string

	// publishHit appends a hit line and fires an SSE toast immediately
	// (live UI feedback) — the persistent note is written once at the end.
	publishHit := func(source, detail string, sev model.Severity) {
		hitCount++
		lines = append(lines, lineEntry{ip: currentIP, text: fmt.Sprintf("⚠ [%s] %s", source, detail), hit: true, informative: true})
		evtData, _ := json.Marshal(map[string]any{
			"finding_id": f.ID, "source": source, "severity": string(sev), "detail": detail, "hit": true,
		})
		s.broker.Publish(SSEEvent{Type: "ti_result", Data: string(evtData)})
	}

	// publishInfo appends a non-hit but substantive line — e.g. GreyNoise
	// classifying an IP as benign infrastructure, Censys returning a host's
	// service list. Cross-noted onto other findings the IP appears in so an
	// analyst opening (say) a beacon finding sees the enrichment context.
	publishInfo := func(source, detail string) {
		lines = append(lines, lineEntry{ip: currentIP, text: fmt.Sprintf("ℹ [%s] %s", source, detail), hit: false, informative: true})
		evtData, _ := json.Marshal(map[string]any{
			"finding_id": f.ID, "source": source, "severity": string(model.SevInfo), "detail": detail, "hit": false,
		})
		s.broker.Publish(SSEEvent{Type: "ti_result", Data: string(evtData)})
	}

	// publishClean appends a non-informative clean line — "no record found",
	// "lookup failed", "request failed". Recorded in the consolidated note on
	// the originating finding for completeness, but NOT cross-noted since
	// these carry no signal worth surfacing on unrelated findings.
	publishClean := func(source, detail string) {
		lines = append(lines, lineEntry{ip: currentIP, text: fmt.Sprintf("✓ [%s] %s", source, detail), hit: false, informative: false})
		evtData, _ := json.Marshal(map[string]any{
			"finding_id": f.ID, "source": source, "severity": string(model.SevInfo), "detail": detail, "hit": false,
		})
		s.broker.Publish(SSEEvent{Type: "ti_result", Data: string(evtData)})
	}

	for _, dst := range ips {
		if dst == "" || dst == "—" || dst == "(network)" {
			continue
		}
		currentIP = dst
		isIP := strings.Count(dst, ".") == 3

		if svcs["crowdsec"] && cfg.CrowdSecAPIKey != "" && isIP {
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://cti.api.crowdsec.net/v2/smoke/%s", dst), nil); err == nil {
				req.Header.Set("X-Api-Key", cfg.CrowdSecAPIKey)
				if body, ok := doReq(req); ok {
					var data struct {
						Scores struct {
							Overall struct {
								Total float64 `json:"total"`
							} `json:"overall"`
						} `json:"scores"`
					}
					if json.Unmarshal(body, &data) == nil {
						if data.Scores.Overall.Total > 0 {
							sev := model.SevHigh
							if data.Scores.Overall.Total > 5 {
								sev = model.SevCritical
							}
							publishHit("CrowdSec", fmt.Sprintf("%s reputation score %.2f", dst, data.Scores.Overall.Total), sev)
						} else {
							publishClean("CrowdSec", fmt.Sprintf("%s - no threats found", dst))
						}
					} else {
						publishClean("CrowdSec", fmt.Sprintf("%s - lookup failed", dst))
					}
				} else {
					publishClean("CrowdSec", fmt.Sprintf("%s - request failed", dst))
				}
			}
		}

		if svcs["vt"] && cfg.VirusTotalAPIKey != "" {
			vtURL := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", dst)
			if !isIP {
				vtURL = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", dst)
			}
			if req, err := http.NewRequest("GET", vtURL, nil); err == nil {
				req.Header.Set("x-apikey", cfg.VirusTotalAPIKey)
				if body, ok := doReq(req); ok {
					var data struct {
						Data struct {
							Attributes struct {
								LastAnalysisStats map[string]int `json:"last_analysis_stats"`
							} `json:"attributes"`
						} `json:"data"`
					}
					if json.Unmarshal(body, &data) == nil {
						stats := data.Data.Attributes.LastAnalysisStats
						if mal := stats["malicious"]; mal > 0 {
							sev := model.SevHigh
							if mal > 3 {
								sev = model.SevCritical
							}
							publishHit("VirusTotal", fmt.Sprintf("%d engines flagged %s as malicious", mal, dst), sev)
						} else {
							publishClean("VirusTotal", fmt.Sprintf("%s - no malicious detections", dst))
						}
					} else {
						publishClean("VirusTotal", fmt.Sprintf("%s - lookup failed", dst))
					}
				} else {
					publishClean("VirusTotal", fmt.Sprintf("%s - request failed", dst))
				}
			}
		}

		if svcs["otx"] && cfg.OTXAPIKey != "" {
			otxURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", dst)
			if !isIP {
				otxURL = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/general", dst)
			}
			if req, err := http.NewRequest("GET", otxURL, nil); err == nil {
				req.Header.Set("X-OTX-API-KEY", cfg.OTXAPIKey)
				if body, ok := doReq(req); ok {
					var data struct {
						PulseInfo struct {
							Count int `json:"count"`
						} `json:"pulse_info"`
						Reputation int `json:"reputation"`
					}
					if json.Unmarshal(body, &data) == nil {
						if data.PulseInfo.Count > 0 || data.Reputation > 0 {
							sev := model.SevHigh
							if data.PulseInfo.Count > 5 {
								sev = model.SevCritical
							}
							publishHit("OTX", fmt.Sprintf("%s found in %d threat pulse(s)", dst, data.PulseInfo.Count), sev)
						} else {
							publishClean("OTX", fmt.Sprintf("%s - no threat pulses found", dst))
						}
					} else {
						publishClean("OTX", fmt.Sprintf("%s - lookup failed", dst))
					}
				} else {
					publishClean("OTX", fmt.Sprintf("%s - request failed", dst))
				}
			}
		}

		if svcs["abuseipdb"] && cfg.AbuseIPDBAPIKey != "" && isIP {
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", dst), nil); err == nil {
				req.Header.Set("Key", cfg.AbuseIPDBAPIKey)
				req.Header.Set("Accept", "application/json")
				if body, ok := doReq(req); ok {
					var data struct {
						Data struct {
							AbuseConfidenceScore int `json:"abuseConfidenceScore"`
							TotalReports         int `json:"totalReports"`
						} `json:"data"`
					}
					if json.Unmarshal(body, &data) == nil {
						if data.Data.AbuseConfidenceScore > 0 {
							sev := model.SevHigh
							if data.Data.AbuseConfidenceScore > 75 {
								sev = model.SevCritical
							}
							publishHit("AbuseIPDB", fmt.Sprintf("%s confidence score %d%% (%d reports)", dst, data.Data.AbuseConfidenceScore, data.Data.TotalReports), sev)
						} else {
							publishClean("AbuseIPDB", fmt.Sprintf("%s - no abuse reports", dst))
						}
					} else {
						publishClean("AbuseIPDB", fmt.Sprintf("%s - lookup failed", dst))
					}
				} else {
					publishClean("AbuseIPDB", fmt.Sprintf("%s - request failed", dst))
				}
			}
		}

		// GreyNoise Community API — IP-only, returns the noise/riot/classification
		// triple. The big triage signal is `noise:true` ("this is internet
		// background scanning, not someone targeting you"); a `classification:
		// malicious` is the rare hit. Works unauthenticated; an optional key
		// raises the rate limit but isn't required.
		if svcs["greynoise"] && isIP {
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://api.greynoise.io/v3/community/%s", dst), nil); err == nil {
				if cfg.GreyNoiseAPIKey != "" {
					req.Header.Set("key", cfg.GreyNoiseAPIKey)
				}
				if body, ok := doReq(req); ok {
					var data struct {
						Noise          bool   `json:"noise"`
						Riot           bool   `json:"riot"`
						Classification string `json:"classification"`
						Name           string `json:"name"`
						Message        string `json:"message"`
					}
					if json.Unmarshal(body, &data) == nil {
						switch {
						case data.Classification == "malicious":
							sev := model.SevHigh
							if data.Noise {
								sev = model.SevCritical // both flagged AND scanning
							}
							publishHit("GreyNoise", fmt.Sprintf("%s classified malicious (%s)", dst, data.Name), sev)
						case data.Riot:
							publishInfo("GreyNoise", fmt.Sprintf("%s known benign service: %s", dst, data.Name))
						case data.Noise:
							publishInfo("GreyNoise", fmt.Sprintf("%s background internet scanner (%s) — likely not targeted", dst, data.Name))
						case data.Message == "IP not observed scanning the internet or contained in RIOT data set.":
							publishClean("GreyNoise", fmt.Sprintf("%s - no record found", dst))
						case data.Classification != "":
							publishInfo("GreyNoise", fmt.Sprintf("%s - %s", dst, data.Classification))
						default:
							publishClean("GreyNoise", fmt.Sprintf("%s - no record found", dst))
						}
					} else {
						publishClean("GreyNoise", fmt.Sprintf("%s - lookup failed", dst))
					}
				} else {
					publishClean("GreyNoise", fmt.Sprintf("%s - request failed", dst))
				}
			}
		}

		// Censys Hosts API — IP-only, requires Basic auth (API ID + Secret).
		// Censys doesn't classify malicious vs benign directly, so this is
		// always informational: which services are running and when the host
		// was last observed. Useful context to attach to the finding without
		// generating a hit/clean verdict on its own.
		if svcs["censys"] && cfg.CensysAPIID != "" && cfg.CensysAPISecret != "" && isIP {
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", dst), nil); err == nil {
				req.SetBasicAuth(cfg.CensysAPIID, cfg.CensysAPISecret)
				req.Header.Set("Accept", "application/json")
				if body, ok := doReq(req); ok {
					var data struct {
						Result struct {
							Services []struct {
								ServiceName string `json:"service_name"`
								Port        int    `json:"port"`
							} `json:"services"`
							LastUpdatedAt string `json:"last_updated_at"`
							Location      struct {
								Country string `json:"country"`
							} `json:"location"`
						} `json:"result"`
					}
					if json.Unmarshal(body, &data) == nil {
						svcCount := len(data.Result.Services)
						if svcCount > 0 {
							// Surface up to three port:service summaries so the
							// note is grep-able without dumping the full payload.
							sample := make([]string, 0, 3)
							for i, s := range data.Result.Services {
								if i >= 3 {
									break
								}
								sample = append(sample, fmt.Sprintf("%d/%s", s.Port, s.ServiceName))
							}
							loc := data.Result.Location.Country
							if loc == "" {
								loc = "unknown"
							}
							publishInfo("Censys", fmt.Sprintf("%s - %d services [%s] (location: %s, last seen %s)",
								dst, svcCount, strings.Join(sample, ", "), loc, data.Result.LastUpdatedAt))
						} else {
							publishClean("Censys", fmt.Sprintf("%s - no record found", dst))
						}
					} else {
						publishClean("Censys", fmt.Sprintf("%s - lookup failed", dst))
					}
				} else {
					publishClean("Censys", fmt.Sprintf("%s - request failed", dst))
				}
			}
		}
	}

	// Write the consolidated note. Group results per IP so the analyst can
	// scan top-down: header → IP block → service lines. Empty buffer means
	// no service ran (e.g. all IPs filtered, no services selected) — skip
	// the note entirely so the thread doesn't gain a useless empty entry.
	if len(lines) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "TI Enrichment Results — %d IP(s), %d hit(s)\n", len(ips), hitCount)
		seen := make(map[string]bool)
		for _, ip := range ips {
			if ip == "" || ip == "—" || ip == "(network)" || seen[ip] {
				continue
			}
			seen[ip] = true
			fmt.Fprintf(&b, "\n[%s]\n", ip)
			for _, ln := range lines {
				if ln.ip == ip {
					fmt.Fprintf(&b, "  %s\n", ln.text)
				}
			}
		}
		s.store.AddNote(f.ID, model.Note{
			Text:        strings.TrimRight(b.String(), "\n"),
			Author:      "TI Enrichment",
			AuthorEmail: "system",
			Timestamp:   ts,
		})
	}

	// Cross-annotate: for every IP with a substantive enrichment result
	// (hit or informative non-hit, e.g. GreyNoise CiscoOpenDNS / Censys
	// service list), attach a per-IP note to all OTHER findings that mention
	// that IP. The originating finding already got the full consolidated
	// note above; this surfaces the enrichment context on related findings
	// so an analyst opening a beacon row sees the TI verdict inline.
	skipIDs := map[int]bool{f.ID: true}
	notedIPs := make(map[string]bool)
	for _, ip := range ips {
		if ip == "" || ip == "—" || ip == "(network)" || notedIPs[ip] {
			continue
		}
		notedIPs[ip] = true
		var b strings.Builder
		fmt.Fprintf(&b, "TI Enrichment — %s", ip)
		any := false
		for _, ln := range lines {
			if ln.ip != ip || !ln.informative {
				continue
			}
			fmt.Fprintf(&b, "\n  %s", ln.text)
			any = true
		}
		if !any {
			continue
		}
		s.crossNoteByIP(ip, model.Note{
			Text:        b.String(),
			Author:      "TI Enrichment",
			AuthorEmail: "system",
			Timestamp:   ts,
		}, skipIDs)
	}

	doneData, _ := json.Marshal(map[string]any{
		"finding_id": f.ID,
		"hits":       hitCount,
	})
	s.broker.Publish(SSEEvent{Type: "ti_done", Data: string(doneData)})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetConfig())
	case http.MethodPut:
		if u := userFromCtx(r); u.Role != model.RoleAdmin {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		cfg := s.store.GetConfig()
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.store.SetConfig(cfg)
		jsonOK(w)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetAllowlist())
	case http.MethodPut:
		if u := userFromCtx(r); u.Role == model.RoleViewer {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var entries []string
		if err := json.NewDecoder(r.Body).Decode(&entries); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		s.store.SetAllowlist(entries)
		jsonOK(w)
	}
}

func (s *Server) handleIOC(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetIOCList())
	case http.MethodPut:
		if u := userFromCtx(r); u.Role == model.RoleViewer {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var entries []string
		if err := json.NewDecoder(r.Body).Decode(&entries); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		s.store.SetIOCList(entries)
		jsonOK(w)
	}
}

func (s *Server) handleSuppressions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sups := s.store.GetSuppressions()
		out := make([]map[string]any, 0, len(sups))
		for target, entry := range sups {
			out = append(out, map[string]any{"target": target, "expiry": entry.Expiry.Unix(), "detail": entry.Detail})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)

	case http.MethodPost:
		if u := userFromCtx(r); u.Role == model.RoleViewer {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var req struct {
			Target string  `json:"target"`
			Days   float64 `json:"days"`
			Detail string  `json:"detail"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Target) == "" || req.Days <= 0 {
			jsonError(w, "target and days are required", http.StatusBadRequest)
			return
		}
		expiry := time.Now().Add(time.Duration(req.Days * float64(24*time.Hour)))
		s.store.AddSuppression(req.Target, expiry, req.Detail)
		jsonOK(w)
	}
}

func (s *Server) handleDeleteSuppression(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role == model.RoleViewer {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	target := strings.TrimPrefix(r.URL.Path, "/api/suppressions/")
	s.store.RemoveSuppression(target)
	jsonOK(w)
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetNotifications())
	case http.MethodPost:
		var req struct {
			Action string `json:"action"` // "dismiss", "dismiss_all"
			ID     int    `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		switch req.Action {
		case "dismiss":
			s.store.DismissNotification(req.ID)
		case "dismiss_all":
			s.store.DismissAllNotifications()
		}
		jsonOK(w)
	}
}

func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		watchTime, enabled := s.store.GetWatch()
		tz := s.store.GetTimezone()
		intervalHours := s.store.GetWatchInterval()
		resp := map[string]any{
			"time":           watchTime,
			"enabled":        enabled,
			"timezone":       tz,
			"interval_hours": intervalHours,
		}
		if enabled && watchTime != "" {
			loc := loadLocationOrUTC(tz)
			// Surface the timezone abbreviation (EDT, PST, UTC, …) once,
			// instead of repeating the long IANA name three times across
			// the schedule preview, the next-run line, and the next-full
			// line. Frontend renders the abbrev once on the cadence head
			// and leaves the time strings unadorned.
			abbrev := time.Now().In(loc).Format("MST")
			if abbrev == "" {
				abbrev = "UTC"
			}
			resp["timezone_abbr"] = abbrev

			if next, err := nextOccurrenceInterval(watchTime, intervalHours, loc); err == nil {
				resp["next_run"] = formatRelativeTime(next, loc)

				// Two-tier cadence: derive next_run_kind and next_full_run so
				// the sidebar can tell the analyst whether the upcoming tick
				// is the daily full-pipeline pass or an incremental TI-only
				// pass — matters for "is my beacon detection going to refresh
				// at the next tick?" mental modelling. Mirrors the decision
				// logic in triggerWatchAnalysis (see watch.go).
				//
				// Operator can opt out of the two-tier behavior via the
				// "Always run full scan" toggle in Settings → Watch Mode;
				// when on, every tick is full and the sidebar drops the
				// "Next Full Scan" follow-up line.
				alwaysFull := s.store.GetConfig().WatchAlwaysFull
				lastFull := s.store.GetLastFullAnalysisTime()
				isFullTick := func(t time.Time) bool {
					if alwaysFull || lastFull.IsZero() {
						return true
					}
					utc := t.UTC()
					lf := lastFull.UTC()
					return utc.Year() != lf.Year() || utc.YearDay() != lf.YearDay()
				}
				nextIsFull := isFullTick(next)
				if nextIsFull {
					resp["next_run_kind"] = "full"
					resp["next_full_run"] = resp["next_run"]
				} else {
					resp["next_run_kind"] = "incremental"
					// Walk forward in the cadence until we land on a tick
					// whose UTC date differs from the last full run's date.
					// Bounded search: at hourly cadence the next-day boundary
					// is at most 25 hops away; at 12h cadence at most 3.
					step := time.Duration(intervalHours) * time.Hour
					if intervalHours == 0 || intervalHours == 24 {
						step = 24 * time.Hour
					}
					candidate := next
					for i := 0; i < 30; i++ {
						candidate = candidate.Add(step)
						if isFullTick(candidate) {
							resp["next_full_run"] = formatRelativeTime(candidate, loc)
							break
						}
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

	case http.MethodPost, http.MethodPut:
		if u := userFromCtx(r); u.Role != model.RoleAdmin {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		var req struct {
			Time          string `json:"time"`
			Enabled       bool   `json:"enabled"`
			Timezone      string `json:"timezone"`
			IntervalHours int    `json:"interval_hours"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Validate HH:MM format when enabling
		if req.Enabled {
			var h, m int
			if ok, _ := parseHHMM(req.Time, &h, &m); !ok {
				jsonError(w, "time must be HH:MM in 24-hour format", http.StatusBadRequest)
				return
			}
		}
		// Validate IANA timezone name. Empty is allowed and means UTC.
		if req.Timezone != "" {
			if _, err := time.LoadLocation(req.Timezone); err != nil {
				jsonError(w, `invalid timezone — use an IANA name like "America/New_York"`, http.StatusBadRequest)
				return
			}
		}
		// Validate interval. 0 (or 24) means daily; otherwise must be one of
		// the supported sub-daily cadences. Anything else gets clamped to 0
		// rather than rejected — the UI is the source of truth here.
		switch req.IntervalHours {
		case 0, 1, 4, 6, 12, 24:
			// ok
		default:
			req.IntervalHours = 0
		}
		s.store.SetWatch(req.Time, req.Timezone, req.Enabled, req.IntervalHours)
		if req.Enabled {
			s.startWatch()
		} else {
			s.stopWatch()
		}
		jsonOK(w)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleArchive(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetArchive())

	case http.MethodPost, http.MethodPut:
		if u := userFromCtx(r); u.Role != model.RoleAdmin {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		var req store.ArchiveSettings
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.Enabled && req.AfterDays <= 0 {
			jsonError(w, "after_days must be positive when enabling", http.StatusBadRequest)
			return
		}
		s.store.SetArchive(req)
		jsonOK(w)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleArchiveRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	me := userFromCtx(r)
	if me.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	settings := s.store.GetArchive()
	if settings.AfterDays <= 0 {
		jsonError(w, "configure archive_after_days before running", http.StatusBadRequest)
		return
	}

	// Empty body = real run; {"dry_run": true} = preview. The body is
	// optional so existing clients that just POST without a body keep
	// working.
	var req struct {
		DryRun bool `json:"dry_run"`
	}
	if r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	triggeredBy := me.DisplayName()
	if req.DryRun {
		triggeredBy = "" // preview never gets recorded, but be explicit
	}
	res := s.runArchive(settings.AfterDays, settings.PruneFindingsOnArchive, req.DryRun, triggeredBy)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// handleArchiveScan walks /data/archive and runs an IOC + TI-feed
// scan over its contents. Findings merge with the regular finding set
// — the SetFindings fingerprint logic preserves analyst state on any
// hits that were already known. Admin-only, mutually exclusive with a
// regular analysis run.
func (s *Server) handleArchiveScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	if s.store.IsAnalyzing() {
		jsonError(w, "another analysis is already in progress", http.StatusConflict)
		return
	}
	files := s.scanArchiveDir()
	if len(files) == 0 {
		jsonError(w, "no archived logs to scan", http.StatusBadRequest)
		return
	}
	s.launchTIOnly(files)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "started", "files": len(files)})
}

// launchTIOnly is the archive-scan analogue of launchAnalysisWithOptions.
// It runs only the IOC/TI phases of the analyzer, preserves all live
// findings via SetFindings's fingerprint merge, and reuses the regular
// progress/status/done/notification SSE events so the existing UI shows
// the run without any frontend changes.
func (s *Server) launchTIOnly(files []string) {
	cfg := s.store.GetConfig()
	s.store.SetAnalyzing(true)
	progressCh := make(chan analysis.ProgressEvent, 32)
	statusCh := make(chan string, 32)

	go func() {
		for evt := range progressCh {
			data, _ := json.Marshal(evt)
			s.broker.Publish(SSEEvent{Type: "progress", Data: string(data)})
		}
	}()
	go func() {
		for msg := range statusCh {
			data, _ := json.Marshal(map[string]string{"msg": msg})
			s.broker.Publish(SSEEvent{Type: "status", Data: string(data)})
		}
	}()

	go func() {
		az := analysis.New(cfg, progressCh, statusCh)

		s.analyzerMu.Lock()
		s.activeAnalyzer = az
		s.analyzerMu.Unlock()

		defer func() {
			s.analyzerMu.Lock()
			s.activeAnalyzer = nil
			s.analyzerMu.Unlock()
			close(progressCh)
			close(statusCh)
		}()

		findings := az.AnalyzeTIOnly(files)

		// Sensor attribution. Archive preserves the /logs/<sensor>/...
		// layout, so resolving against archiveDir yields the same sensor
		// name that the live tree would have used for these files.
		for i := range findings {
			findings[i].Sensor = sensorFromPath(archiveDir, findings[i].SourceFile)
		}

		newNotifs := s.store.SetFindings(findings)
		s.crossAnnotateNewTIHits(findings)
		for _, n := range newNotifs {
			nData, _ := json.Marshal(n)
			s.broker.Publish(SSEEvent{Type: "notification", Data: string(nData)})
		}

		wasCancelled := az.Ctx().Err() != nil
		newCount := 0
		for _, f := range findings {
			if f.IsNew {
				newCount++
			}
		}
		data, _ := json.Marshal(map[string]any{
			"count":     len(findings),
			"new_count": newCount,
			"cancelled": wasCancelled,
		})
		s.broker.Publish(SSEEvent{Type: "done", Data: string(data)})
	}()
}

// Exports honor the same query-string filters as /api/findings. Passing no
// parameters exports everything (original behavior); passing filters produces
// a file that matches exactly what the analyst sees on screen.
func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	findings := s.filterFindings(s.store.GetFindings(), r.URL.Query())

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

func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	findings := s.filterFindings(s.store.GetFindings(), r.URL.Query())
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="archer_%s.csv"`, time.Now().Format("20060102_150405")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"score", "severity", "type", "src_ip", "dst_ip", "dst_port", "timestamp", "detail", "source_file", "sensor", "status", "analyst", "analyst_note"})
	for _, f := range findings {
		_ = cw.Write([]string{
			strconv.Itoa(f.Score), string(f.Severity), f.Type,
			f.SrcIP, f.DstIP, f.DstPort, f.Timestamp, f.Detail, f.SourceFile, f.Sensor,
			string(f.Status), f.Analyst, f.AnalystNote,
		})
	}
	cw.Flush()
}

func (s *Server) handleImportJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		Findings  []model.Finding `json:"findings"`
		Allowlist []string        `json:"allowlist"`
		IOCList   []string        `json:"ioc_list"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	for i := range payload.Findings {
		payload.Findings[i].ID = i + 1
	}
	s.store.SetFindings(payload.Findings)
	if len(payload.Allowlist) > 0 {
		s.store.SetAllowlist(payload.Allowlist)
	}
	if len(payload.IOCList) > 0 {
		s.store.SetIOCList(payload.IOCList)
	}
	jsonOK(w)
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetUploadedFiles())
	}
}

func (s *Server) handleAddNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role == model.RoleViewer {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Text) == "" {
		jsonError(w, "note text required", http.StatusBadRequest)
		return
	}
	user := userFromCtx(r)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	ok := s.store.AddNote(id, model.Note{
		Text:        strings.TrimSpace(req.Text),
		Author:      user.DisplayName(),
		AuthorEmail: user.Email,
		Timestamp:   ts,
	})
	if !ok {
		http.NotFound(w, r)
		return
	}
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

func jsonOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
