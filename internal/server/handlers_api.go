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

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// datasetFromPath returns the first path component under logsDir.
// e.g. logsDir=/logs  path=/logs/apt29/2024-01-01/conn.log  →  "apt29"
func datasetFromPath(logsDir, filePath string) string {
	logsDir = filepath.Clean(logsDir)
	filePath = filepath.Clean(filePath)
	rel, err := filepath.Rel(logsDir, filePath)
	if err != nil || rel == "." {
		return ""
	}
	// First component of the relative path is the dataset name
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
	search := strings.ToLower(q.Get("search"))
	typeF := q.Get("type")
	sevF := q.Get("severity")
	minScore, _ := strconv.Atoi(q.Get("min_score"))
	delta := q.Get("delta") == "true"
	sortCol := q.Get("sort")
	if sortCol == "" {
		sortCol = "score"
	}
	sortDir := q.Get("dir")

	findings := s.store.GetFindings()
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

	var result []model.Finding
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
		if search != "" {
			hay := strings.ToLower(fmt.Sprintf("%s %s %s %s %s %s %s",
				f.Type, f.SrcIP, f.DstIP, f.DstPort, f.Detail, f.Timestamp, f.Severity))
			if !strings.Contains(hay, search) {
				continue
			}
		}
		// Mark IOC matches
		f.IOCMatch = iocSet[f.DstIP] || iocSet[f.SrcIP]
		result = append(result, *f)
	}

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
	idStr := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	// Strip any trailing path segment
	if i := strings.Index(idStr, "/"); i >= 0 {
		idStr = idStr[:i]
	}
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		jsonError(w, "invalid id", http.StatusBadRequest)
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
// without exposing the keys themselves.
func (s *Server) handleTIServices(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.GetConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"vt":        cfg.VirusTotalAPIKey != "",
		"crowdsec":  cfg.CrowdSecAPIKey != "",
		"otx":       cfg.OTXAPIKey != "",
		"abuseipdb": cfg.AbuseIPDBAPIKey != "",
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

	doReq := func(req *http.Request) ([]byte, bool) {
		resp, err := client.Do(req)
		if err != nil {
			return nil, false
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return body, true
	}

	// publishHit saves a note and fires an SSE toast for a confirmed threat.
	publishHit := func(source, detail string, sev model.Severity) {
		hitCount++
		s.store.AddNote(f.ID, model.Note{
			Text:        fmt.Sprintf("[%s] %s", source, detail),
			Author:      source + " (TI Enrichment)",
			AuthorEmail: "system",
			Timestamp:   ts,
		})
		evtData, _ := json.Marshal(map[string]any{
			"finding_id": f.ID, "source": source, "severity": string(sev), "detail": detail, "hit": true,
		})
		s.broker.Publish(SSEEvent{Type: "ti_result", Data: string(evtData)})
	}

	// publishClean saves a note and fires an SSE toast for a clean (no threat) result.
	publishClean := func(source, detail string) {
		s.store.AddNote(f.ID, model.Note{
			Text:        fmt.Sprintf("[%s] %s", source, detail),
			Author:      source + " (TI Enrichment)",
			AuthorEmail: "system",
			Timestamp:   ts,
		})
		evtData, _ := json.Marshal(map[string]any{
			"finding_id": f.ID, "source": source, "severity": string(model.SevInfo), "detail": detail, "hit": false,
		})
		s.broker.Publish(SSEEvent{Type: "ti_result", Data: string(evtData)})
	}

	for _, dst := range ips {
		if dst == "" || dst == "—" || dst == "(network)" {
			continue
		}
		isIP := strings.Count(dst, ".") == 3

		if svcs["crowdsec"] && cfg.CrowdSecAPIKey != "" && isIP {
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://cti.api.crowdsec.net/v2/smoke/%s", dst), nil); err == nil {
				req.Header.Set("X-Api-Key", cfg.CrowdSecAPIKey)
				if body, ok := doReq(req); ok {
					var data struct {
						Scores struct{ Overall struct{ Total float64 `json:"total"` } `json:"overall"` } `json:"scores"`
					}
					if json.Unmarshal(body, &data) == nil {
						if data.Scores.Overall.Total > 0 {
							sev := model.SevHigh
							if data.Scores.Overall.Total > 5 { sev = model.SevCritical }
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
			if !isIP { vtURL = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", dst) }
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
							if mal > 3 { sev = model.SevCritical }
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
			if !isIP { otxURL = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/general", dst) }
			if req, err := http.NewRequest("GET", otxURL, nil); err == nil {
				req.Header.Set("X-OTX-API-KEY", cfg.OTXAPIKey)
				if body, ok := doReq(req); ok {
					var data struct {
						PulseInfo struct { Count int `json:"count"` } `json:"pulse_info"`
						Reputation int `json:"reputation"`
					}
					if json.Unmarshal(body, &data) == nil {
						if data.PulseInfo.Count > 0 || data.Reputation > 0 {
							sev := model.SevHigh
							if data.PulseInfo.Count > 5 { sev = model.SevCritical }
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
							if data.Data.AbuseConfidenceScore > 75 { sev = model.SevCritical }
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
		resp := map[string]any{
			"time":    watchTime,
			"enabled": enabled,
		}
		if enabled && watchTime != "" {
			if next, err := nextUTCOccurrence(watchTime); err == nil {
				resp["next_run"] = next.UTC().Format("2006-01-02 15:04 UTC")
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
			Time    string `json:"time"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Validate HH:MM format when enabling
		if req.Enabled {
			var h, m int
			if ok, _ := parseHHMM(req.Time, &h, &m); !ok {
				jsonError(w, "time must be HH:MM in 24-hour UTC format", http.StatusBadRequest)
				return
			}
		}
		s.store.SetWatch(req.Time, req.Enabled)
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

func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	findings := s.store.GetFindings()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="archer_results_%s.json"`, time.Now().Format("20060102_150405")))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]any{
		"archer_version": "3.0.0-go",
		"saved_at":       time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		"findings":       findings,
		"allowlist":      s.store.GetAllowlist(),
		"ioc_list":       s.store.GetIOCList(),
	})
}

func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	findings := s.store.GetFindings()
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="archer_%s.csv"`, time.Now().Format("20060102_150405")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"score", "severity", "type", "src_ip", "dst_ip", "dst_port", "timestamp", "detail", "source_file", "status", "analyst", "analyst_note"})
	for _, f := range findings {
		_ = cw.Write([]string{
			strconv.Itoa(f.Score), string(f.Severity), f.Type,
			f.SrcIP, f.DstIP, f.DstPort, f.Timestamp, f.Detail, f.SourceFile,
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
