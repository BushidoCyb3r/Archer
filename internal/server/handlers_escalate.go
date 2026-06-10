package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/siem"
	"github.com/BushidoCyb3r/Archer/internal/version"
)

// handleTIServices reports which TI services have API keys configured,
// without exposing the keys themselves. GreyNoise reports true
// unconditionally — its Community API works without a key (rate-limited),
// so the service is always available regardless of config state.
func (s *Server) handleTIServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
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

// siemDeepLink builds a URL back to the finding from the escalating analyst's
// own request (scheme + the host they reach Archer on). The frontend's
// ?finding= loader resolves it to the finding's row.
func siemDeepLink(r *http.Request, id int) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/?finding=%d", scheme, r.Host, id)
}

// forwardEscalationToSIEM forwards an escalated finding to a configured SIEM,
// best-effort. It fires only on the transition into escalated (before.Status
// guards against re-sending on a redundant escalate). Errors are logged, never
// surfaced — escalation's outcome is unchanged whether the SIEM is up, down,
// or unconfigured.
func (s *Server) forwardEscalationToSIEM(cfg config.Config, before model.Finding, analyst, deepLink string) {
	if !cfg.SIEMEnabled || cfg.SIEMHost == "" || before.Status == model.StatusEscalated {
		return
	}
	fwd := before
	fwd.Status = model.StatusEscalated
	fwd.Analyst = analyst
	port := cfg.SIEMPort
	if port == 0 {
		port = 9003
	}
	addr := net.JoinHostPort(cfg.SIEMHost, strconv.Itoa(port))
	line := siem.FormatCEF(fwd, version.Version, deepLink)
	if err := s.siemSend(addr, line); err != nil {
		slog.Warn("SIEM forward failed", "finding_id", before.ID, "addr", addr, "err", err)
	}
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
	if err := decodeJSONBody(w, r, &req, escalateBodyMaxBytes); err != nil {
		return
	}
	user := userFromCtx(r)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	// UpdateFinding returns the pre-mutation snapshot under the same
	// mutex so the audit row's BeforeValue.status is the actual prior
	// state, not a separate GetFinding read that races against
	// concurrent PATCHes. v0.14.2 NEW-36.
	before, found, err := s.store.UpdateFinding(id, model.StatusEscalated, user.DisplayName(), req.Note, ts)
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
	// Audit body deliberately omits the note text — it could carry
	// operationally sensitive specifics (named hosts, target
	// indicators), and the note is already preserved on the finding
	// itself. We record only the shape: length, selected IPs/services.
	s.recordAudit(r, "finding_escalate", auditEvent{
		TargetType:  "finding",
		TargetID:    strconv.Itoa(id),
		TargetName:  findingAuditName(before),
		BeforeValue: map[string]any{"status": string(before.Status)},
		AfterValue:  map[string]any{"status": string(model.StatusEscalated)},
		Details: map[string]any{
			"note_length": len(strings.TrimSpace(req.Note)),
			"ips":         req.IPs,
			"services":    req.Services,
		},
	})

	// Background TI lookup using analyst-selected artifacts and services.
	if len(req.IPs) > 0 && len(req.Services) > 0 {
		svcSet := make(map[string]bool, len(req.Services))
		for _, svc := range req.Services {
			svcSet[svc] = true
		}
		f, _ := s.store.GetFinding(id)
		go s.runTIEscalation(f, req.IPs, svcSet)
	}
	// IOCMatch/IOCSource are computed at /api/findings read time, not stored,
	// so the escalate snapshot lacks them — recompute here (same logic the
	// findings list uses) so the CEF reason field carries the real feed/list.
	before.IOCMatch, before.IOCSource = s.iocStatusFor(before)
	// Off the response path (like runTIEscalation above), so a slow or
	// unreachable SIEM never adds latency to the escalation. Arguments are
	// evaluated now, before the goroutine reads them.
	go s.forwardEscalationToSIEM(s.store.GetConfig(), before, user.DisplayName(), siemDeepLink(r, id))
	jsonOK(w)
}

func (s *Server) runTIEscalation(f model.Finding, ips []string, svcs map[string]bool) {
	cfg := s.store.GetConfig()
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
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
		// Bound the read: these are per-IP TI lookups against third-party
		// services (OTX, AbuseIPDB, GreyNoise, Censys). An unbounded ReadAll
		// lets a misbehaving or hostile endpoint balloon memory during
		// escalation. Matches the LimitReader discipline the feed fetchers use.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTIEscalationResponse))
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
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://cti.api.crowdsec.net/v2/smoke/%s", url.PathEscape(dst)), nil); err == nil {
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
			vtURL := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", url.PathEscape(dst))
			if !isIP {
				vtURL = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", url.PathEscape(dst))
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
			otxURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", url.PathEscape(dst))
			if !isIP {
				otxURL = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/general", url.PathEscape(dst))
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
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", url.QueryEscape(dst)), nil); err == nil {
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
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://api.greynoise.io/v3/community/%s", url.PathEscape(dst)), nil); err == nil {
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
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", url.PathEscape(dst)), nil); err == nil {
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
		_, _ = s.store.AddNote(f.ID, model.Note{
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
