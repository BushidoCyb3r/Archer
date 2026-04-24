package analysis

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)


// prefetchFeeds fetches threat intel feeds concurrently and caches results on the Analyzer.
// This runs as the first analysis step so downstream steps (checkTI, checkSuspiciousURLs) can
// reuse the data without a second network round-trip.
func (a *Analyzer) prefetchFeeds(_ []string) {
	client := &http.Client{Timeout: 30 * time.Second}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.feodoIPs = fetchFeodo(client) }()
	go func() { defer wg.Done(); a.urlhausIPs, a.urlhausHosts = fetchURLhaus(client) }()
	wg.Wait()
}

// checkSuspiciousURLs scans HTTP logs for requests to hosts listed in URLhaus.
func (a *Analyzer) checkSuspiciousURLs(files []string) {
	if len(a.urlhausHosts) == 0 {
		return
	}
	seen := make(map[[2]string]bool)
	for _, f := range filterFiles(files, "http") {
		_ = parser.ParseLog(f, func(rec map[string]any) bool {
			src     := parser.GetStr(rec, "id.orig_h")
			dst     := parser.GetStr(rec, "id.resp_h")
			host    := parser.GetStr(rec, "host")
			uri     := parser.GetStr(rec, "uri")
			ts      := parser.GetFloat(rec, "ts")
			dstPort := parser.GetInt(rec, "id.resp_p")
			if host == "" || src == "" {
				return true
			}
			h := host
			if idx := strings.LastIndex(h, ":"); idx >= 0 && strings.Count(h, ":") == 1 {
				h = h[:idx]
			}
			if a.urlhausHosts[h] {
				key := [2]string{src, h}
				if !seen[key] {
					seen[key] = true
					a.add(model.Finding{
						Type:      "Suspicious URL",
						Severity:  model.SevCritical,
						Score:     96,
						SrcIP:     src,
						DstIP:     dst,
						DstPort:   fmt.Sprint(dstPort),
						Detail:    fmt.Sprintf("URLhaus malware distribution host: %s | URI: %s", host, uri),
						Timestamp: fmtTS(ts),
					})
				}
			}
			return true
		})
	}
}

func (a *Analyzer) checkTI(files []string) {
	// Use pre-fetched feeds from prefetchFeeds step
	feodoIPs     := a.feodoIPs
	urlhausIPs   := a.urlhausIPs
	urlhausHosts := a.urlhausHosts

	dstIPs     := make(map[string]bool)
	dstDomains := make(map[string]bool)

	// Source 1: scan conn.log directly for every external destination IP.
	// This is the critical path — Feodo/URLhaus C2s may not trigger any other
	// detector (no beaconing score, no suspicious port), so we must check all
	// observed IPs, not just ones that already appear in findings.
	for _, f := range filterFiles(files, "conn") {
		_ = parser.ParseLog(f, func(rec map[string]any) bool {
			dst := parser.GetStr(rec, "id.resp_h")
			if dst != "" && !isPrivateIP(dst) && isIPAddr(dst) {
				dstIPs[dst] = true
			}
			return true
		})
	}

	// Source 2: DNS queries — catch URLhaus domains resolved by internal hosts.
	for _, f := range filterFiles(files, "dns") {
		_ = parser.ParseLog(f, func(rec map[string]any) bool {
			q := parser.GetStr(rec, "query")
			if q != "" && !isIPAddr(q) {
				dstDomains[q] = true
			}
			return true
		})
	}

	// Source 3: HTTP Host headers — URLhaus tracks URLs by hostname.
	for _, f := range filterFiles(files, "http") {
		_ = parser.ParseLog(f, func(rec map[string]any) bool {
			host := parser.GetStr(rec, "host")
			if host == "" {
				return true
			}
			// Strip port if present
			if i := strings.LastIndex(host, ":"); i >= 0 && strings.Count(host, ":") == 1 {
				host = host[:i]
			}
			if host != "" && !isIPAddr(host) {
				dstDomains[host] = true
			}
			return true
		})
	}

	// Source 4: IPs/domains from findings already generated — catches anything
	// the log scans above might miss (e.g. synthetic DstIP values).
	a.mu.RLock()
	for _, f := range a.findings {
		dst := f.DstIP
		if dst == "" || isPrivateIP(dst) ||
			dst == "(network)" || dst == "(escalation)" || dst == "(cert)" {
			continue
		}
		if isIPAddr(dst) {
			dstIPs[dst] = true
		} else {
			dstDomains[dst] = true
		}
	}
	a.mu.RUnlock()

	type tiHit struct {
		dst    string
		source string
		detail string
		score  int
		sev    model.Severity
	}
	var hits []tiHit

	// Match against FeodoTracker
	for ip := range dstIPs {
		if feodoIPs[ip] {
			hits = append(hits, tiHit{
				dst:    ip,
				source: "FeodoTracker",
				detail: fmt.Sprintf("FeodoTracker botnet C2 IP: %s — Emotet/TrickBot/Dridex infrastructure", ip),
				score:  99,
				sev:    model.SevCritical,
			})
		}
	}

	// Match against URLhaus
	for ip := range dstIPs {
		if urlhausIPs[ip] {
			hits = append(hits, tiHit{
				dst:    ip,
				source: "URLhaus",
				detail: fmt.Sprintf("URLhaus malware distribution IP: %s", ip),
				score:  97,
				sev:    model.SevCritical,
			})
		}
	}
	for host := range dstDomains {
		if urlhausHosts[host] {
			hits = append(hits, tiHit{
				dst:    host,
				source: "URLhaus",
				detail: fmt.Sprintf("URLhaus malware distribution domain: %s", host),
				score:  97,
				sev:    model.SevCritical,
			})
		}
	}

	// OTX and AbuseIPDB require a client (only if keys are configured)
	client := &http.Client{Timeout: time.Duration(a.cfg.TITimeoutSec) * time.Second}

	// OTX — cap at 20 IPs
	if a.cfg.OTXAPIKey != "" && len(dstIPs) > 0 {
		ipList := mapKeys(dstIPs, 20)
		for _, ip := range ipList {
			detail, score := checkOTX(client, ip, a.cfg.OTXAPIKey)
			if detail != "" {
				sev := model.SevHigh
				if score >= 7 {
					sev = model.SevCritical
				}
				hits = append(hits, tiHit{
					dst: ip, source: "OTX",
					detail: detail,
					score:  int(math.Min(float64(70+score*3), 99)),
					sev:    sev,
				})
			}
		}
	}

	// AbuseIPDB — cap at 10 IPs
	if a.cfg.AbuseIPDBAPIKey != "" && len(dstIPs) > 0 {
		ipList := mapKeys(dstIPs, 10)
		for _, ip := range ipList {
			detail, score := checkAbuseIPDB(client, ip, a.cfg.AbuseIPDBAPIKey)
			if detail != "" {
				sev := model.SevHigh
				if score >= 80 {
					sev = model.SevCritical
				}
				hits = append(hits, tiHit{
					dst: ip, source: "AbuseIPDB",
					detail: detail,
					score:  int(math.Min(float64(50+score/5), 99)),
					sev:    sev,
				})
			}
		}
	}

	for _, h := range hits {
		a.add(model.Finding{
			Type:      "Threat Intel Hit",
			Severity:  h.sev,
			Score:     h.score,
			SrcIP:     "(TI)",
			DstIP:     h.dst,
			Detail:    h.detail,
			Timestamp: time.Now().UTC().Format("2006-01-02 15:04:05"),
			SourceFile: h.source,
		})
	}
}

func fetchFeodo(client *http.Client) map[string]bool {
	resp, err := client.Get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	ips := make(map[string]bool)
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips[line] = true
	}
	return ips
}

func fetchURLhaus(client *http.Client) (ips, hosts map[string]bool) {
	ips = make(map[string]bool)
	hosts = make(map[string]bool)
	// csv_online = only currently-active URLs (much smaller than full history)
	resp, err := client.Get("https://urlhaus.abuse.ch/downloads/csv_online/")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}
		// URL is in field index 2
		rawURL := strings.Trim(parts[2], `"`)
		// Extract host
		h := extractHost(rawURL)
		if h == "" {
			continue
		}
		if isIPAddr(h) {
			ips[h] = true
		} else {
			hosts[h] = true
		}
	}
	return
}

func checkOTX(client *http.Client, ip, apiKey string) (string, float64) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", ip)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-OTX-API-KEY", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	var data struct {
		PulseInfo struct {
			Count int `json:"count"`
		} `json:"pulse_info"`
	}
	if json.NewDecoder(resp.Body).Decode(&data) != nil {
		return "", 0
	}
	if data.PulseInfo.Count == 0 {
		return "", 0
	}
	return fmt.Sprintf("OTX: %d threat pulses for %s", data.PulseInfo.Count, ip), float64(data.PulseInfo.Count)
}

func checkAbuseIPDB(client *http.Client, ip, apiKey string) (string, float64) {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	var data struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			TotalReports         int    `json:"totalReports"`
			CountryCode          string `json:"countryCode"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&data) != nil {
		return "", 0
	}
	score := float64(data.Data.AbuseConfidenceScore)
	if score == 0 {
		return "", 0
	}
	return fmt.Sprintf("AbuseIPDB: confidence=%d%% reports=%d country=%s", data.Data.AbuseConfidenceScore, data.Data.TotalReports, data.Data.CountryCode), score
}

func isIPAddr(s string) bool {
	dots := strings.Count(s, ".")
	colons := strings.Count(s, ":")
	return dots == 3 || colons >= 2
}

func mapKeys(m map[string]bool, limit int) []string {
	out := make([]string, 0, limit)
	for k := range m {
		out = append(out, k)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func extractHost(rawURL string) string {
	// Strip scheme
	for _, scheme := range []string{"https://", "http://"} {
		if strings.HasPrefix(rawURL, scheme) {
			rawURL = rawURL[len(scheme):]
			break
		}
	}
	// Strip path
	if i := strings.Index(rawURL, "/"); i >= 0 {
		rawURL = rawURL[:i]
	}
	// Strip port
	if i := strings.LastIndex(rawURL, ":"); i >= 0 && !strings.Contains(rawURL[:i], ":") {
		rawURL = rawURL[:i]
	}
	return rawURL
}
