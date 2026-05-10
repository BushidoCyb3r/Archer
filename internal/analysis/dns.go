package analysis

import (
	"fmt"
	"math"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

// apexFromQuery extracts the registrable domain (eTLD+1) using the
// Mozilla Public Suffix List. Pre-fix the apex was the last two
// labels joined: that broke for multi-component eTLDs like .co.uk
// (bbc.co.uk → "co.uk"), .com.au (example.com.au → "com.au"),
// .ac.jp, .gov.cn etc., bucketing every subdomain under the public
// suffix and inflating the per-(src, apex) diversity counter past
// DNSUniqueSubdomainMin trivially in any non-US environment. The
// PSL gets it right and is the canonical answer maintained by
// Mozilla for exactly this purpose. Falls back to the simple
// last-two-labels heuristic on lookup failure (the input wasn't a
// recognised public name) since the alternative is dropping the
// query entirely and we'd rather over-count diversity than skip
// the record. Audited 2026-05-10.
func apexFromQuery(query string) string {
	q := strings.TrimSuffix(strings.TrimSpace(query), ".")
	if q == "" {
		return ""
	}
	if etld1, err := publicsuffix.EffectiveTLDPlusOne(q); err == nil {
		return etld1
	}
	labels := strings.Split(q, ".")
	if len(labels) < 2 {
		return q
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

func (a *Analyzer) analyzeDNS(files []string) {
	type apexKey struct{ src, apex string }
	type apexData struct {
		subs    map[string]bool
		firstTS float64
	}

	apexMap := make(map[apexKey]*apexData)
	nxCounts := make(map[string]int) // src → nxdomain count
	nxFirst := make(map[string]float64)
	seenTunnel := make(map[[2]string]bool)
	seenTLD := make(map[[2]string]bool)
	seenDoH := make(map[[2]string]bool)

	dnsFiles := filterFiles(files, "dns")
	for _, f := range dnsFiles {
		a.parseLog(f, func(rec map[string]any) bool {
			src := parser.GetStr(rec, "id.orig_h")
			dst := parser.GetStr(rec, "id.resp_h")
			query := strings.TrimRight(strings.ToLower(parser.GetStr(rec, "query")), ".")
			rcode := parser.GetStr(rec, "rcode_name")
			ts := parser.GetFloat(rec, "ts")

			if src == "" || query == "" {
				return true
			}

			// DoH Bypass: TLS to known resolver on port 443
			dstPort := parser.GetInt(rec, "id.resp_p")
			if dstPort == 443 && model.DoHIPs[dst] {
				key := [2]string{src, dst}
				if !seenDoH[key] {
					seenDoH[key] = true
					a.add(model.Finding{
						Type:       "DoH Bypass",
						Severity:   model.SevMedium,
						Score:      62,
						SrcIP:      src,
						DstIP:      dst,
						DstPort:    "443",
						Detail:     fmt.Sprintf("DNS-over-HTTPS to known resolver %s — evades DNS logging", dst),
						Timestamp:  fmtTS(ts),
						SourceFile: f,
					})
				}
			}

			// NXDOMAIN flood
			if rcode == "NXDOMAIN" {
				nxCounts[src]++
				// Guard nxFirst against a leading record with ts == 0
				// (missing field). Pre-fix any first record with ts == 0
				// poisoned nxFirst, and the subsequent ts < nxFirst
				// check then never fired for valid forward timestamps,
				// so the finding's Timestamp reported as empty even
				// when later records carried a real time. Audited
				// 2026-05-10. Same guard pattern apexMap[k].firstTS
				// already uses below.
				if ts > 0 && (nxFirst[src] == 0 || ts < nxFirst[src]) {
					nxFirst[src] = ts
				}
			}

			labels := strings.Split(query, ".")
			if len(labels) < 2 {
				return true
			}
			apex := apexFromQuery(query)
			if apex == "" {
				return true
			}

			// Suspicious TLD
			tld := "." + labels[len(labels)-1]
			if model.SuspiciousTLDs[tld] {
				key := [2]string{src, apex}
				if !seenTLD[key] {
					seenTLD[key] = true
					a.add(model.Finding{
						Type:       "Suspicious TLD",
						Severity:   model.SevMedium,
						Score:      52,
						SrcIP:      src,
						DstIP:      apex,
						DstPort:    "53",
						Detail:     fmt.Sprintf("TLD %q is a free/abused zone — query: %s", tld, query),
						Timestamp:  fmtTS(ts),
						SourceFile: f,
					})
				}
			}

			// Subdomain diversity tracking
			if len(labels) >= 3 {
				sub := strings.Join(labels[:len(labels)-2], ".")
				k := apexKey{src, apex}
				if apexMap[k] == nil {
					apexMap[k] = &apexData{subs: make(map[string]bool), firstTS: ts}
				}
				apexMap[k].subs[sub] = true
				if ts > 0 && (apexMap[k].firstTS == 0 || ts < apexMap[k].firstTS) {
					apexMap[k].firstTS = ts
				}
			}

			// Per-query DNS tunneling heuristics
			firstLabel := labels[0]
			isTunnel := false
			reasons := []string{}

			if len(firstLabel) >= a.cfg.DNSTunnelLabelLen {
				isTunnel = true
				reasons = append(reasons, fmt.Sprintf("long label (%d chars)", len(firstLabel)))
			}
			ent := shannonEntropy(firstLabel)
			if ent >= a.cfg.DNSTunnelEntropy {
				isTunnel = true
				reasons = append(reasons, fmt.Sprintf("high entropy (%.2f)", ent))
			}
			depth := strings.Count(query, ".")
			if depth >= a.cfg.DNSTunnelMinDepth {
				isTunnel = true
				reasons = append(reasons, fmt.Sprintf("deep nesting (%d levels)", depth))
			}
			// qtype TXT/NULL was previously a sole-fire signal here:
			// every TXT or NULL query produced a DNS Tunneling finding
			// (deduplicated per (src, apex)). That generated a false-
			// positive flood in any environment with mail (SPF, DKIM,
			// DMARC), TLS automation (ACME DNS-01 challenge), or any
			// SaaS that issues TXT-based domain-ownership tokens.
			// Genuine DNS tunnelers (iodine, dnscat2, Cobalt Strike's
			// DNS beacon) couple TXT/NULL with long, high-entropy, or
			// deep labels — exactly what the three signals above
			// already gate on. A pathological "tiny TXT-only tunnel"
			// using short low-entropy shallow labels is theoretically
			// possible but defeats the point of using DNS for
			// covert channel capacity in the first place. Audited
			// 2026-05-10 (deferred from v0.9.0); shipping the auditor's
			// recommended option of dropping the qtype-alone path
			// outright. If a real deployment surfaces a missed case,
			// the follow-up is a separate volume-based detector
			// (TODO 1f option C).

			if isTunnel {
				key := [2]string{src, apex}
				if !seenTunnel[key] {
					seenTunnel[key] = true
					score := clamp(int(math.Min(55+ent*6, 88)), 1, 95)
					a.add(model.Finding{
						Type:       "DNS Tunneling",
						Severity:   model.SevHigh,
						Score:      score,
						SrcIP:      src,
						DstIP:      apex,
						DstPort:    "53",
						Detail:     fmt.Sprintf("Tunnel indicators: %s | query: %s", strings.Join(reasons, ", "), query),
						Timestamp:  fmtTS(ts),
						SourceFile: f,
					})
				}
			}

			return true
		})
	}

	// ── NXDOMAIN flood ───────────────────────────────────────────────────────
	for src, count := range nxCounts {
		if count < a.cfg.DNSNXDomainThreshold {
			continue
		}
		score := clamp(int(45+math.Log10(float64(count))*15), 1, 85)
		a.add(model.Finding{
			Type:      "DNS NXDOMAIN Flood",
			Severity:  model.SevHigh,
			Score:     score,
			SrcIP:     src,
			DstIP:     "(network)",
			DstPort:   "53",
			Detail:    fmt.Sprintf("NXDOMAIN responses: %d (threshold: %d) — possible DGA", count, a.cfg.DNSNXDomainThreshold),
			Timestamp: fmtTS(nxFirst[src]),
		})
	}

	// ── Subdomain diversity ───────────────────────────────────────────────────
	for k, data := range apexMap {
		if len(data.subs) < a.cfg.DNSUniqueSubdomainMin {
			continue
		}
		sample := make([]float64, 0, len(data.subs))
		for s := range data.subs {
			sample = append(sample, shannonEntropy(s))
			if len(sample) >= 200 {
				break
			}
		}
		avgEnt := fmean(sample)
		sev := model.SevMedium
		if avgEnt > 3.0 {
			sev = model.SevHigh
		}
		score := clamp(int(math.Min(55+avgEnt*6, 90)), 1, 95)
		a.add(model.Finding{
			Type:      "DNS Tunneling",
			Severity:  sev,
			Score:     score,
			SrcIP:     k.src,
			DstIP:     k.apex,
			DstPort:   "53",
			Detail:    fmt.Sprintf("High subdomain diversity — apex: %s | Unique subdomains: %d | Avg entropy: %.2f", k.apex, len(data.subs), avgEnt),
			Timestamp: fmtTS(data.firstTS),
		})
	}
}
