package analysis

import (
	"fmt"
	"math"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

func (a *Analyzer) analyzeDNS(files []string) {
	type apexKey struct{ src, apex string }
	type apexData struct {
		subs    map[string]bool
		firstTS float64
	}

	apexMap := make(map[apexKey]*apexData)
	nxCounts := make(map[string]int) // src → nxdomain count
	nxFirst := make(map[string]float64)
	seenPerQuery := make(map[[2]string]bool)
	seenTLD := make(map[[2]string]bool)
	seenDoH := make(map[[2]string]bool)

	dnsFiles := filterFiles(files, "dns")
	for _, f := range dnsFiles {
		_ = parser.ParseLog(f, func(rec map[string]any) bool {
			src := parser.GetStr(rec, "id.orig_h")
			dst := parser.GetStr(rec, "id.resp_h")
			query := strings.TrimRight(strings.ToLower(parser.GetStr(rec, "query")), ".")
			qtype := parser.GetStr(rec, "qtype_name")
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
				if nxCounts[src] == 1 || ts < nxFirst[src] {
					nxFirst[src] = ts
				}
			}

			labels := strings.Split(query, ".")
			if len(labels) < 2 {
				return true
			}
			apex := strings.Join(labels[len(labels)-2:], ".")

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
			if qtype == "TXT" || qtype == "NULL" {
				isTunnel = true
				reasons = append(reasons, fmt.Sprintf("qtype=%s", qtype))
			}

			if isTunnel {
				key := [2]string{src, apex}
				if !seenPerQuery[key] {
					seenPerQuery[key] = true
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
