package analysis

import (
	"fmt"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

// checkJA3TI scans ssl.log for JA3 fingerprints that match any enabled
// feed's JA3s bucket. Runs in Phase 3 alongside checkTI and checkFileHashes
// (depends on a.feedSources being populated by prefetchFeeds). One TI Hit
// (JA3) finding per (feedSource, ja3, src, dst) tuple — multiple sessions
// from the same client to the same server sharing the same JA3 collapse to
// one finding.
func (a *Analyzer) checkJA3TI(files []string) {
	if !a.anyFeedJA3s() {
		return
	}
	seen := make(map[[3]string]bool)
	for _, f := range filterFiles(files, "ssl") {
		a.parseLog(f, func(rec map[string]any) bool {
			ja3 := strings.ToLower(parser.GetStr(rec, "ja3"))
			if ja3 == "" {
				return true
			}
			src := parser.GetStr(rec, "id.orig_h")
			dst := parser.GetStr(rec, "id.resp_h")
			if src == "" || dst == "" {
				return true
			}
			ts := parser.GetFloat(rec, "ts")
			sni := parser.GetStr(rec, "server_name")
			portStr := fmt.Sprint(parser.GetInt(rec, "id.resp_p"))

			for _, fs := range a.feedSources {
				if !fs.JA3s[ja3] {
					continue
				}
				key := [3]string{fs.Source + "|" + ja3, src, dst}
				if seen[key] {
					continue
				}
				seen[key] = true
				feedName := strings.TrimPrefix(fs.Source, "feed:")
				detail := fmt.Sprintf("%s JA3 match: %s", feedName, ja3)
				if sni != "" {
					detail += " | SNI: " + sni
				}
				if tags := fs.Tags[ja3]; len(tags) > 0 {
					detail += " | tags: " + strings.Join(tags, ", ")
				}
				a.add(model.Finding{
					Type:       model.TypeTIHitJA3,
					Severity:   model.SevHigh,
					Score:      90,
					SrcIP:      src,
					DstIP:      dst,
					DstPort:    portStr,
					Detail:     detail,
					Timestamp:  fmtTS(ts),
					SourceFile: f,
				})
			}
			return true
		})
	}
}

// anyFeedJA3s is the cheap early-exit guard for checkJA3TI. Mirrors
// anyFeedDomains / anyFeedHashes in shape.
func (a *Analyzer) anyFeedJA3s() bool {
	for _, fs := range a.feedSources {
		if len(fs.JA3s) > 0 {
			return true
		}
	}
	return false
}

func (a *Analyzer) analyzeSSL(files []string) {
	seenJA3 := make(map[[3]string]bool)
	seenNoSNI := make(map[[3]string]bool)
	seenWeakTLS := make(map[[3]string]bool)
	seenDoH := make(map[[2]string]bool)

	sslFiles := filterFiles(files, "ssl")
	for _, f := range sslFiles {
		a.parseLog(f, func(rec map[string]any) bool {
			src := parser.GetStr(rec, "id.orig_h")
			dst := parser.GetStr(rec, "id.resp_h")
			dstPort := parser.GetInt(rec, "id.resp_p")
			uid := parser.GetStr(rec, "uid")
			ja3 := strings.ToLower(parser.GetStr(rec, "ja3"))
			// JA4 is opportunistic: stock Zeek ssl.log is ja3/ja3s, so
			// GetStr returns "" unless the sensor runs the JA4+ plugin.
			// An empty value is the normal case, not an error.
			ja4 := strings.ToLower(parser.GetStr(rec, "ja4"))
			sni := parser.GetStr(rec, "server_name")
			version := parser.GetStr(rec, "version")
			established := parser.GetBool(rec, "established")
			subject := parser.GetStr(rec, "subject")
			issuer := parser.GetStr(rec, "issuer")
			ts := parser.GetFloat(rec, "ts")

			if src == "" || dst == "" {
				return true
			}

			// Build SSL UID index for domain fronting detection in HTTP pass
			if uid != "" {
				a.mu.Lock()
				a.sslUIDIndex[uid] = sslEntry{
					serverName: sni,
					ja3:        ja3,
					ja4:        ja4,
					version:    version,
					subject:    subject,
					issuer:     issuer,
				}
				a.mu.Unlock()
			}

			portStr := fmt.Sprint(dstPort)

			// Malicious JA3
			if ja3 != "" {
				if label, bad := KnownBadJA3[ja3]; bad {
					key := [3]string{src, dst, ja3}
					if !seenJA3[key] {
						seenJA3[key] = true
						detail := fmt.Sprintf("JA3: %s — %s", ja3, label)
						if sni != "" {
							detail += " | SNI: " + sni
						}
						a.add(model.Finding{
							Type:       "Malicious JA3",
							Severity:   model.SevCritical,
							Score:      95,
							SrcIP:      src,
							DstIP:      dst,
							DstPort:    portStr,
							Detail:     detail,
							Timestamp:  fmtTS(ts),
							SourceFile: f,
						})
					}
				}
			}

			// Weak TLS version
			if WeakTLSVersions[version] {
				key := [3]string{src, dst, version}
				if !seenWeakTLS[key] {
					seenWeakTLS[key] = true
					a.add(model.Finding{
						Type:       "Weak TLS",
						Severity:   model.SevLow,
						Score:      48,
						SrcIP:      src,
						DstIP:      dst,
						DstPort:    portStr,
						Detail:     fmt.Sprintf("Deprecated TLS version: %s", version),
						Timestamp:  fmtTS(ts),
						SourceFile: f,
					})
				}
			}

			// DoH Bypass: TLS to a known public DoH resolver on port 443.
			// ssl.log is the correct source — DoH is an HTTPS session, not
			// a DNS transaction, so it never appears in dns.log.
			if dstPort == 443 && DoHIPs[dst] {
				key := [2]string{src, dst}
				if !seenDoH[key] {
					seenDoH[key] = true
					detail := fmt.Sprintf("DNS-over-HTTPS to known resolver %s — evades DNS logging", dst)
					if sni != "" {
						detail = fmt.Sprintf("DNS-over-HTTPS to known resolver %s (%s) — evades DNS logging", dst, sni)
					}
					a.add(model.Finding{
						Type:       "DoH Bypass",
						Severity:   model.SevMedium,
						Score:      62,
						SrcIP:      src,
						DstIP:      dst,
						DstPort:    portStr,
						Detail:     detail,
						Timestamp:  fmtTS(ts),
						SourceFile: f,
					})
				}
			}

			// No-SNI detections (established TLS, no server_name)
			if established && sni == "" {
				isC2Port := KnownC2Ports[dstPort] != ""
				key := [3]string{src, dst, portStr}
				if !seenNoSNI[key] {
					seenNoSNI[key] = true
					if isC2Port {
						a.add(model.Finding{
							Type:       "SSL No-SNI on C2 Port",
							Severity:   model.SevHigh,
							Score:      82,
							SrcIP:      src,
							DstIP:      dst,
							DstPort:    portStr,
							Detail:     fmt.Sprintf("Established TLS with no SNI on C2 port %d (%s)", dstPort, KnownC2Ports[dstPort]),
							Timestamp:  fmtTS(ts),
							SourceFile: f,
						})
					} else {
						a.add(model.Finding{
							Type:       "SSL No-SNI",
							Severity:   model.SevLow,
							Score:      35,
							SrcIP:      src,
							DstIP:      dst,
							DstPort:    portStr,
							Detail:     fmt.Sprintf("Established TLS with no SNI on port %d", dstPort),
							Timestamp:  fmtTS(ts),
							SourceFile: f,
						})
					}
				}
			}

			return true
		})
	}
}
