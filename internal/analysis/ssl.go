package analysis

import (
	"fmt"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

func (a *Analyzer) analyzeSSL(files []string) {
	seenJA3 := make(map[[3]string]bool)
	seenJA4 := make(map[[3]string]bool)
	seenNoSNI := make(map[[3]string]bool)
	seenWeakTLS := make(map[[3]string]bool)
	seenDoH := make(map[[2]string]bool)

	// Per-fingerprint prevalence over every TLS connection in this pass.
	// Accumulated locally (the sslFiles loop is sequential) and published to
	// the analyzer once, below, for enrichBeaconSNI to read after the wg1 barrier.
	localJA4 := make(map[string]*fpStat)
	localJA3 := make(map[string]*fpStat)

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

			// Fingerprint prevalence (all TLS, not just emitted beacons).
			if ja4 != "" {
				fpAdd(localJA4, ja4, src, dst)
			}
			if ja3 != "" {
				fpAdd(localJA3, ja3, src, dst)
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
				if label, bad := a.badJA3(ja3); bad {
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
							JA3:        ja3,
						})
					}
				}
			}

			// Malicious JA4
			if ja4 != "" {
				if label, bad := a.badJA4(ja4); bad {
					key := [3]string{src, dst, ja4}
					if !seenJA4[key] {
						seenJA4[key] = true
						detail := fmt.Sprintf("JA4: %s — %s", ja4, label)
						if sni != "" {
							detail += " | SNI: " + sni
						}
						a.add(model.Finding{
							Type:       "Malicious JA4",
							Severity:   model.SevCritical,
							Score:      95,
							SrcIP:      src,
							DstIP:      dst,
							DstPort:    portStr,
							Detail:     detail,
							Timestamp:  fmtTS(ts),
							SourceFile: f,
							JA4:        ja4,
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

	a.mu.Lock()
	a.fpJA4 = localJA4
	a.fpJA3 = localJA3
	a.mu.Unlock()
}
