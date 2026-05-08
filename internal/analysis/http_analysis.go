package analysis

import (
	"fmt"
	"math"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

type httpBeaconState struct {
	total    int
	lastTs   float64
	ivs      []float64
	ivsSeen  int
	byteVals []float64
	byteSeen int
	hourMap  map[int]int
	minTs    float64
	maxTs    float64
	firstTs  float64
}

func csChecksum8(uri string) int {
	sum := 0
	for _, c := range uri {
		sum += int(c)
	}
	return sum % 256
}

func (a *Analyzer) analyzeHTTP(files []string) {
	type beaconKey struct{ src, dst, host, uri string }
	beaconCounts := make(map[beaconKey]int)
	beacon := make(map[beaconKey]*httpBeaconState)

	seenUA := make(map[[2]string]bool)
	seenCS := make(map[[3]string]bool)
	seenDF := make(map[[2]string]bool)
	seenFile := make(map[[2]string]bool)

	httpFiles := filterFiles(files, "http")
	for _, f := range httpFiles {
		_ = parser.ParseLog(f, func(rec map[string]any) bool {
			src := parser.GetStr(rec, "id.orig_h")
			dst := parser.GetStr(rec, "id.resp_h")
			dstPort := parser.GetInt(rec, "id.resp_p")
			uid := parser.GetStr(rec, "uid")
			method := parser.GetStr(rec, "method")
			host := parser.GetStr(rec, "host")
			uri := parser.GetStr(rec, "uri")
			ua := strings.ToLower(parser.GetStr(rec, "user_agent"))
			respMime := strings.ToLower(parser.GetStr(rec, "resp_mime_types"))
			origB := parser.GetFloat(rec, "orig_ip_bytes")
			ts := parser.GetFloat(rec, "ts")

			if src == "" {
				return true
			}

			portStr := fmt.Sprint(dstPort)

			// Suspicious UA
			for _, pat := range model.SuspiciousUAPatterns {
				if strings.Contains(ua, strings.ToLower(pat)) {
					key := [2]string{src, pat}
					if !seenUA[key] {
						seenUA[key] = true
						a.add(model.Finding{
							Type:       "Suspicious UA",
							Severity:   model.SevLow,
							Score:      30,
							SrcIP:      src,
							DstIP:      dst,
							DstPort:    portStr,
							Detail:     fmt.Sprintf("Scripting/automation UA: %q | Host: %s", ua, host),
							Timestamp:  fmtTS(ts),
							SourceFile: f,
						})
					}
					break
				}
			}

			// Cobalt Strike URI checksum8 + C2 URI patterns
			if uri != "" && len(uri) > 1 {
				cs8 := csChecksum8(uri)
				if cs8 == 92 || cs8 == 93 {
					variant := "x86"
					if cs8 == 93 {
						variant = "x64"
					}
					key := [3]string{src, dst, uri}
					if !seenCS[key] {
						seenCS[key] = true
						a.add(model.Finding{
							Type:       "Cobalt Strike URI",
							Severity:   model.SevCritical,
							Score:      93,
							SrcIP:      src,
							DstIP:      dst,
							DstPort:    portStr,
							Detail:     fmt.Sprintf("CS checksum8 match (%s) — URI: %s | Host: %s | Checksum=%d", variant, uri, host, cs8),
							Timestamp:  fmtTS(ts),
							SourceFile: f,
						})
					}
				} else {
					for _, pat := range model.C2URIPatterns {
						if pat.Re.MatchString(uri) {
							key := [3]string{src, dst, uri}
							if !seenCS[key] {
								seenCS[key] = true
								a.add(model.Finding{
									Type:       "C2 URI Pattern",
									Severity:   model.SevCritical,
									Score:      91,
									SrcIP:      src,
									DstIP:      dst,
									DstPort:    portStr,
									Detail:     fmt.Sprintf("%s — URI: %s | Host: %s | Method: %s", pat.Label, uri, host, method),
									Timestamp:  fmtTS(ts),
									SourceFile: f,
								})
							}
							break
						}
					}
				}
			}

			// Domain Fronting: SSL SNI != HTTP Host header
			if uid != "" && host != "" {
				a.mu.RLock()
				ssl, hasSSL := a.sslUIDIndex[uid]
				a.mu.RUnlock()
				if hasSSL && ssl.serverName != "" && ssl.serverName != host {
					key := [2]string{src, uid}
					if !seenDF[key] {
						seenDF[key] = true
						a.add(model.Finding{
							Type:       "Domain Fronting",
							Severity:   model.SevCritical,
							Score:      88,
							SrcIP:      src,
							DstIP:      dst,
							DstPort:    portStr,
							Detail:     fmt.Sprintf("SSL SNI: %q ≠ HTTP Host: %q — CDN-based domain fronting", ssl.serverName, host),
							Timestamp:  fmtTS(ts),
							SourceFile: f,
						})
					}
				}
			}

			// Suspicious File Download
			isSuspicious := false
			suspReason := ""
			if respMime != "" {
				for mime := range model.SuspiciousMIMETypes {
					if strings.Contains(respMime, mime) {
						isSuspicious = true
						suspReason = fmt.Sprintf("MIME: %s", respMime)
						break
					}
				}
			}
			if !isSuspicious && uri != "" {
				for ext := range model.SuspiciousFileExts {
					if strings.HasSuffix(strings.ToLower(uri), ext) {
						isSuspicious = true
						suspReason = fmt.Sprintf("extension: %s", ext)
						break
					}
				}
			}
			if isSuspicious {
				key := [2]string{src, uri}
				if !seenFile[key] {
					seenFile[key] = true
					a.add(model.Finding{
						Type:       "Suspicious File Download",
						Severity:   model.SevHigh,
						Score:      72,
						SrcIP:      src,
						DstIP:      dst,
						DstPort:    portStr,
						Detail:     fmt.Sprintf("%s | URI: %s | Host: %s", suspReason, uri, host),
						Timestamp:  fmtTS(ts),
						SourceFile: f,
					})
				}
			}

			// HTTP Beaconing: group by (src, dst, host, uri).
			// Lazy-create per-key state after a minimum count to keep
			// high-cardinality low-count keys at O(1) memory.
			if uri != "" && host != "" {
				bk := beaconKey{src, dst, host, uri}
				beaconCounts[bk]++
				if beaconCounts[bk] >= beaconLazyMinConn {
					st := beacon[bk]
					if st == nil {
						st = &httpBeaconState{
							hourMap: make(map[int]int),
							firstTs: ts,
							minTs:   ts,
							maxTs:   ts,
						}
						beacon[bk] = st
					}
					st.total++
					if ts < st.minTs {
						st.minTs = ts
					}
					if ts > st.maxTs {
						st.maxTs = ts
					}
					if st.lastTs > 0 && ts > st.lastTs {
						iv := ts - st.lastTs
						st.ivs, st.ivsSeen = reservoirAddF(st.ivs, st.ivsSeen, iv, beaconIvCap)
					}
					st.lastTs = ts
					if origB > 0 {
						st.byteVals, st.byteSeen = reservoirAddF(st.byteVals, st.byteSeen, origB, beaconByteCap)
					}
					if ts > 0 {
						st.hourMap[int(ts)/3600]++
					}
				}
			}

			// Store HTTP UID index for potential use
			if uid != "" {
				a.mu.Lock()
				a.httpUIDIndex[uid] = httpEntry{
					method: method, host: host, uri: uri, userAgent: ua,
				}
				a.mu.Unlock()
			}

			return true
		})
	}

	// ── HTTP Beaconing ────────────────────────────────────────────────────────
	a.mu.RLock()
	dsMin := a.datasetMin
	dsMax := a.datasetMax
	a.mu.RUnlock()
	if dsMin == math.MaxFloat64 {
		dsMin = 0
	}

	for bk, st := range beacon {
		totalObserved := beaconCounts[bk]
		if totalObserved < a.cfg.HTTPBeaconMinRequests {
			continue
		}
		if len(st.ivs) < 3 {
			continue
		}

		ivs := make([]float64, len(st.ivs))
		copy(ivs, st.ivs)
		byteVals := make([]float64, len(st.byteVals))
		copy(byteVals, st.byteVals)

		tsScore := statisticalScore(ivs, 1.0)
		dsScore := 0.0
		if len(byteVals) >= 3 {
			dsScore = statisticalScore(byteVals, 0.0)
		}
		hScore, _ := histScoreFromHourMap(st.hourMap, dsMin, dsMax)
		durScore := durationScoreFromHourMap(st.hourMap, st.minTs, st.maxTs, dsMin, dsMax, 6)

		score := int(100 * (tsScore*0.25 + dsScore*0.25 + hScore*0.25 + durScore*0.25))
		if score < 1 {
			continue
		}
		score = clamp(score, 1, 100)

		var sev model.Severity
		if score >= 80 {
			sev = model.SevCritical
		} else {
			sev = model.SevHigh
		}

		a.add(model.Finding{
			Type:      "HTTP Beaconing",
			Severity:  sev,
			Score:     score,
			SrcIP:     bk.src,
			DstIP:     bk.dst,
			Detail:    fmt.Sprintf("Requests: %d | Host: %s | URI: %s | Score: ts=%.2f ds=%.2f hist=%.2f dur=%.2f", totalObserved, bk.host, bk.uri, tsScore, dsScore, hScore, durScore),
			Timestamp: fmtTS(st.firstTs),
		})
	}
}
