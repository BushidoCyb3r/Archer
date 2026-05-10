package analysis

import (
	"fmt"
	"sort"
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
	// tsData feeds the Beacon Chart's Timeline / Interval / Bytes views.
	// Reservoir-sampled (ts, origBytes, respBytes) triples — same shape
	// the conn-level beacon detector emits, capped at beaconTsCap.
	tsData  [][3]float64
	tsSeen  int
	hourMap map[int]int
	minTs   float64
	maxTs   float64
	firstTs float64
}

func csChecksum8(uri string) int {
	sum := 0
	for _, c := range uri {
		sum += int(c)
	}
	return sum % 256
}

func (a *Analyzer) analyzeHTTP(files []string) {
	type beaconKey struct{ sensor, src, dst, host, uri string }
	beaconCounts := make(map[beaconKey]int)
	beacon := make(map[beaconKey]*httpBeaconState)

	// Pre-allocation timestamp stash. See conn.go's preBeaconTs for the
	// reasoning — connections 1 and 2 of each pair would otherwise lose
	// their intervals to the lazy-init guard.
	preBeaconTs := make(map[beaconKey][]float64)

	seenUA := make(map[[2]string]bool)
	seenCS := make(map[[3]string]bool)
	seenDF := make(map[[2]string]bool)
	seenFile := make(map[[2]string]bool)

	// Per-sensor windows for HTTP-beacon scoring. analyzeHTTP runs in
	// phase 2 after analyzeConn has already populated a.sensorWindows
	// for every sensor that has conn.log records, but a sensor with
	// only http.log (no conn.log) wouldn't otherwise get a window.
	// Accumulate locally and merge so the HTTP-only case stays sound.
	localWindows := map[string]sensorWindow{}

	httpFiles := filterFiles(files, "http")
	for _, f := range httpFiles {
		sensor := a.sensorOf(f)
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
			respB := parser.GetFloat(rec, "resp_ip_bytes")
			ts := parser.GetFloat(rec, "ts")

			if src == "" {
				return true
			}

			if ts > 0 {
				w := localWindows[sensor]
				if w.min == 0 || ts < w.min {
					w.min = ts
				}
				if ts > w.max {
					w.max = ts
				}
				localWindows[sensor] = w
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
				bk := beaconKey{sensor, src, dst, host, uri}
				beaconCounts[bk]++
				if beaconCounts[bk] < beaconLazyMinConn {
					if ts > 0 {
						preBeaconTs[bk] = append(preBeaconTs[bk], ts)
					}
				} else {
					st := beacon[bk]
					if st == nil {
						st = &httpBeaconState{
							hourMap: make(map[int]int),
							firstTs: ts,
							minTs:   ts,
							maxTs:   ts,
						}
						// Replay stashed pre-state timestamps so intervals
						// 1→2 and 2→3 land in the reservoir.
						if early := preBeaconTs[bk]; len(early) > 0 {
							for _, ets := range early {
								if st.lastTs > 0 && ets > st.lastTs {
									iv := ets - st.lastTs
									st.ivs, st.ivsSeen = reservoirAddF(st.ivs, st.ivsSeen, iv, beaconIvCap)
								}
								st.lastTs = ets
							}
							delete(preBeaconTs, bk)
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
					// Per-event triple feeds the Beacon Chart. Reservoir
					// sample to bound memory at beaconTsCap regardless of
					// how many requests this (src, dst, host, uri) pair
					// generates.
					st.tsData, st.tsSeen = reservoirAddT(st.tsData, st.tsSeen, [3]float64{ts, origB, respB}, beaconTsCap)
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

	// Merge per-sensor windows accumulated above into the analyzer-wide
	// map, then read snapshots for HTTP-beacon scoring. Conn analyzer
	// already populated entries for sensors with conn.log records;
	// HTTP-only sensors land here.
	a.mu.Lock()
	for s, w := range localWindows {
		aw := a.sensorWindows[s]
		if aw.min == 0 || w.min < aw.min {
			aw.min = w.min
		}
		if w.max > aw.max {
			aw.max = w.max
		}
		a.sensorWindows[s] = aw
	}
	a.mu.Unlock()

	// ── HTTP Beaconing ────────────────────────────────────────────────────────
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
		if mm := intervalMultimodalScore(ivs); mm > tsScore {
			tsScore = mm
		}
		dsScore := 0.0
		if len(byteVals) >= 3 {
			dsScore = statisticalScore(byteVals, 0.0)
		}
		// Hist + duration score against this beacon's sensor's capture
		// window — not a global union across all /logs/ trees.
		w := a.windowOf(bk.sensor)
		hScore, _ := histScoreFromHourMap(st.hourMap, w.min, w.max)
		durScore := durationScoreFromHourMap(st.hourMap, st.minTs, st.maxTs, w.min, w.max, 6)

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

		tsData := make([][3]float64, len(st.tsData))
		copy(tsData, st.tsData)
		sort.Slice(tsData, func(i, j int) bool { return tsData[i][0] < tsData[j][0] })

		a.add(model.Finding{
			Type:      "HTTP Beaconing",
			Severity:  sev,
			Score:     score,
			SrcIP:     bk.src,
			DstIP:     bk.dst,
			Detail:    fmt.Sprintf("Requests: %d | Host: %s | URI: %s | Score: ts=%.2f ds=%.2f hist=%.2f dur=%.2f", totalObserved, bk.host, bk.uri, tsScore, dsScore, hScore, durScore),
			Timestamp: fmtTS(st.firstTs),
			TSData:    tsData,
		})
	}
}
