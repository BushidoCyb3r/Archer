package analysis

import (
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

// Reservoir caps keep per-pair beacon state at O(1) memory regardless of
// record count. Algorithm R sampling preserves an unbiased random sample of
// the underlying stream, so Bowley/MAD regularity scores remain valid.
const (
	beaconIvCap       = 1000
	beaconByteCap     = 1000
	beaconTsCap       = 200
	beaconLazyMinConn = 3
)

type pairKey struct{ sensor, src, dst string }
type strobeKey struct{ src, dst string }
type exfilKey struct{ src, dst string }
type offKey struct{ src, dst string }

// preBeaconRec captures the full per-connection contribution that the
// lazy-init replay path has to back-fill into beaconState. Stashing
// only ts (the v0.8.0 fix) under-replayed: the timing axis got
// rescued but byteVals (size axis), hourMap (histogram), tsData
// (chart), and firstTs/minTs (duration coverage) still saw conn 3
// as the start of the beacon. For a pair right at
// BeaconMinConnections=10, that's 20% of the data fidelity missing.
// Audited 2026-05-10. The struct is small enough that stashing two
// of them per pre-allocation pair is well below the original lazy-
// init memory budget.
type preBeaconRec struct {
	ts    float64
	origB float64
	respB float64
}

type beaconState struct {
	lastTs     float64
	ivs        []float64
	ivsSeen    int
	byteVals   []float64
	byteSeen   int
	tsData     [][3]float64
	tsSeen     int
	hourMap    map[int]int // absolute hour index → count
	minTs      float64
	maxTs      float64
	firstTs    float64
	firstPort  int
	firstProto string
}

func (a *Analyzer) analyzeConn(files []string) {
	connFiles := filterFiles(files, "conn")

	// Off-hours window is interpreted in the operator's configured timezone.
	// Empty Timezone or an unparseable IANA name falls back to UTC so a bad
	// config doesn't disable detection — failing closed (UTC default) is
	// preferable to failing open (no off-hours detection at all).
	offHoursLoc := time.UTC
	if a.cfg.Timezone != "" {
		if loc, err := time.LoadLocation(a.cfg.Timezone); err == nil {
			offHoursLoc = loc
		}
	}

	pairCounts := make(map[pairKey]int)
	beacon := make(map[pairKey]*beaconState)

	// Connections 1 and 2 of each pair are stashed here so their
	// full contribution (ts, bytes, chart triple, hour bucket,
	// firstTs/minTs window) can be replayed when state allocation
	// finally happens at connection 3. Pre-v0.8.1 only ts was
	// stashed and only the timing-axis interval reservoir was
	// replayed — every other dimension under-counted by 2 records
	// out of N. Audited 2026-05-10.
	preBeaconRecs := make(map[pairKey][]preBeaconRec)

	strobeCounts := make(map[strobeKey]int)
	strobeFirst := make(map[strobeKey]float64)
	exfilOrig := make(map[exfilKey]float64)
	exfilResp := make(map[exfilKey]float64)
	exfilFirst := make(map[exfilKey]float64)
	offBytes := make(map[offKey]float64)
	offFirst := make(map[offKey]float64)

	lateralSeen := make(map[string]struct{})
	c2Seen := make(map[string]struct{})

	// Per-sensor capture windows — drives histogram + duration scoring
	// for beacons in this analyzer pass. Accumulated locally to avoid
	// taking a.mu per record; merged into a.sensorWindows once at the
	// end of the file loop.
	localWindows := map[string]sensorWindow{}

	// Conn files are processed sequentially so per-pair interval math stays
	// ordering-correct without cross-goroutine coordination. Coarse phase-1
	// parallelism (7 analyzers in parallel) is preserved at the Analyze level.
	for _, path := range connFiles {
		if a.ctx.Err() != nil {
			break
		}
		if !a.waitIfPaused() {
			break
		}

		sensor := a.sensorOf(path)

		a.parseLog(path, func(rec map[string]any) bool {
			src := parser.GetStr(rec, "id.orig_h")
			dst := parser.GetStr(rec, "id.resp_h")
			if src == "" || dst == "" {
				return true
			}
			ts := parser.GetFloat(rec, "ts")
			dur := parser.GetFloat(rec, "duration")
			origB := parser.GetFloat(rec, "orig_bytes")
			if origB == 0 {
				origB = parser.GetFloat(rec, "orig_ip_bytes")
			}
			respB := parser.GetFloat(rec, "resp_bytes")
			if respB == 0 {
				respB = parser.GetFloat(rec, "resp_ip_bytes")
			}
			dstPort := parser.GetInt(rec, "id.resp_p")
			proto := parser.GetStr(rec, "proto")

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

			sk := strobeKey{src, dst}
			strobeCounts[sk]++
			if ts > 0 && (strobeFirst[sk] == 0 || ts < strobeFirst[sk]) {
				strobeFirst[sk] = ts
			}
			ek := exfilKey{src, dst}
			exfilOrig[ek] += origB
			exfilResp[ek] += respB
			if ts > 0 && (exfilFirst[ek] == 0 || ts < exfilFirst[ek]) {
				exfilFirst[ek] = ts
			}

			if ts > 0 && !isPrivateIP(dst) {
				hour := time.Unix(int64(ts), 0).In(offHoursLoc).Hour()
				var offHours bool
				if a.cfg.OffHoursStart > a.cfg.OffHoursEnd {
					offHours = hour >= a.cfg.OffHoursStart || hour < a.cfg.OffHoursEnd
				} else {
					offHours = hour >= a.cfg.OffHoursStart && hour < a.cfg.OffHoursEnd
				}
				if offHours && origB > 0 {
					ok2 := offKey{src, dst}
					offBytes[ok2] += origB
					if offFirst[ok2] == 0 || ts < offFirst[ok2] {
						offFirst[ok2] = ts
					}
				}
			}

			hours := dur / 3600.0
			if hours >= a.cfg.LongConnMinHours {
				score := clamp(int(50+hours/8), 1, 95)
				var sev model.Severity
				if hours > 24 {
					sev = model.SevHigh
				} else {
					sev = model.SevMedium
				}
				a.add(model.Finding{
					Type:       "Long Connection",
					Severity:   sev,
					Score:      score,
					SrcIP:      src,
					DstIP:      dst,
					DstPort:    fmt.Sprint(dstPort),
					Detail:     fmt.Sprintf("Duration: %.2f hours | Proto: %s", hours, proto),
					Timestamp:  fmtTS(ts),
					SourceFile: path,
				})
			}

			if isPrivateIP(src) && isPrivateIP(dst) && model.LateralMovementPorts[dstPort] {
				lk := fmt.Sprintf("%s→%s:%d", src, dst, dstPort)
				if _, ok := lateralSeen[lk]; !ok {
					lateralSeen[lk] = struct{}{}
					a.add(model.Finding{
						Type:       "Lateral Movement",
						Severity:   model.SevHigh,
						Score:      78,
						SrcIP:      src,
						DstIP:      dst,
						DstPort:    fmt.Sprint(dstPort),
						Detail:     fmt.Sprintf("Internal→Internal on port %d (%s)", dstPort, lateralPortLabel(dstPort)),
						Timestamp:  fmtTS(ts),
						SourceFile: path,
					})
				}
			}

			if !isPrivateIP(dst) {
				if label, ok := model.KnownC2Ports[dstPort]; ok {
					ck := fmt.Sprintf("%s→%s:%d", src, dst, dstPort)
					if _, ok2 := c2Seen[ck]; !ok2 {
						c2Seen[ck] = struct{}{}
						a.add(model.Finding{
							Type:       "C2 Port",
							Severity:   model.SevHigh,
							Score:      75,
							SrcIP:      src,
							DstIP:      dst,
							DstPort:    fmt.Sprint(dstPort),
							Detail:     fmt.Sprintf("Port %d — %s", dstPort, label),
							Timestamp:  fmtTS(ts),
							SourceFile: path,
						})
					}
				}
			}

			pk := pairKey{sensor, src, dst}
			pairCounts[pk]++
			if pairCounts[pk] < beaconLazyMinConn {
				preBeaconRecs[pk] = append(preBeaconRecs[pk], preBeaconRec{ts: ts, origB: origB, respB: respB})
				return true
			}
			st := beacon[pk]
			if st == nil {
				st = &beaconState{
					hourMap:    make(map[int]int),
					firstTs:    ts,
					firstPort:  dstPort,
					firstProto: proto,
					minTs:      ts,
					maxTs:      ts,
				}
				// Replay every dimension that conns 1 and 2 contributed
				// to: timing intervals, byte-size samples, chart triples,
				// hour buckets, and the firstTs/minTs window. Pre-v0.8.1
				// the replay only touched intervals; firstTs reported
				// conn 3's timestamp (analyst chasing "when did this
				// start" got the wrong answer), the duration-coverage
				// span was 2 connections too narrow, and byteVals/
				// hourMap/tsData were computed on N-2 samples while the
				// finding still claimed N. Audited 2026-05-10.
				for _, e := range preBeaconRecs[pk] {
					if e.ts > 0 {
						if st.firstTs == 0 || e.ts < st.firstTs {
							st.firstTs = e.ts
						}
						if st.minTs == 0 || e.ts < st.minTs {
							st.minTs = e.ts
						}
						if e.ts > st.maxTs {
							st.maxTs = e.ts
						}
					}
					if e.ts > st.lastTs {
						if st.lastTs > 0 {
							iv := e.ts - st.lastTs
							st.ivs, st.ivsSeen = reservoirAddF(st.ivs, st.ivsSeen, iv, beaconIvCap)
						}
						st.lastTs = e.ts
					}
					if e.origB > 0 {
						st.byteVals, st.byteSeen = reservoirAddF(st.byteVals, st.byteSeen, e.origB, beaconByteCap)
					}
					st.tsData, st.tsSeen = reservoirAddT(st.tsData, st.tsSeen, [3]float64{e.ts, e.origB, e.respB}, beaconTsCap)
					if e.ts > 0 {
						st.hourMap[int(e.ts)/3600]++
					}
				}
				delete(preBeaconRecs, pk)
				beacon[pk] = st
			}
			if ts < st.minTs {
				st.minTs = ts
			}
			if ts > st.maxTs {
				st.maxTs = ts
			}
			// Only advance lastTs when the new record moves forward.
			// Pre-fix the assignment was unconditional, so an
			// out-of-order record (multi-sensor clock drift, conn
			// close-time logging at high load) would rewind lastTs
			// backward. The next valid forward record then computed
			// its interval against the rewound timestamp, sampling an
			// inflated bogus value into the reservoir. Audited
			// 2026-05-10.
			if ts > st.lastTs {
				if st.lastTs > 0 {
					iv := ts - st.lastTs
					st.ivs, st.ivsSeen = reservoirAddF(st.ivs, st.ivsSeen, iv, beaconIvCap)
				}
				st.lastTs = ts
			}
			if origB > 0 {
				st.byteVals, st.byteSeen = reservoirAddF(st.byteVals, st.byteSeen, origB, beaconByteCap)
			}
			st.tsData, st.tsSeen = reservoirAddT(st.tsData, st.tsSeen, [3]float64{ts, origB, respB}, beaconTsCap)
			if ts > 0 {
				st.hourMap[int(ts)/3600]++
			}

			return true
		})
	}

	// Merge per-sensor windows accumulated above into the analyzer-wide
	// map. Phase 2 (analyzeHTTP) reads these for HTTP-beacon scoring.
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

	// ── Beaconing ────────────────────────────────────────────────────────────
	for pk, st := range beacon {
		totalObserved := pairCounts[pk]
		if totalObserved < a.cfg.BeaconMinConnections {
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
		// Multimodal augmentation: rescue beacons whose intervals
		// cluster around 2-4 distinct values (heartbeat + tasking,
		// idle + active, etc.) — those would otherwise be penalised
		// by Bowley + MAD on the raw distribution. max() so
		// single-mode beacons (where the helper returns 0) are
		// unaffected.
		if mm := intervalMultimodalScore(ivs); mm > tsScore {
			tsScore = mm
		}
		// Entropy augmentation: rescue jittered single-mode beacons
		// where MAD looks bad but every interval still lands in the
		// same one or two log2 buckets. Orthogonal to the other two
		// timing-axis paths.
		if eh := intervalEntropyScore(ivs); eh > tsScore {
			tsScore = eh
		}
		dsScore := 0.0
		if len(byteVals) >= 3 {
			dsScore = statisticalScore(byteVals, 0.0)
		}
		// Hist + duration are scored against this pair's sensor's
		// capture window — not a global union across all /logs/ trees.
		// Cross-sensor smearing was the bug fixed here.
		w := localWindows[pk.sensor]
		hScore, _ := histScoreFromHourMap(st.hourMap, w.min, w.max)
		durScore := durationScoreFromHourMap(st.hourMap, st.minTs, st.maxTs, w.min, w.max, 6)

		score := clamp(int(100*(tsScore*0.25+dsScore*0.25+hScore*0.25+durScore*0.25)), 1, 100)
		if score < 1 {
			continue
		}

		var sev model.Severity
		if score >= 80 {
			sev = model.SevCritical
		} else {
			sev = model.SevHigh
		}

		ivMean := fmean(ivs)
		ivCV := 0.0
		if ivMean > 0 {
			variance := 0.0
			for _, v := range ivs {
				d := v - ivMean
				variance += d * d
			}
			ivCV = math.Sqrt(variance/float64(len(ivs))) / ivMean
		}

		tsData := make([][3]float64, len(st.tsData))
		copy(tsData, st.tsData)
		sort.Slice(tsData, func(i, j int) bool { return tsData[i][0] < tsData[j][0] })

		a.add(model.Finding{
			Type:      "Beaconing",
			Severity:  sev,
			Score:     score,
			SrcIP:     pk.src,
			DstIP:     pk.dst,
			DstPort:   fmt.Sprint(st.firstPort),
			Detail:    fmt.Sprintf("Connections: %d | Mean interval: %.1fs | CV: %.2f | Score components: ts=%.2f ds=%.2f hist=%.2f dur=%.2f", totalObserved, ivMean, ivCV, tsScore, dsScore, hScore, durScore),
			Timestamp: fmtTS(st.firstTs),
			TSData:    tsData,
		})
	}

	// ── Strobe ───────────────────────────────────────────────────────────────
	for sk, count := range strobeCounts {
		if count < a.cfg.StrobeMinConnections {
			continue
		}
		score := clamp(int(50+math.Log10(float64(count))*15), 1, 88)
		a.add(model.Finding{
			Type:      "Strobe",
			Severity:  model.SevHigh,
			Score:     score,
			SrcIP:     sk.src,
			DstIP:     sk.dst,
			Detail:    fmt.Sprintf("Connection count: %d (threshold: %d)", count, a.cfg.StrobeMinConnections),
			Timestamp: fmtTS(strobeFirst[sk]),
		})
	}

	// ── Data Exfiltration ────────────────────────────────────────────────────
	for ek, origB := range exfilOrig {
		if isPrivateIP(ek.dst) {
			continue
		}
		respB := exfilResp[ek]
		mb := origB / 1e6
		if mb < a.cfg.ExfilMinBytesMB {
			continue
		}
		ratio := 0.0
		if respB > 0 {
			ratio = origB / respB
		} else if origB > 0 {
			ratio = a.cfg.ExfilRatioThreshold + 1
		}
		if ratio < a.cfg.ExfilRatioThreshold {
			continue
		}
		score := clamp(int(55+math.Log10(mb+1)*12), 1, 92)
		a.add(model.Finding{
			Type:      "Data Exfiltration",
			Severity:  model.SevCritical,
			Score:     score,
			SrcIP:     ek.src,
			DstIP:     ek.dst,
			Detail:    fmt.Sprintf("Outbound: %.2f MB | Ratio out/in: %.1f (threshold: %.1f)", mb, ratio, a.cfg.ExfilRatioThreshold),
			Timestamp: fmtTS(exfilFirst[ek]),
		})
	}

	// ── Off-Hours Transfer ───────────────────────────────────────────────────
	for ok2, bytes := range offBytes {
		mb := bytes / 1e6
		if mb < a.cfg.OffHoursMinMB {
			continue
		}
		score := clamp(int(45+math.Log10(mb+1)*12), 1, 78)
		ts := offFirst[ok2]
		tzAtTs := time.Unix(int64(ts), 0).In(offHoursLoc)
		hour := tzAtTs.Hour()
		tzAbbrev := tzAtTs.Format("MST")
		a.add(model.Finding{
			Type:      "Off-Hours Transfer",
			Severity:  model.SevMedium,
			Score:     score,
			SrcIP:     ok2.src,
			DstIP:     ok2.dst,
			Detail:    fmt.Sprintf("%.2f MB outbound at %02d:xx %s (off-hours window: %02d-%02d)", mb, hour, tzAbbrev, a.cfg.OffHoursStart, a.cfg.OffHoursEnd),
			Timestamp: fmtTS(ts),
		})
	}
}

// reservoirAddF applies Algorithm R reservoir sampling to a float64 stream.
// Returns the possibly-updated buffer and the incremented seen-count.
func reservoirAddF(buf []float64, seen int, v float64, capN int) ([]float64, int) {
	if len(buf) < capN {
		buf = append(buf, v)
	} else {
		idx := rand.IntN(seen + 1)
		if idx < capN {
			buf[idx] = v
		}
	}
	return buf, seen + 1
}

func reservoirAddT(buf [][3]float64, seen int, v [3]float64, capN int) ([][3]float64, int) {
	if len(buf) < capN {
		buf = append(buf, v)
	} else {
		idx := rand.IntN(seen + 1)
		if idx < capN {
			buf[idx] = v
		}
	}
	return buf, seen + 1
}

// histScoreFromHourMap computes the 24-bucket histogram regularity score from
// pre-bucketed hour counters. Mirrors histScoreRegularity but avoids retaining raw
// timestamps.
func histScoreFromHourMap(hourMap map[int]int, dsMin, dsMax float64) (float64, int) {
	const nBuckets = 24
	freq := make([]int, nBuckets)
	if dsMax <= dsMin {
		return 0, 0
	}
	span := dsMax - dsMin
	for hr, c := range hourMap {
		ts := float64(hr) * 3600.0
		idx := int((ts - dsMin) / span * float64(nBuckets))
		if idx >= nBuckets {
			idx = nBuckets - 1
		}
		if idx < 0 {
			idx = 0
		}
		freq[idx] += c
	}
	freqCount := make(map[int]int)
	for i, v := range freq {
		if v > 0 {
			freqCount[i] = v
		}
	}
	totalBars := len(freqCount)
	cv := cvScore(freq)
	bm := bimodalScore(freqCount, totalBars, 0.05)
	score := cv
	if bm > score {
		score = bm
	}
	return score, totalBars
}

func durationScoreFromHourMap(hourMap map[int]int, firstTs, lastTs, dsMin, dsMax float64, minBars int) float64 {
	_, totalBars := histScoreFromHourMap(hourMap, dsMin, dsMax)
	if totalBars < minBars {
		return 0
	}

	coverage := 0.0
	if dsMax > dsMin {
		coverage = (lastTs - firstTs) / (dsMax - dsMin)
	}

	const nBuckets = 24
	freq := make([]int, nBuckets)
	if dsMax > dsMin {
		span := dsMax - dsMin
		for hr, c := range hourMap {
			ts := float64(hr) * 3600.0
			idx := int((ts - dsMin) / span * float64(nBuckets))
			if idx >= nBuckets {
				idx = nBuckets - 1
			}
			if idx < 0 {
				idx = 0
			}
			freq[idx] += c
		}
	}
	longestRun := 0
	currentRun := 0
	for i := 0; i < nBuckets; i++ {
		if freq[i] > 0 {
			currentRun++
			if currentRun > longestRun {
				longestRun = currentRun
			}
		} else {
			currentRun = 0
		}
	}
	consistency := float64(longestRun) / 12.0
	if consistency > 1 {
		consistency = 1
	}

	if coverage > consistency {
		return coverage
	}
	return consistency
}

func lateralPortLabel(port int) string {
	labels := map[int]string{
		445: "SMB", 3389: "RDP", 135: "WMI/RPC", 5985: "WinRM HTTP", 5986: "WinRM HTTPS", 22: "SSH",
	}
	if l, ok := labels[port]; ok {
		return l
	}
	return "unknown"
}

func fmtTS(ts float64) string {
	if ts == 0 {
		return ""
	}
	return time.Unix(int64(ts), 0).UTC().Format("2006-01-02 15:04:05")
}
