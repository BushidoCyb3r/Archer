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

type pairKey struct{ src, dst string }
type strobeKey struct{ src, dst string }
type exfilKey struct{ src, dst string }
type offKey struct{ src, dst string }

type beaconState struct {
	total      int
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

	pairCounts := make(map[pairKey]int)
	beacon := make(map[pairKey]*beaconState)

	strobeCounts := make(map[strobeKey]int)
	strobeFirst := make(map[strobeKey]float64)
	exfilOrig := make(map[exfilKey]float64)
	exfilResp := make(map[exfilKey]float64)
	exfilFirst := make(map[exfilKey]float64)
	offBytes := make(map[offKey]float64)
	offFirst := make(map[offKey]float64)

	lateralSeen := make(map[string]struct{})
	c2Seen := make(map[string]struct{})

	dsMin := math.MaxFloat64
	dsMax := 0.0

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

		_ = parser.ParseLog(path, func(rec map[string]any) bool {
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
				if ts < dsMin {
					dsMin = ts
				}
				if ts > dsMax {
					dsMax = ts
				}
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
				hour := time.Unix(int64(ts), 0).UTC().Hour()
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

			pk := pairKey{src, dst}
			pairCounts[pk]++
			if pairCounts[pk] < beaconLazyMinConn {
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
				beacon[pk] = st
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
			st.tsData, st.tsSeen = reservoirAddT(st.tsData, st.tsSeen, [3]float64{ts, origB, respB}, beaconTsCap)
			if ts > 0 {
				st.hourMap[int(ts)/3600]++
			}

			return true
		})
	}

	a.mu.Lock()
	if dsMin < a.datasetMin {
		a.datasetMin = dsMin
	}
	if dsMax > a.datasetMax {
		a.datasetMax = dsMax
	}
	a.mu.Unlock()
	if dsMin == math.MaxFloat64 {
		dsMin = 0
	}

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
		dsScore := 0.0
		if len(byteVals) >= 3 {
			dsScore = statisticalScore(byteVals, 0.0)
		}
		hScore, _ := histScoreFromHourMap(st.hourMap, dsMin, dsMax)
		durScore := durationScoreFromHourMap(st.hourMap, st.minTs, st.maxTs, dsMin, dsMax, 6)

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
		hour := time.Unix(int64(ts), 0).UTC().Hour()
		a.add(model.Finding{
			Type:      "Off-Hours Transfer",
			Severity:  model.SevMedium,
			Score:     score,
			SrcIP:     ok2.src,
			DstIP:     ok2.dst,
			Detail:    fmt.Sprintf("%.2f MB outbound at %02d:xx UTC (off-hours window: %02d-%02d)", mb, hour, a.cfg.OffHoursStart, a.cfg.OffHoursEnd),
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
// pre-bucketed hour counters. Mirrors histScoreRITA but avoids retaining raw
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
