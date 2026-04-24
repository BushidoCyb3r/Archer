package analysis

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

type connRecord struct {
	ts        float64
	duration  float64
	origBytes float64
	respBytes float64
	dstPort   int
	proto     string
	sslUID    string
}

func (a *Analyzer) analyzeConn(files []string) {
	type pairKey struct{ src, dst string }
	type strobeKey struct{ src, dst string }
	type exfilKey struct{ src, dst string }
	type offKey struct{ src, dst string }

	// Shared accumulation maps — written once per file (merge under lock)
	var mu sync.Mutex
	pairs        := make(map[pairKey][]connRecord)
	strobeCounts := make(map[strobeKey]int)
	exfilOrig    := make(map[exfilKey]float64)
	exfilResp    := make(map[exfilKey]float64)
	offBytes     := make(map[offKey]float64)
	offFirst     := make(map[offKey]float64)

	connFiles := filterFiles(files, "conn")

	// Each conn.log file is parsed independently into a local set of maps,
	// then merged into the shared maps with a single mutex acquire per file.
	// This eliminates per-record lock contention and scales with core count.
	a.parallelEach(connFiles, func(path string) {
		lPairs        := make(map[pairKey][]connRecord)
		lStrobeCounts := make(map[strobeKey]int)
		lExfilOrig    := make(map[exfilKey]float64)
		lExfilResp    := make(map[exfilKey]float64)
		lOffBytes     := make(map[offKey]float64)
		lOffFirst     := make(map[offKey]float64)
		lDsMin        := math.MaxFloat64
		lDsMax        := 0.0

		_ = parser.ParseLog(path, func(rec map[string]any) bool {
			src := parser.GetStr(rec, "id.orig_h")
			dst := parser.GetStr(rec, "id.resp_h")
			if src == "" || dst == "" {
				return true
			}
			ts    := parser.GetFloat(rec, "ts")
			dur   := parser.GetFloat(rec, "duration")
			origB := parser.GetFloat(rec, "orig_bytes")
			if origB == 0 {
				origB = parser.GetFloat(rec, "orig_ip_bytes")
			}
			respB := parser.GetFloat(rec, "resp_bytes")
			if respB == 0 {
				respB = parser.GetFloat(rec, "resp_ip_bytes")
			}
			dstPort := parser.GetInt(rec, "id.resp_p")
			proto   := parser.GetStr(rec, "proto")
			uid     := parser.GetStr(rec, "uid")

			if ts > 0 {
				if ts < lDsMin { lDsMin = ts }
				if ts > lDsMax { lDsMax = ts }
			}

			pk := pairKey{src, dst}
			lPairs[pk] = append(lPairs[pk], connRecord{
				ts: ts, duration: dur,
				origBytes: origB, respBytes: respB,
				dstPort: dstPort, proto: proto, sslUID: uid,
			})
			lStrobeCounts[strobeKey{src, dst}]++
			lExfilOrig[exfilKey{src, dst}] += origB
			lExfilResp[exfilKey{src, dst}] += respB

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
					lOffBytes[ok2] += origB
					if lOffFirst[ok2] == 0 || ts < lOffFirst[ok2] {
						lOffFirst[ok2] = ts
					}
				}
			}
			return true
		})

		// Single lock per file — merge local results into shared maps
		mu.Lock()
		for k, v := range lPairs        { pairs[k] = append(pairs[k], v...) }
		for k, v := range lStrobeCounts { strobeCounts[k] += v }
		for k, v := range lExfilOrig    { exfilOrig[k] += v }
		for k, v := range lExfilResp    { exfilResp[k] += v }
		for k, v := range lOffBytes     { offBytes[k] += v }
		for k, v := range lOffFirst {
			if cur, ok := offFirst[k]; !ok || v < cur { offFirst[k] = v }
		}
		if lDsMin < a.datasetMin { a.datasetMin = lDsMin }
		if lDsMax > a.datasetMax { a.datasetMax = lDsMax }
		mu.Unlock()
	})

	a.mu.RLock()
	dsMin := a.datasetMin
	dsMax := a.datasetMax
	a.mu.RUnlock()
	if dsMin == math.MaxFloat64 {
		dsMin = 0
	}

	// ── Beaconing ────────────────────────────────────────────────────────────
	for pk, recs := range pairs {
		if len(recs) < a.cfg.BeaconMinConnections {
			continue
		}
		sort.Slice(recs, func(i, j int) bool { return recs[i].ts < recs[j].ts })
		timestamps := make([]float64, len(recs))
		for i, r := range recs {
			timestamps[i] = r.ts
		}

		allIvs := make([]float64, 0, len(recs)-1)
		for i := 1; i < len(recs); i++ {
			if iv := recs[i].ts - recs[i-1].ts; iv > 0 {
				allIvs = append(allIvs, iv)
			}
		}
		if len(allIvs) < 3 {
			continue
		}

		byteVals := make([]float64, 0, len(recs))
		for _, r := range recs {
			if r.origBytes > 0 {
				byteVals = append(byteVals, r.origBytes)
			}
		}

		tsScore  := statisticalScore(allIvs, 1.0)
		dsScore  := 0.0
		if len(byteVals) >= 3 {
			dsScore = statisticalScore(byteVals, 0.0)
		}
		hScore, _ := histScoreRITA(timestamps, dsMin, dsMax)
		durScore   := durationScore(timestamps, dsMin, dsMax, 6)

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

		ivMean := fmean(allIvs)
		ivCV := 0.0
		if ivMean > 0 {
			variance := 0.0
			for _, v := range allIvs {
				d := v - ivMean
				variance += d * d
			}
			ivCV = math.Sqrt(variance/float64(len(allIvs))) / ivMean
		}

		tsData := make([][3]float64, len(recs))
		for i, r := range recs {
			tsData[i] = [3]float64{r.ts, r.origBytes, r.respBytes}
		}

		a.add(model.Finding{
			Type:      "Beaconing",
			Severity:  sev,
			Score:     score,
			SrcIP:     pk.src,
			DstIP:     pk.dst,
			DstPort:   fmt.Sprint(recs[0].dstPort),
			Detail:    fmt.Sprintf("Connections: %d | Mean interval: %.1fs | CV: %.2f | Score components: ts=%.2f ds=%.2f hist=%.2f dur=%.2f", len(recs), ivMean, ivCV, tsScore, dsScore, hScore, durScore),
			Timestamp: fmtTS(recs[0].ts),
			TSData:    tsData,
		})
	}

	// ── Long Connections ─────────────────────────────────────────────────────
	for pk, recs := range pairs {
		for _, r := range recs {
			hours := r.duration / 3600.0
			if hours < a.cfg.LongConnMinHours {
				continue
			}
			score := clamp(int(50+hours/8), 1, 95)
			var sev model.Severity
			if hours > 24 {
				sev = model.SevHigh
			} else {
				sev = model.SevMedium
			}
			a.add(model.Finding{
				Type:      "Long Connection",
				Severity:  sev,
				Score:     score,
				SrcIP:     pk.src,
				DstIP:     pk.dst,
				DstPort:   fmt.Sprint(r.dstPort),
				Detail:    fmt.Sprintf("Duration: %.2f hours | Proto: %s", hours, r.proto),
				Timestamp: fmtTS(r.ts),
			})
		}
	}

	// ── Strobe ───────────────────────────────────────────────────────────────
	for sk, count := range strobeCounts {
		if count < a.cfg.StrobeMinConnections {
			continue
		}
		score := clamp(int(50+math.Log10(float64(count))*15), 1, 88)
		a.add(model.Finding{
			Type:     "Strobe",
			Severity: model.SevHigh,
			Score:    score,
			SrcIP:    sk.src,
			DstIP:    sk.dst,
			Detail:   fmt.Sprintf("Connection count: %d (threshold: %d)", count, a.cfg.StrobeMinConnections),
		})
	}

	// ── Data Exfiltration ────────────────────────────────────────────────────
	for ek, origB := range exfilOrig {
		if isPrivateIP(ek.dst) {
			continue
		}
		respB := exfilResp[ek]
		mb    := origB / 1e6
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
			Type:     "Data Exfiltration",
			Severity: model.SevCritical,
			Score:    score,
			SrcIP:    ek.src,
			DstIP:    ek.dst,
			Detail:   fmt.Sprintf("Outbound: %.2f MB | Ratio out/in: %.1f (threshold: %.1f)", mb, ratio, a.cfg.ExfilRatioThreshold),
		})
	}

	// ── Lateral Movement ─────────────────────────────────────────────────────
	seen := make(map[string]bool)
	for pk, recs := range pairs {
		if !isPrivateIP(pk.src) || !isPrivateIP(pk.dst) {
			continue
		}
		for _, r := range recs {
			if !model.LateralMovementPorts[r.dstPort] {
				continue
			}
			key := fmt.Sprintf("%s→%s:%d", pk.src, pk.dst, r.dstPort)
			if seen[key] {
				continue
			}
			seen[key] = true
			a.add(model.Finding{
				Type:      "Lateral Movement",
				Severity:  model.SevHigh,
				Score:     78,
				SrcIP:     pk.src,
				DstIP:     pk.dst,
				DstPort:   fmt.Sprint(r.dstPort),
				Detail:    fmt.Sprintf("Internal→Internal on port %d (%s)", r.dstPort, lateralPortLabel(r.dstPort)),
				Timestamp: fmtTS(r.ts),
			})
		}
	}

	// ── C2 Ports ─────────────────────────────────────────────────────────────
	c2seen := make(map[string]bool)
	for pk, recs := range pairs {
		if isPrivateIP(pk.dst) {
			continue
		}
		for _, r := range recs {
			label, ok := model.KnownC2Ports[r.dstPort]
			if !ok {
				continue
			}
			key := fmt.Sprintf("%s→%s:%d", pk.src, pk.dst, r.dstPort)
			if c2seen[key] {
				continue
			}
			c2seen[key] = true
			a.add(model.Finding{
				Type:      "C2 Port",
				Severity:  model.SevHigh,
				Score:     75,
				SrcIP:     pk.src,
				DstIP:     pk.dst,
				DstPort:   fmt.Sprint(r.dstPort),
				Detail:    fmt.Sprintf("Port %d — %s", r.dstPort, label),
				Timestamp: fmtTS(r.ts),
			})
		}
	}

	// ── Off-Hours Transfer ───────────────────────────────────────────────────
	for ok2, bytes := range offBytes {
		mb := bytes / 1e6
		if mb < a.cfg.OffHoursMinMB {
			continue
		}
		score := clamp(int(45+math.Log10(mb+1)*12), 1, 78)
		ts   := offFirst[ok2]
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

	_ = strings.ToLower // ensure import used
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
