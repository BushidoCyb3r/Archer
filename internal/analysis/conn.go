package analysis

import (
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- Algorithm-R reservoir sampling, statistical not security; crypto/rand is wrong here
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
	// spectralTsCap is the reservoir cap for the raw timestamp series fed to
	// the Lomb-Scargle spectral rescue. Higher than beaconTsCap so that pairs
	// with up to 2000 events get their full series — the plausibility gate
	// relies on accurate power estimates, and reservoir thinning reduces SNR
	// proportionally to the sample fraction. For n=557 (the false-positive
	// case that motivated this fix), the full series is used. For very long-
	// lived pairs (n>2000), 2000 samples still provide 10× the SNR of the
	// old 200-sample tsData path. 2000×8 bytes = 16 KB per pair.
	spectralTsCap = 2000
	// maxPreBeaconKeys caps the pre-beacon stash the same way HTTP does.
	// Crafted logs with millions of unique (src, dst) pairs that never
	// reach beaconLazyMinConn would otherwise grow this map without bound.
	maxConnPreBeaconKeys = 500_000
)

type pairKey struct{ sensor, src, dst string }

// All four conn-level detector keys carry sensor for the same reason
// pairKey does: a Quiver deployment with overlapping captures (two
// sensors observing the same backbone) used to aggregate strobe
// counts, exfil bytes, lateral-movement seen-set, and off-hours
// bytes across sensors, so thresholds calibrated on single-sensor
// traffic spuriously tripped (or, worse, passed thresholds that
// should fail because each sensor saw half the traffic). Audit
// 2026-05-10 NEW-6 flagged the asymmetry — beacons were sensor-
// aware as of v0.8.0 but the rest weren't, with no comment
// explaining why. They are now. Single-sensor deployments behave
// identically (sensor field is constant); multi-sensor overlapping
// deployments stop double-counting.
type strobeKey struct{ sensor, src, dst string }
type exfilKey struct{ sensor, src, dst string }
type offKey struct{ sensor, src, dst string }

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
	uid   string
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
	// firstUID captures the Zeek connection UID of the first
	// contribution to this beacon. Used at emit time to look up
	// SNI from sslUIDIndex (when the connection had TLS), which
	// becomes finding.Hostname for the DGA augmentation pass.
	// Empty for non-TLS beacons; the DGA pass handles missing
	// hostnames by skipping that finding.
	firstUID       string
	spectralTs     []float64
	spectralTsSeen int
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

	// Defensive guard: PUT /api/config rejects OffHoursStart == OffHoursEnd
	// (the equality case silently disables off-hours detection — the
	// >Start branch fails because they're equal, the <End branch is
	// always false because hour can't simultaneously be >=Start and
	// <End when Start==End) and rejects out-of-range hours. But the
	// underlying settings row could be planted via direct DB write,
	// a future config-loading bug, or a half-applied migration — and
	// silently disabling a security detector is exactly the failure
	// mode the v0.14.8 NEW-60 audit hammered on. Hoisting the
	// validity test out of the per-record hot path makes the check
	// effectively free, and skipping off-hours scoring entirely when
	// the window is invalid is the right failure mode: better to
	// surface "off-hours produced no findings" than to silently
	// produce wrong findings. v0.14.9 NEW-66.
	offHoursEnabled := a.cfg.OffHoursStart != a.cfg.OffHoursEnd &&
		a.cfg.OffHoursStart >= 0 && a.cfg.OffHoursStart <= 23 &&
		a.cfg.OffHoursEnd >= 0 && a.cfg.OffHoursEnd <= 23

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
			uid := parser.GetStr(rec, "uid")

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

			sk := strobeKey{sensor, src, dst}
			strobeCounts[sk]++
			if ts > 0 && (strobeFirst[sk] == 0 || ts < strobeFirst[sk]) {
				strobeFirst[sk] = ts
			}
			ek := exfilKey{sensor, src, dst}
			exfilOrig[ek] += origB
			exfilResp[ek] += respB
			if ts > 0 && (exfilFirst[ek] == 0 || ts < exfilFirst[ek]) {
				exfilFirst[ek] = ts
			}

			if offHoursEnabled && ts > 0 && !isPrivateIP(dst) {
				hour := time.Unix(int64(ts), 0).In(offHoursLoc).Hour()
				var offHours bool
				if a.cfg.OffHoursStart > a.cfg.OffHoursEnd {
					offHours = hour >= a.cfg.OffHoursStart || hour < a.cfg.OffHoursEnd
				} else {
					offHours = hour >= a.cfg.OffHoursStart && hour < a.cfg.OffHoursEnd
				}
				if offHours && origB > 0 {
					ok2 := offKey{sensor, src, dst}
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

			if isPrivateIP(src) && isPrivateIP(dst) && LateralMovementPorts[dstPort] {
				// sensor prefix mirrors the strobe/exfil/off-hours
				// keying — overlapping sensor captures stop firing two
				// findings for the same (src, dst, port) seen twice.
				lk := fmt.Sprintf("%s|%s→%s:%d", sensor, src, dst, dstPort)
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
				if label, ok := KnownC2Ports[dstPort]; ok {
					ck := fmt.Sprintf("%s|%s→%s:%d", sensor, src, dst, dstPort)
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
				if _, ok := preBeaconRecs[pk]; ok || len(preBeaconRecs) < maxConnPreBeaconKeys {
					preBeaconRecs[pk] = append(preBeaconRecs[pk], preBeaconRec{ts: ts, origB: origB, respB: respB, uid: uid})
				}
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
					firstUID:   uid,
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
							if e.uid != "" {
								st.firstUID = e.uid
							}
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
					if e.ts > 0 {
						st.tsData, st.tsSeen = reservoirAddT(st.tsData, st.tsSeen, [3]float64{e.ts, e.origB, e.respB}, beaconTsCap)
						st.hourMap[int(e.ts)/3600]++
						st.spectralTs, st.spectralTsSeen = reservoirAddF(st.spectralTs, st.spectralTsSeen, e.ts, spectralTsCap)
					}
				}
				delete(preBeaconRecs, pk)
				beacon[pk] = st
			}
			if ts > 0 && (st.minTs == 0 || ts < st.minTs) {
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
			if ts > 0 {
				st.tsData, st.tsSeen = reservoirAddT(st.tsData, st.tsSeen, [3]float64{ts, origB, respB}, beaconTsCap)
				st.hourMap[int(ts)/3600]++
				st.spectralTs, st.spectralTsSeen = reservoirAddF(st.spectralTs, st.spectralTsSeen, ts, spectralTsCap)
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
	var spectralBlockedCount int
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

		tsRaw := statisticalScore(ivs, 1.0)
		// Multimodal augmentation: rescue beacons whose intervals
		// cluster around 2-4 distinct values (heartbeat + tasking,
		// idle + active, etc.) — those would otherwise be penalised
		// by Bowley + MAD on the raw distribution. max() so
		// single-mode beacons (where the helper returns 0) are
		// unaffected.
		tsMM := intervalMultimodalScore(ivs)
		// Entropy augmentation: rescue jittered single-mode beacons
		// where MAD looks bad but every interval still lands in the
		// same one or two log2 buckets. Orthogonal to the other two
		// timing-axis paths.
		tsEnt := intervalEntropyScore(ivs)
		tsScore := tsRaw
		if tsMM > tsScore {
			tsScore = tsMM
		}
		if tsEnt > tsScore {
			tsScore = tsEnt
		}

		// ivMedian needed as the plausibility reference before the
		// spectral call; ivMean is computed together to keep the
		// three statistics co-located.
		ivMean := fmean(ivs)
		ivMedian := fmedian(ivs)

		// Spectral augmentation: frequency-domain rescue for the
		// class of beacons the Bowley/MAD/multimodal/entropy paths
		// all explicitly miss — a single fixed period with enough
		// bounded jitter to wreck statistical regularity scores but
		// not enough to wash out a Lomb-Scargle peak. Uses the
		// dedicated spectralTs series (capped at spectralTsCap=600)
		// rather than tsData so that pairs with ~200-600 events get
		// their full timestamp series. The plausibility gate
		// [ivMedian/5, ivMedian×5] rejects burst-clustering artifacts
		// whose dominant period is orders of magnitude from the
		// observed inter-arrival cadence — the primary source of
		// spectral false positives.
		var spectralRescued bool
		var spectralResult SpectralResult
		if a.cfg.SpectralEnabled && tsScore < a.cfg.SpectralRescueThreshold && len(st.spectralTs) >= a.cfg.SpectralMinObservations {
			spec := spectralScore(st.spectralTs, a.cfg.SpectralMinObservations, a.cfg.SpectralFAPThreshold, ivMedian/5.0, 0)
			if spec.Score > tsScore {
				tsScore = spec.Score
				spectralRescued = true
				spectralResult = spec
			} else if spec.DominantPeriod > 0 {
				spectralBlockedCount++
				slog.Debug("spectral artifact rejected",
					"src", pk.src, "dst", pk.dst,
					"artifact_period", spec.DominantPeriod,
					"artifact_power", spec.DominantPower,
					"median_interval", ivMedian,
					"ratio", spec.DominantPeriod/ivMedian)
			}
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

		var sev model.Severity
		if score >= 80 {
			sev = model.SevCritical
		} else {
			sev = model.SevHigh
		}

		ivCV := intervalCV(ivs, ivMean)

		tsData := make([][3]float64, len(st.tsData))
		copy(tsData, st.tsData)
		sort.Slice(tsData, func(i, j int) bool { return tsData[i][0] < tsData[j][0] })

		detail := fmt.Sprintf("Connections: %d | Mean interval: %.1fs | CV: %.2f | Score components: ts=%.2f ds=%.2f hist=%.2f dur=%.2f | ts_layers: raw=%.2f mm=%.2f ent=%.2f", totalObserved, ivMean, ivCV, tsScore, dsScore, hScore, durScore, tsRaw, tsMM, tsEnt)
		if spectralRescued {
			detail += fmt.Sprintf(" | Spectral rescued: score=%.2f (period %.1fs, %.1f×median, power %.1f, FAP %.1f)",
				spectralResult.Score, spectralResult.Period, spectralResult.Period/ivMedian,
				spectralResult.RawPower, a.cfg.SpectralFAPThreshold)
			if spectralResult.DominantPeriod > 0 {
				detail += fmt.Sprintf(" [artifact %.1fs (%.0f×median) suppressed]",
					spectralResult.DominantPeriod, spectralResult.DominantPeriod/ivMedian)
			}
		}
		// SNI/JA3/JA4 enrichment is deferred to enrichBeaconSNI(), which
		// runs after wg1.Wait() when sslUIDIndex is fully populated and
		// there is no race with analyzeSSL.
		if st.firstUID != "" {
			a.mu.Lock()
			a.beaconSNINeeds[pk] = st.firstUID
			a.mu.Unlock()
		}
		a.add(model.Finding{
			Type:            "Beaconing",
			Severity:        sev,
			Score:           score,
			Sensor:          pk.sensor,
			SrcIP:           pk.src,
			DstIP:           pk.dst,
			DstPort:         fmt.Sprint(st.firstPort),
			Detail:          detail,
			Timestamp:       fmtTS(st.firstTs),
			TSData:          tsData,
			TSScore:         tsScore,
			DSScore:         dsScore,
			HistScore:       hScore,
			DurScore:        durScore,
			MeanInterval:    ivMean,
			MedianInterval:  ivMedian,
			Jitter:          ivCV,
			SampleSize:      totalObserved,
			SpectralRescued: spectralRescued,
			SpectralPeriod:  spectralResult.Period,
			TSRaw:           tsRaw,
			TSMultimodal:    tsMM,
			TSEntropy:       tsEnt,
		})
	}

	if spectralBlockedCount > 0 {
		slog.Info("spectral rescues fully blocked", "analyzer", "conn", "count", spectralBlockedCount)
		a.spectralBlocked.Add(int64(spectralBlockedCount))
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
