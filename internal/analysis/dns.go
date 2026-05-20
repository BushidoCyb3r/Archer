package analysis

import (
	"fmt"
	"math"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

// dnsEntropyMinLabelLen is the minimum first-label length the DNS
// Tunneling entropy signal requires before firing. Pre-v0.10.x
// entropy alone gated the signal at 3.5 bits, which falsely
// flagged legitimate compound English-with-hyphens labels of
// length 20-30 (SaaS verification tokens like
// `google-site-verification`). Real DNS-tunnel payloads are
// long-by-construction (>= 50 chars typically) — channel
// capacity and base32/base36 encoding overhead force length —
// so requiring a 30-char floor on the entropy signal removes
// the false-positive band without losing real coverage. The
// label-length-alone signal at DNSTunnelLabelLen=50 still
// catches the long-but-low-entropy edge case independently.
const dnsEntropyMinLabelLen = 30

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

	// dnsBeaconState accumulates per-(src, apex) query timing for the
	// DNS-cadence beacon detector (§2g). Held separately from apexData
	// so the existing DNS Tunneling diversity path is byte-for-byte
	// untouched — this detector only adds findings, never perturbs the
	// proven ones. Reservoir caps + scorers are the conn-level beacon
	// machinery; subdomain diversity is read from apexMap at emit time
	// (same key) rather than re-tracked here.
	type dnsBeaconState struct {
		lastTS  float64
		ivs     []float64
		ivsSeen int
		tsData  [][3]float64
		tsSeen  int
		hourMap map[int]int
		minTS   float64
		maxTS   float64
		firstTS float64
		count   int
	}

	apexMap := make(map[apexKey]*apexData)
	beaconApex := make(map[apexKey]*dnsBeaconState)
	// Global DNS capture window — the hist/dur axes score how much of
	// the whole capture a beacon spanned, mirroring conn.go's per-sensor
	// window. dns.go's detector family is not sensor-partitioned (the
	// existing apexKey carries no sensor), so a single window is the
	// consistent choice here.
	var dnsWinMin, dnsWinMax float64
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
			if dstPort == 443 && DoHIPs[dst] {
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

			// DNS-cadence beacon accumulation (§2g). Every query to a
			// (src, apex) contributes its inter-arrival timing —
			// subdomain-rotating C2 (apex constant, label varies) and
			// fixed-FQDN heartbeats both land on the same key. ts==0
			// (missing field) contributes to the count but not the
			// timing reservoir, matching conn.go's iv>0 guard.
			if ts > 0 {
				if dnsWinMin == 0 || ts < dnsWinMin {
					dnsWinMin = ts
				}
				if ts > dnsWinMax {
					dnsWinMax = ts
				}
			}
			// NXDOMAIN-dominated streams are the DNS NXDOMAIN Flood
			// detector's responsibility — a beacon to a sinkholed/dead
			// C2 is that finding, and resolver retry behaviour on
			// failed lookups contaminates the inter-arrival timing.
			// Excluding them keeps DNS Beaconing scoped to the cadence
			// of real lookups and prevents a second HIGH finding on the
			// exact same evidence the flood detector already flags.
			if rcode != "NXDOMAIN" {
				bk := apexKey{src, apex}
				bs := beaconApex[bk]
				if bs == nil {
					bs = &dnsBeaconState{hourMap: make(map[int]int), firstTS: ts, minTS: ts, maxTS: ts}
					beaconApex[bk] = bs
				}
				bs.count++
				if ts > 0 {
					if bs.lastTS > 0 {
						if iv := ts - bs.lastTS; iv > 0 {
							bs.ivs, bs.ivsSeen = reservoirAddF(bs.ivs, bs.ivsSeen, iv, beaconIvCap)
						}
					}
					bs.lastTS = ts
					bs.tsData, bs.tsSeen = reservoirAddT(bs.tsData, bs.tsSeen, [3]float64{ts, 0, 0}, beaconTsCap)
					bs.hourMap[int(ts)/3600]++
					if bs.firstTS == 0 || ts < bs.firstTS {
						bs.firstTS = ts
					}
					if bs.minTS == 0 || ts < bs.minTS {
						bs.minTS = ts
					}
					if ts > bs.maxTS {
						bs.maxTS = ts
					}
				}
			}

			// Suspicious TLD
			tld := "." + labels[len(labels)-1]
			if SuspiciousTLDs[tld] {
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
			// Entropy fires only on labels long enough to carry a
			// realistic tunnel payload. Pre-fix any label crossing
			// 3.5 bits fired regardless of length, which trapped
			// legitimate compound English labels of length 20-30
			// (`google-site-verification`, `atlassian-domain-
			// verification`, `stripe-verification`) — compound
			// English with hyphens has higher per-char entropy
			// than long base32 streams because the alphabet is
			// less constrained. Real DNS tunnel labels are
			// >= 50 chars; 30 is a generous floor that excludes
			// compound English while keeping every realistic
			// tunnel shape. Audit 2026-05-10 follow-up.
			if ent >= a.cfg.DNSTunnelEntropy && len(firstLabel) >= dnsEntropyMinLabelLen {
				isTunnel = true
				reasons = append(reasons, fmt.Sprintf("high entropy (%.2f) on %d-char label", ent, len(firstLabel)))
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
		// Both paths emit Type "DNS Tunneling" on the same (src, apex, port 53)
		// fingerprint. A tunnel that triggers per-query heuristics AND diversity
		// would produce two findings with identical fingerprints, causing a
		// SetFindings ID collision and a silent transaction rollback. Per-query
		// already captured the apex; skip redundant diversity emit.
		if seenTunnel[[2]string{k.src, k.apex}] {
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

	// ── DNS-cadence beaconing (§2g) ───────────────────────────────────────────
	// A regular-cadence, low-entropy, low-diversity DNS heartbeat (the
	// Cobalt-Strike DNS C2 shape) slips DNS Tunneling (entropy/diversity
	// too low) and conn-level Beaconing (IP-pair keyed, never consumes
	// query timing). This closes that gap on the (src, apex) key.
	for k, bs := range beaconApex {
		if bs.count < a.cfg.DNSBeaconMinQueries || len(bs.ivs) < 3 {
			continue
		}
		// Benign skip: built-in CDN/cloud allowlist + the operator's
		// curated allowlist. A constant-cadence resolver / telemetry /
		// CDN apex otherwise aggregates every query under one key and
		// the timing scorer can read that regularity as a beacon.
		if matchesCDNAllowlist(k.apex) || (a.allowlistMatches != nil && a.allowlistMatches(k.apex)) {
			continue
		}

		ivs := make([]float64, len(bs.ivs))
		copy(ivs, bs.ivs)

		// Timing axis — same recipe as the conn-level beacon detector
		// (statistical → multimodal → entropy → spectral rescue).
		// Inlined, not shared, so conn.go's proven path stays
		// untouched; the golden fixture locks this behaviour.
		tsScore := statisticalScore(ivs, 1.0)
		if mm := intervalMultimodalScore(ivs); mm > tsScore {
			tsScore = mm
		}
		if eh := intervalEntropyScore(ivs); eh > tsScore {
			tsScore = eh
		}
		var spectralRescued bool
		var spectralResult SpectralResult
		if a.cfg.SpectralEnabled && tsScore < a.cfg.SpectralRescueThreshold && len(bs.tsData) >= a.cfg.SpectralMinObservations {
			tsOnly := make([]float64, len(bs.tsData))
			for i, row := range bs.tsData {
				tsOnly[i] = row[0]
			}
			spec := spectralScore(tsOnly, a.cfg.SpectralMinObservations, a.cfg.SpectralFAPThreshold)
			if spec.Score > tsScore {
				tsScore = spec.Score
				spectralRescued = true
				spectralResult = spec
			}
		}

		// Inverse subdomain-diversity axis. A fixed-FQDN heartbeat has
		// ≈1 unique label under the apex; a subdomain-rotating beacon
		// more, but still far below legit varied DNS. Read the existing
		// apexMap diversity (same key) — absent means only the bare
		// apex was queried (0 subs), maximally beacon-like. The score
		// decays to 0 by the DNS Tunneling diversity floor (those are
		// caught there, not here).
		subCount := 0
		if ad := apexMap[k]; ad != nil {
			subCount = len(ad.subs)
		}
		divFloor := a.cfg.DNSUniqueSubdomainMin
		if divFloor < 1 {
			divFloor = 1
		}
		// Diversity gate. At or above the DNS Tunneling diversity
		// floor the traffic is exfil-shaped, not a heartbeat — DNS
		// Tunneling owns it and Correlated Activity links the two if
		// the cadence is also regular. §2g scopes this detector to the
		// *low-diversity* shape, so make that explicit rather than
		// letting pure timing regularity carry a high-diversity apex.
		if subCount >= divFloor {
			continue
		}
		divScore := 1.0 - float64(subCount)/float64(divFloor)
		if divScore < 0 {
			divScore = 0
		}

		// Window-coverage axes — histogram regularity + duration span
		// over the whole DNS capture, same helpers/min-bars as conn.go.
		hScore, _ := histScoreFromHourMap(bs.hourMap, dnsWinMin, dnsWinMax)
		durScore := durationScoreFromHourMap(bs.hourMap, bs.minTS, bs.maxTS, dnsWinMin, dnsWinMax, 6)
		coverage := (hScore + durScore) / 2.0

		// Composition: timing 0.5, inverse-diversity 0.25, coverage
		// 0.25 — the slice's stated split, pinned by the golden.
		score := clamp(int(100*(tsScore*0.5+divScore*0.25+coverage*0.25)), 1, 100)
		sev := model.SevHigh
		if score >= 80 {
			sev = model.SevCritical
		}

		ivMean := fmean(ivs)
		ivMedian := fmedian(ivs)
		ivCV := intervalCV(ivs, ivMean)

		detail := fmt.Sprintf("DNS queries: %d | Unique subdomains: %d | Mean interval: %.1fs | CV: %.2f | Score: ts=%.2f div=%.2f cov=%.2f",
			bs.count, subCount, ivMean, ivCV, tsScore, divScore, coverage)
		if spectralRescued {
			detail += fmt.Sprintf(" | Spectral rescued: score=%.2f (dominant period %.1fs, power %.1f, FAP threshold %.1f)",
				spectralResult.Score, spectralResult.Period, spectralResult.RawPower, a.cfg.SpectralFAPThreshold)
		}

		// DSScore is left zero: DNS has no data-size axis, and the
		// diversity axis is detector-internal (surfaced in Detail) —
		// overloading the ds_score column would make §2e sub-score
		// filtering mean different things per finding type. ts/hist/dur
		// keep their conn-level meaning; the timing-summary fields are
		// the same as every other beacon.
		a.add(model.Finding{
			Type:            "DNS Beaconing",
			Severity:        sev,
			Score:           score,
			SrcIP:           k.src,
			DstIP:           k.apex,
			DstPort:         "53",
			Detail:          detail,
			Timestamp:       fmtTS(bs.firstTS),
			Hostname:        k.apex,
			TSScore:         tsScore,
			HistScore:       hScore,
			DurScore:        durScore,
			MeanInterval:    ivMean,
			MedianInterval:  ivMedian,
			Jitter:          ivCV,
			SampleSize:      bs.count,
			SpectralRescued: spectralRescued,
			SpectralPeriod:  spectralResult.Period,
		})
	}
}
