package analysis

import (
	"fmt"
	"math"
	"sort"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// riskWeights maps detection type → contribution to host risk score.
//
// Weights are intentionally hard-coded constants, not config-tunable.
// The audit asked whether this should be operator-configurable; the
// answer is no. The thresholds in detectionsThresholds (config.go) are
// deliberately at the per-detector layer because they are tuned to the
// noise floor of the operator's traffic. Risk weights are at the
// roll-up layer and encode the *relative* danger of detection types
// across all deployments — a Cobalt Strike URI hit is worse than a
// Long Connection regardless of who's looking. Letting operators tune
// these locally would silently desynchronize roll-up scores between
// installs, which makes feed-shared incident discussions ("we saw a
// host risk 80 spike") useless. Audit 2026-05-10 LOW.
//
// The cost of changing a weight is two lines (here + a CHANGELOG
// entry) — the value of leaving it operator-configurable is negative.
var riskWeights = map[string]int{
	"Beacon":                      30,
	"Port-Hopping Beacon":         30, // relabel of Beacon — same weight keeps the host-risk roll-up neutral
	"HTTP Beacon":                 28,
	"DNS Beacon":                  30,
	"Cobalt Strike URI":           40,
	"C2 URI Pattern":              38,
	"Domain Fronting":             32,
	"Malicious JA3":               40,
	"Malicious JA4":               40,
	"TI Hit (IP)":                 35,
	"TI Hit (Domain)":             35,
	"TI Hit (Hash)":               35,
	"Threat Intel Hit":            35, // legacy pre-v0.7.0; pre-rename findings still in DB still contribute
	"Data Exfiltration":           25,
	"Lateral Movement":            20,
	"Strobe":                      15,
	"Long Connection":             10,
	"DNS Tunneling":               35,
	"DNS NXDOMAIN Flood":          18,
	"DNS Subdomain DGA":           22,
	"SSL No-SNI":                  15,
	"SSL No-SNI on C2 Port":       30,
	"Suspicious Certificate":      20,
	"Suspicious File Download":    25,
	"Suspicious URL":              30,
	"Suspicious UA":               12,
	"DoH Bypass":                  18,
	"Weak TLS":                    10,
	"C2 Port":                     22,
	"Protocol on Unexpected Port": 25, // DPD-confirmed protocol/port mismatch on egress — stronger than a bare C2-port match
	"Admin Protocol Egress":       20, // interactive remote-admin protocol reaching the public internet
	"Database Protocol Egress":    22, // cleartext DB protocol crossing to the internet — exfil/exposure channel
	"Protocol Anomaly":            8,
}

// dampenComposite applies an asymptotic curve above the identity threshold
// so raw sums above 75 still grow with extra detectors but never reach 99.
// Below the threshold the function is identity, which keeps single-detector
// hosts (the common shape in goldens and in practice) at their unscaled
// score. Above it: 75 + 24*(1 - exp(-(raw-75)/50)). Concretely:
//
//	raw=  75 → 75   raw= 100 → 84   raw= 150 → 93   raw= 200 → 97   raw= 400 → 99
//
// The 24-point head-room (75..99) preserves rank-order at the top end so
// two badly-saturated hosts can still be compared by their composite.
func dampenComposite(raw int) int {
	const threshold = 75
	if raw <= threshold {
		return raw
	}
	const headroom = 99 - threshold
	const scale = 50.0
	dampened := float64(threshold) + float64(headroom)*(1-math.Exp(-float64(raw-threshold)/scale))
	rounded := int(math.Round(dampened))
	if rounded > 99 {
		return 99
	}
	return rounded
}

func (a *Analyzer) aggregateRisk(_ []string) {
	// Group findings by src_ip. The contributor set unions this run's
	// fresh findings with the previously-merged finding set the store
	// holds — without that union a host that detected last run but
	// went silent this run keeps its stale Host Risk Score row
	// indefinitely (the row's contributing detections are still in
	// the store via SetFindings's preserve-historical loop, but
	// aggregateRisk used to only see this-run's a.findings and so
	// never re-emitted HRS for the host, leaving the old row
	// untouched). Unioning the snapshots regenerates HRS over the
	// host's complete detection footprint so the Hosts tab matches
	// the visible evidence. v0.14.10 NEW-67.
	type hostData struct {
		typeMaxScore map[string]int
		typeDsts     map[string]map[string]struct{} // type → distinct dst IPs
		firstTS      string
	}
	hosts := make(map[string]*hostData)

	// Existing HRS findings have to be excluded from contribution
	// counting: they're the roll-up, not a detector, and folding them
	// in would double-count and spiral upward across runs. They're
	// also the type we're about to regenerate, so leaving them in
	// would feed the previous-run's composite back into the new one.
	//
	// Status filtering is deliberately absent. Dismissed findings
	// still contribute to Host Risk Score: Dismiss is a lightweight
	// reversible view-state bucket ("hide from my default tabs"), not
	// a "false-positive, drop it" verdict. The underlying detection
	// is still real evidence about the host until it's expired by
	// re-analysis or actively suppressed via the IOC/allowlist
	// surfaces. Excluding dismissed here would put load-bearing
	// weight on a one-click reversible action; analysts who genuinely
	// want a finding to stop influencing risk should add it to the
	// allowlist or suppression list instead. NEW-110.
	contribute := func(f model.Finding) {
		src := f.SrcIP
		if src == "" || src == "(cert)" || src == "(escalation)" || src == "(network)" {
			return
		}
		// Roll-up types are excluded from contribution: Host Risk
		// Score is the roll-up we're regenerating (recursive
		// feedback), and Correlated Activity is itself a roll-up
		// whose constituents are already counted via their
		// underlying detector types (double-counting).
		if model.IsRollupType(f.Type) {
			return
		}
		hd := hosts[src]
		if hd == nil {
			hd = &hostData{
				typeMaxScore: make(map[string]int),
				typeDsts:     make(map[string]map[string]struct{}),
			}
			hosts[src] = hd
		}
		if f.Score > hd.typeMaxScore[f.Type] {
			hd.typeMaxScore[f.Type] = f.Score
		}
		if hd.typeDsts[f.Type] == nil {
			hd.typeDsts[f.Type] = make(map[string]struct{})
		}
		hd.typeDsts[f.Type][f.DstIP] = struct{}{}
		// Pick the chronologically earliest contributing timestamp.
		// Pre-fix this set on first-encountered (slice-iteration order),
		// so a host whose first detector emit was at 12:00:15 would
		// stamp the roll-up 12:00:15 even when an earlier 12:00:00 TI
		// hit also contributed. Lexicographic compare on the
		// "YYYY-MM-DD HH:MM:SS UTC" timestamp format is chronological.
		// Audit 2026-05-10 NEW-11.
		if f.Timestamp != "" && (hd.firstTS == "" || f.Timestamp < hd.firstTS) {
			hd.firstTS = f.Timestamp
		}
	}

	a.mu.RLock()
	for _, f := range a.findings {
		contribute(f)
	}
	a.mu.RUnlock()

	// Optional historical context. Nil provider = no union (tests +
	// archive scans). The store snapshot is taken independently of
	// a.mu — Store.GetFindings has its own lock — so there's no nested
	// locking concern. v0.14.10 NEW-67.
	if a.findingsProvider != nil {
		for _, f := range a.findingsProvider.GetFindings() {
			contribute(f)
		}
	}

	// Iterate in sorted-key order so HRS finding IDs are deterministic
	// across re-runs on identical input. Pre-fix `for src, hd := range
	// hosts` used Go's randomized map iteration; a.add assigns sequential
	// IDs in call order, so two fresh runs (post-ClearFindings) on the
	// same logs produced different HRS IDs for the same host. Mostly a
	// reproducibility-and-test-flake concern — steady-state preserves
	// IDs via SetFindings fingerprint match — but the fix is mechanical
	// and the same pattern risk.go:typeList already uses. v0.14.10
	// NEW-68.
	srcKeys := make([]string, 0, len(hosts))
	for src := range hosts {
		srcKeys = append(srcKeys, src)
	}
	sort.Strings(srcKeys)

	for _, src := range srcKeys {
		hd := hosts[src]
		composite := 0
		for t, maxSc := range hd.typeMaxScore {
			if w, ok := riskWeights[t]; ok {
				scoreScale := 0.5 + 0.5*float64(maxSc)/100.0
				// Log multiplier for distinct-destination count: a host
				// hitting two C2 servers is materially worse than one
				// hitting one. 1 + 0.5·log₂(n), capped at 3×.
				n := len(hd.typeDsts[t])
				if n < 1 {
					n = 1
				}
				multiMod := 1.0 + 0.5*math.Log2(float64(n))
				if multiMod > 3.0 {
					multiMod = 3.0
				}
				composite += int(math.Round(float64(w) * scoreScale * multiMod))
			}
		}
		if composite == 0 {
			continue
		}
		// Apply log-scale damping above 75 so additional detectors stop
		// piling onto an already-bad host with linear payoff. Pre-fix
		// the comment claimed log damping but the implementation was a
		// hard clamp at 99 — so a host with raw=120 and another with
		// raw=300 both reported "99" and the analyst lost the relative
		// signal. The asymptote is still 99 but resolution is preserved
		// at the high end. Identity below 75 keeps existing finding
		// scores stable for the common single-/few-detector hosts that
		// the goldens exercise. Audit 2026-05-10 NEW-10.
		composite = dampenComposite(composite)

		var sev model.Severity
		switch {
		case composite >= 75:
			sev = model.SevCritical
		case composite >= 50:
			sev = model.SevHigh
		case composite >= 25:
			sev = model.SevMedium
		default:
			sev = model.SevLow
		}

		typeList := make([]string, 0, len(hd.typeMaxScore))
		for t := range hd.typeMaxScore {
			if len(hd.typeDsts[t]) > 1 {
				typeList = append(typeList, fmt.Sprintf("%s×%d", t, len(hd.typeDsts[t])))
			} else {
				typeList = append(typeList, t)
			}
		}
		sort.Strings(typeList)

		a.add(model.Finding{
			Type:      "Host Risk Score",
			Severity:  sev,
			Score:     composite,
			SrcIP:     src,
			DstIP:     "(network)",
			Detail:    fmt.Sprintf("Composite risk: %d | Detections: %v", composite, typeList),
			Timestamp: hd.firstTS,
		})
	}
}
