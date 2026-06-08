package analysis

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// Cross-host C2 staging detection. Operators land on host A, move laterally to
// host B, and B begins beaconing to the same C2 endpoint A is already calling.
// The network artifact is several internal hosts converging on one rare
// external destination with staggered beacon onsets. A single host beaconing
// to a rare dst is the ambiguous case; two or more, staged in time, is far
// harder to explain benignly — this binds them into one conviction.
//
// detectStaging mirrors correlateFindings: it operates on beacon findings that
// already cleared the emit floor (it never mints low-quality findings), groups
// them by shared external destination, and emits one Multi-Stage Beacon
// finding per qualifying cluster. The Campaigns view stays the broad,
// high-recall fan-in lens; this is the narrow, high-precision conviction
// beside it.
//
// All thresholds are global constants tuned on corpus evidence, not Settings
// knobs (calibration discipline). With no labeled malicious corpus to tune
// against yet, the gate is deliberately stingy — rare dst AND ≥2 hosts AND
// clustered staggered onsets, with corroboration earning the CRITICAL tier.
// Under-fire by design until real-corpus contact widens it.
const (
	stagingMinHosts      = 2    // ≥ this many distinct internal hosts converging
	stagingMaxDstSources = 6    // rarity gate: dst seen by ≤ this many unique internal sources
	stagingWindowHours   = 48.0 // onsets must cluster within this span to read as one campaign
	stagingScore         = 80   // HIGH: staged convergence, no corroboration
	stagingScoreCorrob   = 96   // CRITICAL (and ≥95 bell): staged + corroborated
)

type stagingParams struct {
	minHosts      int
	maxDstSources int
	windowHours   float64
	score         int
	scoreCorrob   int
}

func defaultStagingParams() stagingParams {
	return stagingParams{
		minHosts:      stagingMinHosts,
		maxDstSources: stagingMaxDstSources,
		windowHours:   stagingWindowHours,
		score:         stagingScore,
		scoreCorrob:   stagingScoreCorrob,
	}
}

// stagingParticipant is one internal host in a convergence cluster.
type stagingParticipant struct {
	src     string
	onset   string // earliest beacon Timestamp for this host in the cluster
	freshID int    // contributing fresh finding ID, or 0 if historical-only
}

// computeStaging finds cross-host beacon convergence clusters and returns one
// Multi-Stage Beacon finding per qualifying cluster.
//
//   - fresh / hist: beacon findings from this run and the historical union. A
//     host present in both (same fingerprint) is counted once; fresh wins so
//     its ID is the one linked via Correlations.
//   - related: non-beacon findings consulted for corroboration (Lateral
//     Movement, TI Hit (IP), Malicious JA3/JA4).
//   - dstSources: unique internal sources observed talking to (sensor,dst) —
//     the rarity gate.
func computeStaging(fresh, hist, related []model.Finding, dstSources func(sensor, dst string) int, p stagingParams) []model.Finding {
	type clusterKey struct{ sensor, dst string }
	clusters := map[clusterKey]map[string]*stagingParticipant{}
	seenFP := map[model.Fingerprint]bool{}

	add := func(f model.Finding, isFresh bool) {
		if !model.IsBeaconType(f.Type) || f.SrcIP == "" || f.DstIP == "" || f.Timestamp == "" {
			return
		}
		if isPrivateIP(f.DstIP) { // external destinations only
			return
		}
		fp := f.Fingerprint()
		if seenFP[fp] { // a host in both fresh and history counts once
			return
		}
		seenFP[fp] = true

		ck := clusterKey{f.Sensor, f.DstIP}
		parts := clusters[ck]
		if parts == nil {
			parts = map[string]*stagingParticipant{}
			clusters[ck] = parts
		}
		pp := parts[f.SrcIP]
		if pp == nil {
			pp = &stagingParticipant{src: f.SrcIP, onset: f.Timestamp}
			parts[f.SrcIP] = pp
		}
		// Earliest onset wins (lexicographic compare is chronological for the
		// fixed timestamp layout).
		if f.Timestamp < pp.onset {
			pp.onset = f.Timestamp
		}
		if isFresh && pp.freshID == 0 {
			pp.freshID = f.ID
		}
	}

	for _, f := range fresh {
		add(f, true)
	}
	for _, f := range hist {
		add(f, false)
	}

	// Deterministic cluster order so emitted IDs and detail strings are stable
	// across re-runs on identical input.
	keys := make([]clusterKey, 0, len(clusters))
	for k := range clusters {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].sensor != keys[j].sensor {
			return keys[i].sensor < keys[j].sensor
		}
		return keys[i].dst < keys[j].dst
	})

	var out []model.Finding
	for _, ck := range keys {
		parts := clusters[ck]
		if len(parts) < p.minHosts {
			continue
		}
		if dstSources(ck.sensor, ck.dst) > p.maxDstSources {
			continue
		}

		ordered := make([]*stagingParticipant, 0, len(parts))
		for _, pp := range parts {
			ordered = append(ordered, pp)
		}
		sort.Slice(ordered, func(i, j int) bool {
			if ordered[i].onset != ordered[j].onset {
				return ordered[i].onset < ordered[j].onset
			}
			return ordered[i].src < ordered[j].src
		})

		// Window gate: onsets must cluster within the window to read as one
		// campaign rather than independent niche-app users months apart.
		spread, ok := onsetSpreadHours(ordered[0].onset, ordered[len(ordered)-1].onset)
		if !ok || spread > p.windowHours {
			continue
		}

		participantSet := make(map[string]bool, len(ordered))
		for _, pp := range ordered {
			participantSet[pp.src] = true
		}
		corrob, corrobReason := stagingCorroboration(ck.sensor, ck.dst, participantSet, related)

		score, sev := p.score, model.SevHigh
		if corrob {
			score, sev = p.scoreCorrob, model.SevCritical
		}

		// Correlations link only fresh contributors — their IDs are the ones
		// SetFindings can translate this run. Historical-only participants are
		// named in the detail string instead.
		var corr []int
		for _, pp := range ordered {
			if pp.freshID != 0 {
				corr = append(corr, pp.freshID)
			}
		}
		sort.Ints(corr)

		seed := ordered[0] // patient zero = earliest onset
		var b strings.Builder
		fmt.Fprintf(&b, "%d internal hosts converging on external %s — staged beacon onsets:", len(ordered), ck.dst)
		for _, pp := range ordered {
			fmt.Fprintf(&b, " %s@%s", pp.src, pp.onset)
		}
		if corrob {
			fmt.Fprintf(&b, " | corroboration: %s", corrobReason)
		}

		out = append(out, model.Finding{
			Type:         model.TypeMultiStageBeacon,
			Severity:     sev,
			Score:        score,
			Sensor:       ck.sensor,
			SrcIP:        seed.src,
			DstIP:        ck.dst,
			Timestamp:    seed.onset,
			Detail:       b.String(),
			Correlations: corr,
		})
	}
	return out
}

// onsetSpreadHours returns the hours between two timestamps in the analyzer's
// fixed layout. ok is false if either fails to parse.
func onsetSpreadHours(earliest, latest string) (float64, bool) {
	const layout = "2006-01-02 15:04:05"
	e, err1 := time.Parse(layout, earliest)
	l, err2 := time.Parse(layout, latest)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return l.Sub(e).Hours(), true
}

// stagingCorroboration reports whether any related finding raises the cluster
// to the conviction tier, plus a short reason for the detail string. A lateral
// hop between participants is the staging mechanic itself; a TI hit or
// malicious TLS fingerprint on the destination convicts the C2 directly.
func stagingCorroboration(sensor, dst string, participants map[string]bool, related []model.Finding) (bool, string) {
	for _, r := range related {
		switch r.Type {
		case "Lateral Movement":
			if r.Sensor == sensor && participants[r.SrcIP] && participants[r.DstIP] {
				return true, fmt.Sprintf("lateral movement %s→%s", r.SrcIP, r.DstIP)
			}
		case model.TypeTIHitIP:
			if r.DstIP == dst || r.SrcIP == dst {
				return true, "TI hit on C2 destination"
			}
		case "Malicious JA3", "Malicious JA4":
			if r.DstIP == dst {
				return true, r.Type + " on C2 destination"
			}
		}
	}
	return false, ""
}

// isStagingCorroborationType reports whether a finding type can corroborate a
// staging cluster — kept in lockstep with stagingCorroboration's switch.
func isStagingCorroborationType(t string) bool {
	switch t {
	case "Lateral Movement", model.TypeTIHitIP, "Malicious JA3", "Malicious JA4":
		return true
	}
	return false
}

// detectStaging builds the staging inputs from this run's findings, the
// historical union, and the per-sensor prevalence map, then emits the
// resulting Multi-Stage Beacon findings. Runs after correlateFindings and
// before aggregateRisk (same phase slot and data sources as the same-pair
// roll-up); IsRollupType keeps the emitted rows out of the host-risk weight
// table and out of correlateFindings' eligible set on subsequent runs.
func (a *Analyzer) detectStaging() {
	var fresh, hist, related []model.Finding

	a.mu.RLock()
	for _, f := range a.findings {
		switch {
		case model.IsBeaconType(f.Type):
			fresh = append(fresh, f)
		case isStagingCorroborationType(f.Type):
			related = append(related, f)
		}
	}
	a.mu.RUnlock()

	if a.findingsProvider != nil {
		for _, f := range a.findingsProvider.GetFindings() {
			switch {
			case model.IsBeaconType(f.Type):
				hist = append(hist, f)
			case isStagingCorroborationType(f.Type):
				related = append(related, f)
			}
		}
	}

	dstSources := func(sensor, dst string) int {
		sp := a.sensorPrev[sensor]
		if sp == nil {
			return 0
		}
		return len(sp.dstSrcs[dst])
	}

	for _, f := range computeStaging(fresh, hist, related, dstSources, defaultStagingParams()) {
		a.add(f)
	}
}
