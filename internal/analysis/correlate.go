package analysis

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// correlationEligibleType reports whether a finding type can contribute
// to a same-pair correlation. Three exclusions:
//
//  1. Roll-up types (Host Risk Score, Correlated Activity) — folding
//     them in would double-count and risk recursive feedback the same
//     way NEW-67 documented for HRS.
//  2. Zeek Notice — passthrough of upstream policy hits; too noisy and
//     too varied in shape to be a useful correlation signal on its own.
//  3. Long Connection — by itself a weak indicator (legitimate VPNs,
//     keepalives, long-lived SaaS sessions). Pairing it with one other
//     detector type would generate large numbers of low-quality
//     correlations on every busy host.
//
// These mirror the eligibility set the consultant's design called out.
// If operators surface specific FP shapes the list should evolve; for
// now the constants live here rather than in config so the choice is
// auditable in source rather than per-deployment drift.
func correlationEligibleType(t string) bool {
	switch t {
	case model.TypeHostRiskScore, model.TypeCorrelatedActivity,
		"Zeek Notice", "Long Connection":
		return false
	}
	return true
}

// correlateFindings emits a Correlated Activity finding for every
// (SrcIP, DstIP) pair where two or more distinct eligible detector
// types fired this run (or across this run and the merged historical
// finding set, via findingsProvider). Contributing findings are
// annotated with the IDs of their siblings via Finding.Correlations
// so the table UI can surface a `+N correlated` chip on each row.
//
// Pairs run through this in sorted-key order so the assigned IDs are
// stable across re-runs on identical input — same NEW-68 pattern
// aggregateRisk uses. The historical union mirrors NEW-67's fix for
// HRS: without it, a pair whose detectors all fired last run but are
// quiet this run would lose its correlation row, and the
// preserve-historical loop in SetFindings would then leave a stale
// one behind (closed separately by IsRollupType purge).
//
// Runs between Phase 3 (TI) and Phase 4 (aggregateRisk) so the new
// rows are visible to the host-risk roll-up — though they're
// excluded from its weight table, so they contribute observation
// timestamps but not score.
func (a *Analyzer) correlateFindings() {
	minTypes := a.cfg.CorrelationMinTypes
	if minTypes < 2 {
		// Defensive guard mirroring NEW-66: API rejects <2 at the
		// boundary, but a direct DB write or half-applied migration
		// could still leave a degenerate value. Failing closed
		// (skip the phase) beats failing open (emit a correlation
		// for every single-detector pair).
		return
	}

	// pairKey is sensor-partitioned: a single (src, dst) pair observed
	// by two different sensors in an overlapping-capture deployment
	// (multiple Quiver collectors watching the same backbone) is two
	// distinct observations, not one. Pre-fix correlate.go keyed only
	// on (src, dst) and would conflate findings emitted by different
	// sensors into a single correlation row — same shape NEW-6 flagged
	// for beacon pair keys in v0.10.0. Single-sensor deployments
	// behave identically (Sensor field is constant); multi-sensor
	// overlapping deployments stop cross-sensor smearing. NEW-73.
	type pairKey struct{ sensor, src, dst string }
	type pairData struct {
		types      map[string]bool
		maxScore   int
		earliestTS string
		// idsByFingerprint chooses one ID per unique fingerprint
		// contributing to this pair. NEW-92 from the twenty-first
		// audit round: pre-fix idsByID dedup keyed on f.ID, which
		// is wrong because the same logical finding can appear once
		// as a fresh per-run ID (from a.findings) and once as the
		// persisted ID (from findingsProvider.GetFindings) — two
		// different ID values for the same fingerprint. The downstream
		// Correlations slice would carry both, then SetFindings's
		// translation would handle them inconsistently (fresh ID
		// translated correctly; persisted ID dropped or mis-mapped,
		// per NEW-91). Fingerprint-based dedup gives one
		// representation per finding, and the historical pass
		// overrides the fresh pass so the chosen ID is the
		// already-persisted one — survives SetFindings unchanged
		// via NEW-91's identity-map path.
		idsByFingerprint map[model.Fingerprint]int
	}
	pairs := make(map[pairKey]*pairData)

	contribute := func(f model.Finding, isHistorical bool) {
		if !correlationEligibleType(f.Type) {
			return
		}
		if f.SrcIP == "" || f.DstIP == "" {
			return
		}
		// Synthetic destinations carry meta-findings, not real network
		// pairs — excluding them keeps the correlation tab clean and
		// matches campaigns.js's existing "(network)" guard. (cert)
		// and (escalation) appear on TI-derived findings whose SrcIP
		// the analyzer set to a sentinel when no real source exists.
		if f.DstIP == "(network)" || f.SrcIP == "(cert)" || f.SrcIP == "(escalation)" || f.SrcIP == "(TI)" {
			return
		}
		key := pairKey{sensor: f.Sensor, src: f.SrcIP, dst: f.DstIP}
		pd := pairs[key]
		if pd == nil {
			pd = &pairData{
				types:            make(map[string]bool),
				idsByFingerprint: make(map[model.Fingerprint]int),
			}
			pairs[key] = pd
		}
		pd.types[f.Type] = true
		// Historical pass overrides fresh — historical IDs are
		// already in persisted-ID space and survive SetFindings
		// without translation, while fresh IDs depend on the
		// freshToPersisted map. Preferring the historical ID makes
		// the downstream Correlations slice more robust.
		fp := f.Fingerprint()
		if _, seen := pd.idsByFingerprint[fp]; !seen || isHistorical {
			pd.idsByFingerprint[fp] = f.ID
		}
		if f.Score > pd.maxScore {
			pd.maxScore = f.Score
		}
		// Lexicographic compare on the "YYYY-MM-DD HH:MM:SS UTC"
		// timestamp format is chronological — same shape risk.go uses
		// to pick the earliest contributing timestamp.
		if f.Timestamp != "" && (pd.earliestTS == "" || f.Timestamp < pd.earliestTS) {
			pd.earliestTS = f.Timestamp
		}
	}

	a.mu.RLock()
	for _, f := range a.findings {
		contribute(f, false)
	}
	a.mu.RUnlock()

	if a.findingsProvider != nil {
		for _, f := range a.findingsProvider.GetFindings() {
			contribute(f, true)
		}
	}

	// Sort pair keys so emitted correlation IDs are deterministic.
	// Lexicographic sort across (sensor, src, dst) keeps the ordering
	// stable per multi-sensor deployment too — within one sensor, the
	// same src/dst pairs always sort identically.
	pairKeys := make([]pairKey, 0, len(pairs))
	for k := range pairs {
		pairKeys = append(pairKeys, k)
	}
	sort.Slice(pairKeys, func(i, j int) bool {
		if pairKeys[i].sensor != pairKeys[j].sensor {
			return pairKeys[i].sensor < pairKeys[j].sensor
		}
		if pairKeys[i].src != pairKeys[j].src {
			return pairKeys[i].src < pairKeys[j].src
		}
		return pairKeys[i].dst < pairKeys[j].dst
	})

	// Track which IDs to annotate after we know which pairs actually
	// emit a correlation. Keyed on contributing finding ID → list of
	// sibling IDs (excluding self) plus the new correlation row's
	// future ID. We defer the actual annotation until after add() has
	// run so we know the correlation finding's assigned ID.
	type annotation struct {
		siblings []int
	}
	annotations := make(map[int]*annotation)

	for _, key := range pairKeys {
		pd := pairs[key]
		if len(pd.types) < minTypes {
			continue
		}
		// Materialize the contributing IDs from the fingerprint-dedup
		// map. Sort for stable Detail string + stable Correlations
		// slice ordering across re-runs on identical input.
		findingIDs := make([]int, 0, len(pd.idsByFingerprint))
		for _, id := range pd.idsByFingerprint {
			findingIDs = append(findingIDs, id)
		}
		sort.Ints(findingIDs)

		// Score = max(contributor scores) + 5 per extra distinct type
		// above the minimum, capped at 99. Floor is the underlying
		// detector's strongest signal — a correlation never reports
		// lower than its loudest contributor. Bump rewards depth of
		// signal (more detector types lighting up on the same pair)
		// without runaway inflation. Severity derives from the final
		// score via the standard bands.
		extraTypes := len(pd.types) - minTypes
		score := pd.maxScore + 5*extraTypes
		if score > 99 {
			score = 99
		}

		var sev model.Severity
		switch {
		case score >= 80:
			sev = model.SevCritical
		case score >= 60:
			sev = model.SevHigh
		case score >= 40:
			sev = model.SevMedium
		default:
			sev = model.SevLow
		}

		// Render the type list sorted for a stable Detail string —
		// matches the typeList sort in aggregateRisk so re-runs on
		// identical input produce identical fingerprint-preserved
		// Detail strings.
		typeList := make([]string, 0, len(pd.types))
		for t := range pd.types {
			typeList = append(typeList, t)
		}
		sort.Strings(typeList)

		idStrs := make([]string, len(findingIDs))
		for i, id := range findingIDs {
			idStrs[i] = strconv.Itoa(id)
		}

		// Snapshot the contributors before add() runs so the new
		// correlation row's Correlations field can list every
		// contributing ID. The contributors' own Correlations get
		// the same list plus the new row's ID.
		contributorIDs := make([]int, len(findingIDs))
		copy(contributorIDs, findingIDs)

		a.add(model.Finding{
			Type:     model.TypeCorrelatedActivity,
			Severity: sev,
			Score:    score,
			SrcIP:    key.src,
			DstIP:    key.dst,
			Sensor:   key.sensor,
			Detail: fmt.Sprintf("Multi-stage activity on (%s → %s): %s | Contributing finding IDs: %s",
				key.src, key.dst, strings.Join(typeList, ", "), strings.Join(idStrs, ", ")),
			Timestamp:    pd.earliestTS,
			Correlations: contributorIDs,
		})

		// The correlation finding's ID is the most recent a.nextID
		// after add() has run; capture it under read lock so the
		// annotation pass can include it in every contributor's
		// Correlations.
		a.mu.RLock()
		corrID := a.nextID
		a.mu.RUnlock()

		for _, id := range contributorIDs {
			ann := annotations[id]
			if ann == nil {
				ann = &annotation{}
				annotations[id] = ann
			}
			// Siblings = the other contributors + the correlation
			// row itself. Sorting happens below once per id.
			for _, other := range contributorIDs {
				if other != id {
					ann.siblings = append(ann.siblings, other)
				}
			}
			ann.siblings = append(ann.siblings, corrID)
		}
	}

	// Apply annotations under the write lock. Three cases per finding:
	//   1. It's a Correlated Activity row from this run — its
	//      Correlations were set at emit time above, leave alone.
	//   2. It participates in a correlation this run — set its
	//      Correlations to the deduped+sorted sibling list.
	//   3. It doesn't participate this run — clear any stale
	//      Correlations from a prior run so the table doesn't show
	//      a "+N correlated" chip for siblings that no longer
	//      correlate. Historical-only findings (not in a.findings,
	//      preserved by SetFindings) keep their old Correlations as
	//      a record of past co-firing; this is honest for the
	//      common case (DNS Tunneling fires once a week, Beaconing
	//      fires daily, the correlation is meaningful even on
	//      Beaconing-only days).
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.findings {
		if a.findings[i].Type == model.TypeCorrelatedActivity {
			continue
		}
		ann := annotations[a.findings[i].ID]
		if ann == nil {
			a.findings[i].Correlations = nil
			continue
		}
		seen := make(map[int]bool, len(ann.siblings))
		dedup := make([]int, 0, len(ann.siblings))
		for _, id := range ann.siblings {
			if seen[id] {
				continue
			}
			seen[id] = true
			dedup = append(dedup, id)
		}
		sort.Ints(dedup)
		a.findings[i].Correlations = dedup
	}
}
