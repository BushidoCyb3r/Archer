package analysis

import (
	"fmt"
	"sort"
	"strings"
)

// beaconCorroborators are the same-destination signals that turn a beacon into
// an exfil-over-C2 story: a host that beacons to an external dst AND moves data
// out to that same dst — cleartext database/admin protocol egress, a bulk
// outbound transfer, or a DPD protocol/port mismatch on egress. These are the
// conn-derived egress/exfil detectors whose DstIP is the real external endpoint,
// so sharing a (sensor, src, dst) with a beacon is a genuine corroboration
// rather than a coincidence.
var beaconCorroborators = map[string]bool{
	"Database Protocol Egress":    true,
	"Admin Protocol Egress":       true,
	"Data Exfiltration":           true,
	"Protocol on Unexpected Port": true,
}

// corroboratableBeaconTypes are the conn-based beacon types whose DstIP is the
// actual external endpoint. DNS Beacon is excluded on purpose: its DstIP is the
// resolver, not the C2 endpoint, so same-dst egress would be coincidental.
var corroboratableBeaconTypes = map[string]bool{
	"Beacon":              true,
	"HTTP Beacon":         true,
	"Port-Hopping Beacon": true,
}

// corroborateBeacons enriches a beacon finding's Detail when the same host shows
// an egress/exfil signal to the same external destination — the exfil-over-C2
// pattern that is the platform's reason for being. It tells that story on the
// beacon itself, so an analyst reading the beacon sees the second axis without
// pivoting to the Correlated Activity roll-up.
//
// Annotation-only by design: it does not touch score or severity. The pair-level
// boost is correlateFindings' job, and lifting a beacon's rank on corroboration
// is a calibration-gated detection-semantics change, not this enrichment pass.
// The signal list is sorted so re-runs on identical input produce an identical
// Detail string, and Detail is outside Finding.Fingerprint, so the beacon's
// merge identity (and any analyst state on it) is unaffected.
func (a *Analyzer) corroborateBeacons() {
	type pairKey struct{ sensor, src, dst string }

	a.mu.RLock()
	byPair := map[pairKey]map[string]bool{}
	for _, f := range a.findings {
		if !beaconCorroborators[f.Type] || f.SrcIP == "" || f.DstIP == "" {
			continue
		}
		k := pairKey{f.Sensor, f.SrcIP, f.DstIP}
		if byPair[k] == nil {
			byPair[k] = map[string]bool{}
		}
		byPair[k][f.Type] = true
	}
	a.mu.RUnlock()

	if len(byPair) == 0 {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.findings {
		if !corroboratableBeaconTypes[a.findings[i].Type] {
			continue
		}
		sigs := byPair[pairKey{a.findings[i].Sensor, a.findings[i].SrcIP, a.findings[i].DstIP}]
		if len(sigs) == 0 {
			continue
		}
		list := make([]string, 0, len(sigs))
		for t := range sigs {
			list = append(list, t)
		}
		sort.Strings(list)
		a.findings[i].Detail += fmt.Sprintf(" | Exfil-over-C2 corroboration: same destination also shows %s.", strings.Join(list, ", "))
	}
}
