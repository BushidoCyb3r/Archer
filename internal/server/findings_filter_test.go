package server

import (
	"net/url"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestFilterFindings_DismissedHiddenByDefault codifies the v0.18.0
// Dismissed semantic. The invariant: a Dismissed finding is invisible
// to every default-shaped query (Findings/Ack/Esc/IOC tabs all
// exclude it), and visible only when the caller explicitly requests
// it — either via `status=dismissed` (Dismissed tab) or via
// `include_dismissed=true` (counts endpoint).
//
// Articulating the invariant rather than the failure case: the
// previous filter applied no special-case to dismissed, so a future
// addition of the status would have surfaced rows in the IOC tab
// (which doesn't set a status filter) without anyone noticing. The
// test pins the contract so a future refactor of the status check
// can't silently regress this.
func TestFilterFindings_DismissedHiddenByDefault(t *testing.T) {
	s := newAuditTestServer(t)
	findings := []model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-12 09:00:00"},
		{ID: 2, Type: "TI Hit (IP)", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", Score: 96, Status: model.StatusAcknowledged, Timestamp: "2026-05-12 09:01:00"},
		{ID: 3, Type: "Suspicious URL", SrcIP: "10.0.0.3", DstIP: "3.3.3.3", Score: 97, Status: model.StatusEscalated, Timestamp: "2026-05-12 09:02:00"},
		{ID: 4, Type: "TI Hit (IP)", SrcIP: "10.0.0.4", DstIP: "4.4.4.4", Score: 96, Status: model.StatusDismissed, Timestamp: "2026-05-12 09:03:00"},
		{ID: 5, Type: "Beaconing", SrcIP: "10.0.0.5", DstIP: "5.5.5.5", Score: 70, Status: model.StatusDismissed, Timestamp: "2026-05-12 09:04:00"},
	}

	cases := []struct {
		name    string
		query   url.Values
		wantIDs []int
	}{
		{
			name:    "default findings tab (status=open) excludes dismissed",
			query:   url.Values{"status": []string{"open"}},
			wantIDs: []int{1},
		},
		{
			name:    "ack tab excludes dismissed",
			query:   url.Values{"status": []string{"acknowledged"}},
			wantIDs: []int{2},
		},
		{
			name:    "esc tab excludes dismissed",
			query:   url.Values{"status": []string{"escalated"}},
			wantIDs: []int{3},
		},
		{
			name:    "ioc tab (no status, ioc_only) excludes dismissed even when dismissed row is an IOC type",
			query:   url.Values{"ioc_only": []string{"true"}},
			wantIDs: []int{2, 3},
		},
		{
			name:    "no status filter at all excludes dismissed",
			query:   url.Values{},
			wantIDs: []int{1, 2, 3},
		},
		{
			name:    "status=dismissed shows only dismissed",
			query:   url.Values{"status": []string{"dismissed"}},
			wantIDs: []int{4, 5},
		},
		{
			name:    "include_dismissed=true keeps dismissed in the result (counts endpoint path)",
			query:   url.Values{"include_dismissed": []string{"true"}},
			wantIDs: []int{1, 2, 3, 4, 5},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.filterFindings(append([]model.Finding{}, findings...), c.query)
			gotIDs := []int{}
			for _, f := range got {
				gotIDs = append(gotIDs, f.ID)
			}
			if !sameIntSlice(gotIDs, c.wantIDs) {
				t.Errorf("query=%v: got IDs %v, want %v", c.query, gotIDs, c.wantIDs)
			}
		})
	}
}

// TestFilterFindings_PairAllowlist codifies the pair-allowlist
// invariant end-to-end through the real filter path:
//
//  1. A rule scoped to (src,dst,port,type) hides exactly the findings
//     matching all four — not a different port, not a different dst,
//     not a different type on the same pair.
//  2. The type-scope is the beacon-hunter safety property: muting
//     "Beaconing" on a known-good DNS pair must leave "DNS Tunneling"
//     on that same pair visible (real tradecraft to a legit resolver
//     still surfaces). An empty FindingType is the deliberate broaden
//     that hides every type on the tuple.
//  3. It is a pure view filter: removing the rule restores the
//     finding on the very next filter pass over the same unchanged
//     finding slice — no re-analysis, nothing regenerated.
//
// Asserting the invariant (precision + type-scope safety + reversible)
// rather than a single failure case: a future refactor of the tuple
// key or the type-scope check can't silently regress any one axis
// without a wantIDs mismatch here.
func TestFilterFindings_PairAllowlist(t *testing.T) {
	s := newAuditTestServer(t)
	findings := []model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "53", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-16 09:00:00"},
		{ID: 2, Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "53", Score: 90, Status: model.StatusOpen, Timestamp: "2026-05-16 09:01:00"},
		{ID: 3, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-16 09:02:00"},
		{ID: 4, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "9.9.9.9", DstPort: "53", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-16 09:03:00"},
		{ID: 5, Type: "Beaconing", SrcIP: "10.0.0.9", DstIP: "8.8.8.8", DstPort: "53", Score: 75, Status: model.StatusOpen, Timestamp: "2026-05-16 09:04:00"},
		{ID: 6, Type: "TI Hit (IP)", SrcIP: "10.0.0.9", DstIP: "8.8.8.8", DstPort: "53", Score: 96, Status: model.StatusOpen, Timestamp: "2026-05-16 09:05:00"},
	}
	filterIDs := func() []int {
		got := s.filterFindings(append([]model.Finding{}, findings...), url.Values{})
		ids := []int{}
		for _, f := range got {
			ids = append(ids, f.ID)
		}
		return ids
	}

	if got := filterIDs(); !sameIntSlice(got, []int{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("baseline: got %v, want all 6 visible", got)
	}

	// Scoped rule: only "Beaconing" on the exact DNS tuple.
	scopedID, err := s.store.AddPairAllow(model.PairAllowEntry{
		Src: "10.0.0.1", Dst: "1.1.1.1", Port: "53", FindingType: "Beaconing",
	})
	if err != nil {
		t.Fatalf("AddPairAllow scoped: %v", err)
	}
	if got := filterIDs(); !sameIntSlice(got, []int{2, 3, 4, 5, 6}) {
		t.Errorf("scoped rule: got %v, want {2,3,4,5,6} (only ID 1 hidden; DNS Tunneling on the same pair must stay visible)", got)
	}

	// All-types rule on a second pair.
	if _, err := s.store.AddPairAllow(model.PairAllowEntry{
		Src: "10.0.0.9", Dst: "8.8.8.8", Port: "53", FindingType: "",
	}); err != nil {
		t.Fatalf("AddPairAllow all-types: %v", err)
	}
	if got := filterIDs(); !sameIntSlice(got, []int{2, 3, 4}) {
		t.Errorf("all-types rule: got %v, want {2,3,4} (both types on the 2nd pair hidden)", got)
	}

	// Remove the scoped rule — ID 1 must come straight back on the
	// same finding slice; the all-types rule still hides 5 and 6.
	s.store.RemovePairAllow(scopedID)
	if got := filterIDs(); !sameIntSlice(got, []int{1, 2, 3, 4}) {
		t.Errorf("after remove: got %v, want {1,2,3,4} (ID 1 restored with no re-analysis)", got)
	}
}

// TestFilterFindings_SubScoreRanges codifies the v1.4 sub-score filter
// invariant rather than any single failure case:
//
//  1. Each axis bound is an inclusive [min,max] test against the
//     finding's ts/ds/hist/dur sub-score; either bound may be omitted.
//  2. Setting ANY sub-score bound implicitly scopes the result to
//     beacon types (model.IsBeaconType). The foot-gun this closes:
//     a bare upper bound like dur_max=0.3 must NOT surface every
//     non-beacon, whose dur_score is a structural 0 ≤ 0.3.
//  3. Multiple axes AND together — the documented "ts high but dur
//     low" query is one filter call, not two passes.
//  4. DNS Beaconing is a beacon type but leaves DSScore a structural
//     zero: a ds floor correctly excludes it; a ds ceiling includes
//     it. The gate must not special-case it out.
//  5. A non-numeric bound disables that one axis (defensive, same
//     shape as parsePortSet) rather than blanking the whole filter;
//     when it was the only sub-score param the beacon-scope gate does
//     not engage and pre-existing behaviour is unchanged.
//
// Asserting the invariant (range + implicit beacon-scope + AND across
// axes + DNS structural-zero handling + defensive parse) means a
// future refactor of the parse helper or the gate can't silently
// regress any one axis without a wantIDs mismatch here.
func TestFilterFindings_SubScoreRanges(t *testing.T) {
	s := newAuditTestServer(t)
	findings := []model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-18 09:00:00",
			TSScore: 0.90, DSScore: 0.80, HistScore: 0.50, DurScore: 0.10},
		{ID: 2, Type: "HTTP Beaconing", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", Score: 75, Status: model.StatusOpen, Timestamp: "2026-05-18 09:01:00",
			TSScore: 0.30, DSScore: 0.90, HistScore: 0.90, DurScore: 0.90},
		{ID: 3, Type: "DNS Beaconing", SrcIP: "10.0.0.3", DstIP: "3.3.3.3", Score: 60, Status: model.StatusOpen, Timestamp: "2026-05-18 09:02:00",
			TSScore: 0.95, DSScore: 0.00, HistScore: 0.70, DurScore: 0.60},
		{ID: 4, Type: "Suspicious URL", SrcIP: "10.0.0.4", DstIP: "4.4.4.4", Score: 50, Status: model.StatusOpen, Timestamp: "2026-05-18 09:03:00",
			TSScore: 0.00, DSScore: 0.00, HistScore: 0.00, DurScore: 0.00},
	}

	cases := []struct {
		name    string
		query   url.Values
		wantIDs []int
	}{
		{
			name:    "no sub-score params — baseline unchanged, non-beacon still present",
			query:   url.Values{},
			wantIDs: []int{1, 2, 3, 4},
		},
		{
			name:    "ts_min scopes to beacons and applies the floor",
			query:   url.Values{"ts_min": []string{"0.7"}},
			wantIDs: []int{1, 3},
		},
		{
			name:    "ts_min + dur_max — tight-rhythm short-lived spike (AND across axes)",
			query:   url.Values{"ts_min": []string{"0.7"}, "dur_max": []string{"0.3"}},
			wantIDs: []int{1},
		},
		{
			name:    "bare dur_max must not surface the non-beacon (structural-zero foot-gun)",
			query:   url.Values{"dur_max": []string{"0.3"}},
			wantIDs: []int{1},
		},
		{
			name:    "ds floor excludes DNS Beaconing's structural-zero ds",
			query:   url.Values{"ds_min": []string{"0.5"}},
			wantIDs: []int{1, 2},
		},
		{
			name:    "ds ceiling includes DNS Beaconing (gate must not special-case it out)",
			query:   url.Values{"ds_max": []string{"0.1"}},
			wantIDs: []int{3},
		},
		{
			name:    "hist range [0.6,0.8] inclusive",
			query:   url.Values{"hist_min": []string{"0.6"}, "hist_max": []string{"0.8"}},
			wantIDs: []int{3},
		},
		{
			name:    "non-numeric bound disables that axis; sole param ⇒ no gate, behaviour unchanged",
			query:   url.Values{"ts_min": []string{"abc"}},
			wantIDs: []int{1, 2, 3, 4},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.filterFindings(append([]model.Finding{}, findings...), c.query)
			gotIDs := []int{}
			for _, f := range got {
				gotIDs = append(gotIDs, f.ID)
			}
			if !sameIntSlice(gotIDs, c.wantIDs) {
				t.Errorf("query=%v: got IDs %v, want %v", c.query, gotIDs, c.wantIDs)
			}
		})
	}
}

// TestFilterFindings_JA3 codifies the ja3= filter invariant that
// powers the detail-pane "matched N other beacons" pivot: an exact,
// case-insensitive match on Finding.JA3 (the value is stored lowercased
// at emit, so a pasted upper/mixed-case fingerprint must still match),
// scoping the result to exactly the findings carrying that fingerprint
// regardless of type — the pivot deliberately surfaces the Malicious
// JA3 detection on the same fingerprint alongside the beacons, that is
// the cross-reference the analyst wants. Empty ja3 is a no-op.
func TestFilterFindings_JA3(t *testing.T) {
	s := newAuditTestServer(t)
	findings := []model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-18 09:00:00", JA3: "aabb"},
		{ID: 2, Type: "Beaconing", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-18 09:01:00", JA3: "aabb"},
		{ID: 3, Type: "Malicious JA3", SrcIP: "10.0.0.3", DstIP: "3.3.3.3", Score: 95, Status: model.StatusOpen, Timestamp: "2026-05-18 09:02:00", JA3: "aabb"},
		{ID: 4, Type: "Beaconing", SrcIP: "10.0.0.4", DstIP: "4.4.4.4", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-18 09:03:00", JA3: "ccdd"},
		{ID: 5, Type: "Beaconing", SrcIP: "10.0.0.5", DstIP: "5.5.5.5", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-18 09:04:00", JA3: ""},
	}
	cases := []struct {
		name    string
		query   url.Values
		wantIDs []int
	}{
		{"no ja3 param — unchanged", url.Values{}, []int{1, 2, 3, 4, 5}},
		{"exact match across types (beacons + Malicious JA3)", url.Values{"ja3": []string{"aabb"}}, []int{1, 2, 3}},
		{"case-insensitive (stored lowercased)", url.Values{"ja3": []string{"AABB"}}, []int{1, 2, 3}},
		{"unique fingerprint", url.Values{"ja3": []string{"ccdd"}}, []int{4}},
		{"no match", url.Values{"ja3": []string{"deadbeef"}}, []int{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.filterFindings(append([]model.Finding{}, findings...), c.query)
			gotIDs := []int{}
			for _, f := range got {
				gotIDs = append(gotIDs, f.ID)
			}
			if !sameIntSlice(gotIDs, c.wantIDs) {
				t.Errorf("query=%v: got %v, want %v", c.query, gotIDs, c.wantIDs)
			}
		})
	}
}

// TestFilterFindings_JA4 mirrors TestFilterFindings_JA3 for the ja4=
// filter parameter. The two filters are independent: setting ja4 does
// not restrict by ja3 and vice-versa.
func TestFilterFindings_JA4(t *testing.T) {
	s := newAuditTestServer(t)
	findings := []model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-26 09:00:00", JA4: "t12d190800_d83cc789557e_16bbda4055b2"},
		{ID: 2, Type: "Beaconing", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-26 09:01:00", JA4: "t12d190800_d83cc789557e_16bbda4055b2"},
		{ID: 3, Type: "Malicious JA4", SrcIP: "10.0.0.3", DstIP: "3.3.3.3", Score: 95, Status: model.StatusOpen, Timestamp: "2026-05-26 09:02:00", JA4: "t12d190800_d83cc789557e_16bbda4055b2"},
		{ID: 4, Type: "Beaconing", SrcIP: "10.0.0.4", DstIP: "4.4.4.4", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-26 09:03:00", JA4: "t13d201100_2b729b4bf6f3_9e7b989ebec8"},
		{ID: 5, Type: "Beaconing", SrcIP: "10.0.0.5", DstIP: "5.5.5.5", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-26 09:04:00", JA4: ""},
	}
	cases := []struct {
		name    string
		query   url.Values
		wantIDs []int
	}{
		{"no ja4 param — unchanged", url.Values{}, []int{1, 2, 3, 4, 5}},
		{"exact match across types (beacons + Malicious JA4)", url.Values{"ja4": []string{"t12d190800_d83cc789557e_16bbda4055b2"}}, []int{1, 2, 3}},
		{"case-insensitive (stored lowercased)", url.Values{"ja4": []string{"T12D190800_D83CC789557E_16BBDA4055B2"}}, []int{1, 2, 3}},
		{"unique fingerprint", url.Values{"ja4": []string{"t13d201100_2b729b4bf6f3_9e7b989ebec8"}}, []int{4}},
		{"no match", url.Values{"ja4": []string{"t13d000000_deadbeef0000_000000000000"}}, []int{}},
		{"ja3 and ja4 filters are independent — ja4 alone", url.Values{"ja4": []string{"t12d190800_d83cc789557e_16bbda4055b2"}}, []int{1, 2, 3}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.filterFindings(append([]model.Finding{}, findings...), c.query)
			gotIDs := []int{}
			for _, f := range got {
				gotIDs = append(gotIDs, f.ID)
			}
			if !sameIntSlice(gotIDs, c.wantIDs) {
				t.Errorf("query=%v: got %v, want %v", c.query, gotIDs, c.wantIDs)
			}
		})
	}
}

// TestFilterFindings_BeaconsPseudoType codifies the type=beacons
// invariant: the pseudo-value matches exactly the beacon family
// (Beaconing / HTTP Beaconing / DNS Beaconing) and nothing else, while
// an exact type and the empty/All cases keep their prior meaning. This
// is the selector the beacon export and the all-beacons Findings
// filter both ride, so a regression in the special-case ordering
// (e.g. "beacons" falling through to the exact-match arm and matching
// nothing) is caught here.
func TestFilterFindings_BeaconsPseudoType(t *testing.T) {
	s := newAuditTestServer(t)
	findings := []model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-18 09:00:00"},
		{ID: 2, Type: "HTTP Beaconing", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", Score: 75, Status: model.StatusOpen, Timestamp: "2026-05-18 09:01:00"},
		{ID: 3, Type: "DNS Beaconing", SrcIP: "10.0.0.3", DstIP: "3.3.3.3", Score: 60, Status: model.StatusOpen, Timestamp: "2026-05-18 09:02:00"},
		{ID: 4, Type: "Suspicious URL", SrcIP: "10.0.0.4", DstIP: "4.4.4.4", Score: 70, Status: model.StatusOpen, Timestamp: "2026-05-18 09:03:00"},
		{ID: 5, Type: "Strobe", SrcIP: "10.0.0.5", DstIP: "5.5.5.5", Score: 50, Status: model.StatusOpen, Timestamp: "2026-05-18 09:04:00"},
	}
	cases := []struct {
		name    string
		query   url.Values
		wantIDs []int
	}{
		{"beacons pseudo-type → whole beacon family only", url.Values{"type": []string{"beacons"}}, []int{1, 2, 3}},
		{"exact type still exact", url.Values{"type": []string{"Beaconing"}}, []int{1}},
		{"empty type → all", url.Values{}, []int{1, 2, 3, 4, 5}},
		{"All → all", url.Values{"type": []string{"All"}}, []int{1, 2, 3, 4, 5}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.filterFindings(append([]model.Finding{}, findings...), c.query)
			gotIDs := []int{}
			for _, f := range got {
				gotIDs = append(gotIDs, f.ID)
			}
			if !sameIntSlice(gotIDs, c.wantIDs) {
				t.Errorf("query=%v: got %v, want %v", c.query, gotIDs, c.wantIDs)
			}
		})
	}
}

func sameIntSlice(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[int]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		seen[x]--
	}
	for _, v := range seen {
		if v != 0 {
			return false
		}
	}
	return true
}
