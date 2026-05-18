package analysis

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestTopURIFootprint codifies the footprint-shape invariant the
// HTTP-beacon path aggregation guarantees, independent of the timing-
// sensitive beacon gate (analyzeHTTP owns the gate; this owns the
// shape): paths group by (sensor,src,dst,host); within a group they
// order by request count descending with URI ascending as the
// deterministic tie-break; the list is capped; groups are isolated;
// and no entries yields nil (the pre-feature shape the store column
// default decodes to). Asserting every axis means a refactor of the
// sort, the cap, or the grouping can't silently regress one.
func TestTopURIFootprint(t *testing.T) {
	gA := uriGroup{"s1", "10.0.0.1", "1.1.1.1", "evil.example"}
	gB := uriGroup{"s1", "10.0.0.9", "1.1.1.1", "evil.example"} // different src → different group
	entries := []uriFootprintEntry{
		{gA, "/a", 50},
		{gA, "/b", 300},
		{gA, "/c", 120},
		{gA, "/aa", 50}, // ties /a on count → URI ascending breaks it (/a before /aa)
		{gB, "/only", 99},
	}

	out := topURIFootprint(entries, 8)

	gotA := out[gA]
	wantA := []model.URIStat{{"/b", 300}, {"/c", 120}, {"/a", 50}, {"/aa", 50}}
	if len(gotA) != len(wantA) {
		t.Fatalf("group A: got %v, want %v", gotA, wantA)
	}
	for i := range wantA {
		if gotA[i] != wantA[i] {
			t.Errorf("group A[%d] = %v; want %v (count desc, URI asc tie-break)", i, gotA[i], wantA[i])
		}
	}

	// Groups are isolated — B must not see A's paths.
	if gb := out[gB]; len(gb) != 1 || gb[0] != (model.URIStat{URI: "/only", Count: 99}) {
		t.Errorf("group B = %v; want [{/only 99}] (group isolation)", gb)
	}

	// Cap applies after the sort: the top `limit` by count survive.
	capped := topURIFootprint(entries, 2)
	if c := capped[gA]; len(c) != 2 || c[0].URI != "/b" || c[1].URI != "/c" {
		t.Errorf("limit=2 group A = %v; want [/b /c] (highest-count survive the cap)", c)
	}

	// No entries → nil, matching the store column's empty-string decode.
	if topURIFootprint(nil, 8) != nil {
		t.Error("empty input: want nil footprint")
	}
}
