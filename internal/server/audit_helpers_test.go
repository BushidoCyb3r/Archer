package server

import (
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// Test the v0.14.2 audit helpers introduced for NEW-34 (list edits
// record diff+hash, not full state) and the cosmetic findingAuditName
// rendering. These run without a Store / Server — they're pure
// functions on values.

func TestDiffStringSets(t *testing.T) {
	added, removed := diffStringSets(
		[]string{"a.com", "b.com", "c.com"},
		[]string{"b.com", "c.com", "d.com", "e.com"},
	)
	wantAdded := []string{"d.com", "e.com"}
	wantRemoved := []string{"a.com"}
	if !equalStringSlices(added, wantAdded) {
		t.Errorf("added = %v; want %v", added, wantAdded)
	}
	if !equalStringSlices(removed, wantRemoved) {
		t.Errorf("removed = %v; want %v", removed, wantRemoved)
	}

	// Same inputs (reordered) must produce no diff — the lists are
	// conceptually sets, not ordered sequences.
	added, removed = diffStringSets(
		[]string{"a", "b", "c"},
		[]string{"c", "a", "b"},
	)
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("reorder-only diff: added=%v removed=%v; want empty", added, removed)
	}

	// Duplicates in input are de-duped on each side.
	added, removed = diffStringSets(
		[]string{"a", "a", "b"},
		[]string{"a", "b", "b", "c"},
	)
	if !equalStringSlices(added, []string{"c"}) || len(removed) != 0 {
		t.Errorf("dup-collapsed diff wrong: added=%v removed=%v", added, removed)
	}
}

func TestHashStringList_Stable(t *testing.T) {
	// Order doesn't change the hash — input is sorted internally.
	h1 := hashStringList([]string{"a", "b", "c"})
	h2 := hashStringList([]string{"c", "a", "b"})
	if h1 != h2 {
		t.Errorf("hashStringList not order-stable: %s vs %s", h1, h2)
	}

	// Different contents produce different hashes.
	h3 := hashStringList([]string{"a", "b", "d"})
	if h1 == h3 {
		t.Errorf("different lists hashed identically: %s == %s", h1, h3)
	}

	// Hex digest plus the sha256: prefix that lets readers identify
	// the algorithm without context.
	if !strings.HasPrefix(h1, "sha256:") || len(h1) != len("sha256:")+64 {
		t.Errorf("hashStringList format wrong: %q", h1)
	}

	// Empty list hash is deterministic and matches the well-known
	// SHA-256 empty-input value (sentinel so a future refactor
	// doesn't silently change the empty-case behaviour).
	empty := hashStringList(nil)
	if empty != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty-list hash drift: %s", empty)
	}
}

// TestListEditAuditDetail_TruncationMarker covers the NEW-34 bound
// on the diff size. A whole-list replacement of 200 entries must
// surface diff_truncated=true with the per-side slices capped at
// auditListDiffCap entries, while the counts retain the true totals.
func TestListEditAuditDetail_TruncationMarker(t *testing.T) {
	added := make([]string, 200)
	for i := range added {
		added[i] = "a"
	}
	d := listEditAuditDetail(added, nil)
	if got := d["added_count"].(int); got != 200 {
		t.Errorf("added_count = %d; want 200", got)
	}
	if got := len(d["added"].([]string)); got != auditListDiffCap {
		t.Errorf("added slice len = %d; want cap %d", got, auditListDiffCap)
	}
	if d["diff_truncated"] != true {
		t.Errorf("diff_truncated = %v; want true", d["diff_truncated"])
	}

	// Small diffs don't set the marker.
	d2 := listEditAuditDetail([]string{"x"}, []string{"y"})
	if d2["diff_truncated"] != false {
		t.Errorf("small diff marked truncated: %v", d2)
	}
}

// TestFindingAuditName covers the cosmetic improvement to TargetName
// on finding_* audit rows — analysts skimming the audit log should
// see distinguishing detail, not five rows all labeled "Beaconing".
func TestFindingAuditName(t *testing.T) {
	cases := []struct {
		name string
		f    model.Finding
		want string
	}{
		{
			"full beacon",
			model.Finding{Type: "Beaconing", SrcIP: "10.4.1.7", DstIP: "185.99.135.7", DstPort: "443"},
			"Beaconing 10.4.1.7 → 185.99.135.7:443",
		},
		{
			"no port",
			model.Finding{Type: "TI Hit (Domain)", SrcIP: "10.4.1.7", DstIP: "evil.example"},
			"TI Hit (Domain) 10.4.1.7 → evil.example",
		},
		{
			"type-only fallback",
			model.Finding{Type: "Host Risk Score"},
			"Host Risk Score",
		},
		{
			"empty type returns empty",
			model.Finding{},
			"",
		},
	}
	for _, tc := range cases {
		if got := findingAuditName(tc.f); got != tc.want {
			t.Errorf("%s: findingAuditName = %q; want %q", tc.name, got, tc.want)
		}
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
