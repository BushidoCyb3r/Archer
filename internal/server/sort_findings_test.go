package server

import (
	"reflect"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestSortFindings_StrictWeakOrderingWithTiebreak is the LG-4 regression. The
// descending comparator returned `!less`, which for equal keys reports a<b AND
// b<a — not a strict weak ordering, so tie order was undefined and could differ
// between the listing and position endpoints (breaking Jump's landing page).
// Score is the default sort and heavily tied. The comparator now breaks ties
// on ID, giving a deterministic total order in both directions.
func TestSortFindings_StrictWeakOrderingWithTiebreak(t *testing.T) {
	mk := func(id, score int) model.Finding { return model.Finding{ID: id, Score: score} }
	ids := func(fs []model.Finding) []int {
		out := make([]int, len(fs))
		for i, f := range fs {
			out[i] = f.ID
		}
		return out
	}

	// All tied on score: the tiebreak imposes a deterministic ID-ascending
	// order regardless of direction and input permutation.
	for _, dir := range []string{"asc", "desc"} {
		in := []model.Finding{mk(3, 50), mk(1, 50), mk(2, 50)}
		sortFindings(in, "score", dir)
		if got, want := ids(in), []int{1, 2, 3}; !reflect.DeepEqual(got, want) {
			t.Errorf("tied scores dir=%s: ids=%v, want %v", dir, got, want)
		}
	}

	// Mixed scores descending: score desc, ties broken by ID ascending.
	in := []model.Finding{mk(5, 90), mk(2, 99), mk(7, 90), mk(1, 99)}
	sortFindings(in, "score", "desc")
	if got, want := ids(in), []int{1, 2, 5, 7}; !reflect.DeepEqual(got, want) {
		t.Errorf("mixed desc: ids=%v, want %v (99s by id, then 90s by id)", got, want)
	}

	// Two different permutations of the same set must sort identically — the
	// total-order property the position endpoint depends on so the listing and
	// "where is finding X" answers agree.
	a := []model.Finding{mk(1, 50), mk(2, 50), mk(3, 80), mk(4, 80), mk(5, 10)}
	b := []model.Finding{mk(5, 10), mk(3, 80), mk(1, 50), mk(4, 80), mk(2, 50)}
	sortFindings(a, "score", "desc")
	sortFindings(b, "score", "desc")
	if !reflect.DeepEqual(ids(a), ids(b)) {
		t.Errorf("permutations sorted differently: %v vs %v — not a total order", ids(a), ids(b))
	}
}
