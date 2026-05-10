package analysis

import "testing"

// TestDampenComposite_AsymptoticAbove75 covers the curve replacing the
// old hard-clamp at 99. The pre-fix bug was that two saturated hosts
// (raw=120 and raw=300) both reported "99" — losing the relative signal
// the analyst used to triage which host was worse. Audit 2026-05-10
// NEW-10.
func TestDampenComposite_AsymptoticAbove75(t *testing.T) {
	cases := []struct {
		raw       int
		want      int
		whyMatter string
	}{
		// Identity below threshold preserves single-detector hosts at
		// their unscaled score — same shape goldens exercise.
		{raw: 0, want: 0},
		{raw: 30, want: 30, whyMatter: "single Beaconing finding"},
		{raw: 65, want: 65, whyMatter: "Beaconing + Suspicious URL + TI Hit (Domain)"},
		{raw: 75, want: 75, whyMatter: "threshold boundary"},

		// Above threshold, dampened toward 99 with monotonic increase.
		// Exact values follow 75 + 24*(1 - exp(-(raw-75)/50)).
		{raw: 100, want: 84, whyMatter: "two-detector saturated host"},
		{raw: 150, want: 94, whyMatter: "highly-saturated host"},
		{raw: 200, want: 97},
		{raw: 400, want: 99, whyMatter: "asymptote"},
		{raw: 1_000, want: 99, whyMatter: "no overflow at extreme raw"},
	}
	for _, c := range cases {
		got := dampenComposite(c.raw)
		if got != c.want {
			t.Errorf("dampenComposite(%d) = %d; want %d (%s)", c.raw, got, c.want, c.whyMatter)
		}
	}
}

// TestDampenComposite_Monotonic asserts the curve is non-decreasing —
// a host with strictly more detector signal should never score lower.
func TestDampenComposite_Monotonic(t *testing.T) {
	prev := dampenComposite(0)
	for raw := 1; raw <= 500; raw++ {
		cur := dampenComposite(raw)
		if cur < prev {
			t.Fatalf("non-monotonic at raw=%d: %d < prev %d", raw, cur, prev)
		}
		prev = cur
	}
}

// TestDampenComposite_NeverExceeds99 caps blast radius if the formula
// is later edited — Severity bucketing in aggregateRisk treats 99 as
// the implicit max.
func TestDampenComposite_NeverExceeds99(t *testing.T) {
	for _, raw := range []int{99, 100, 500, 5_000, 1 << 20} {
		if got := dampenComposite(raw); got > 99 {
			t.Errorf("dampenComposite(%d) = %d; must be ≤ 99", raw, got)
		}
	}
}
