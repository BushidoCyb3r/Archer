package analysis

import "testing"

// TestDurScore_RetentionInvariant pins the property bounded-window persistence
// was introduced for: a beacon's persistence score depends only on its activity
// within the trailing beaconPersistenceWindowSec, not on how much older history
// the corpus holds. Before the fix, durationScoreFromHourMap bucketed across the
// full corpus span, so the same beacon scored differently on a 14-day vs a
// 270-day store — a beacon silently lost persistence credit as retention grew.
func TestDurScore_RetentionInvariant(t *testing.T) {
	const hr = 3600.0
	const day = 24 * hr
	dsMaxHr := 1_000_000
	dsMax := float64(dsMaxHr) * hr

	// Beacon active hourly across the last 10 days (240 hourly hits), ending now.
	hourMap := map[int]int{}
	for i := 0; i < 240; i++ {
		hourMap[dsMaxHr-i] = 1
	}
	firstTs := float64(dsMaxHr-239) * hr
	lastTs := dsMax

	var scores []float64
	for _, span := range []float64{14 * day, 60 * day, 270 * day} {
		dsMin := dsMax - span
		scores = append(scores, durationScoreFromHourMap(hourMap, firstTs, lastTs, dsMin, dsMax, 6))
	}
	for i := 1; i < len(scores); i++ {
		if scores[i] != scores[0] {
			t.Fatalf("persistence not retention-invariant across corpus spans: %v (all must be equal)", scores)
		}
	}
	if scores[0] < 0.9 {
		t.Errorf("10-day hourly beacon should saturate persistence over the trailing window, got %v", scores[0])
	}

	// Contrast: a beacon active only 20-30 days ago — entirely outside the
	// trailing window — earns no persistence credit (its activity clamps into
	// the first bin, leaving total populated bins below minBars).
	dormant := map[int]int{}
	for i := 0; i < 240; i++ {
		dormant[dsMaxHr-20*24-i] = 1
	}
	dFirst := float64(dsMaxHr-30*24) * hr
	dLast := float64(dsMaxHr-20*24) * hr
	if got := durationScoreFromHourMap(dormant, dFirst, dLast, dsMax-60*day, dsMax, 6); got != 0 {
		t.Errorf("dormant beacon (active only >7d ago) should score 0 persistence, got %v", got)
	}

	// Short corpus (≤ window): behaviour is unchanged — the window is the whole
	// corpus, so a beacon spanning a 3-day capture is scored over those 3 days.
	short := map[int]int{}
	for i := 0; i < 72; i++ {
		short[dsMaxHr-i] = 1
	}
	if got := durationScoreFromHourMap(short, float64(dsMaxHr-71)*hr, dsMax, dsMax-3*day, dsMax, 6); got < 0.9 {
		t.Errorf("3-day hourly beacon in a 3-day corpus should be highly persistent, got %v", got)
	}
}
