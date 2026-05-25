package analysis

import (
	"math"
	"testing"
)

const floatTol = 1e-9

func almostEqual(a, b, tol float64) bool {
	if math.IsNaN(a) || math.IsNaN(b) {
		return false
	}
	return math.Abs(a-b) <= tol
}

func TestFmedian(t *testing.T) {
	tests := []struct {
		name string
		in   []float64
		want float64
	}{
		{"empty", []float64{}, 0},
		{"single", []float64{42}, 42},
		{"odd_sorted", []float64{1, 2, 3, 4, 5}, 3},
		{"odd_unsorted", []float64{5, 1, 3, 2, 4}, 3},
		{"even", []float64{1, 2, 3, 4}, 2.5},
		{"duplicates", []float64{2, 2, 2, 2}, 2},
		{"negatives", []float64{-3, -1, 0, 1, 3}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fmedian(tt.in)
			if !almostEqual(got, tt.want, floatTol) {
				t.Errorf("fmedian(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}

	// Confirm input is not mutated (fmedian copies before sort).
	in := []float64{3, 1, 2}
	_ = fmedian(in)
	if in[0] != 3 || in[1] != 1 || in[2] != 2 {
		t.Errorf("fmedian mutated input: %v", in)
	}
}

func TestFmean(t *testing.T) {
	tests := []struct {
		name string
		in   []float64
		want float64
	}{
		{"empty", []float64{}, 0},
		{"single", []float64{5}, 5},
		{"basic", []float64{1, 2, 3, 4, 5}, 3},
		{"negatives_cancel", []float64{-2, -1, 0, 1, 2}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fmean(tt.in)
			if !almostEqual(got, tt.want, floatTol) {
				t.Errorf("fmean(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestBowleyScore(t *testing.T) {
	t.Run("too_few_elements", func(t *testing.T) {
		if got := bowleyScore([]float64{1, 2}); got != 1.0 {
			t.Errorf("bowleyScore(<3) = %v, want 1.0", got)
		}
	})

	t.Run("small_iqr_returns_one", func(t *testing.T) {
		// Spread under 10s — denom guard returns 1.0.
		got := bowleyScore([]float64{1, 2, 3, 4, 5})
		if got != 1.0 {
			t.Errorf("small-iqr bowleyScore = %v, want 1.0", got)
		}
	})

	t.Run("perfectly_symmetric", func(t *testing.T) {
		// Symmetric distribution with denom >= 10 → score 1.0.
		xs := []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
		got := bowleyScore(xs)
		if !almostEqual(got, 1.0, 1e-6) {
			t.Errorf("symmetric bowleyScore = %v, want 1.0", got)
		}
	})

	t.Run("right_skewed_lowers_score", func(t *testing.T) {
		// Heavy right tail — score should drop below 1.
		xs := []float64{0, 1, 2, 3, 4, 5, 6, 7, 100, 200, 1000}
		got := bowleyScore(xs)
		if got >= 1.0 || got < 0 {
			t.Errorf("skewed bowleyScore = %v, want in [0,1)", got)
		}
	})
}

func TestMadScore(t *testing.T) {
	t.Run("empty_returns_default", func(t *testing.T) {
		if got := madScore(nil, 0.42); got != 0.42 {
			t.Errorf("empty madScore = %v, want default 0.42", got)
		}
	})

	t.Run("zero_median_returns_default", func(t *testing.T) {
		// All zeros → median 0 → returns default.
		if got := madScore([]float64{0, 0, 0}, 0.99); got != 0.99 {
			t.Errorf("zero-median madScore = %v, want default 0.99", got)
		}
	})

	t.Run("perfectly_regular", func(t *testing.T) {
		// All same value → MAD = 0 → score = (med - 0) / med = 1.0.
		got := madScore([]float64{60, 60, 60, 60}, 0)
		if !almostEqual(got, 1.0, floatTol) {
			t.Errorf("regular madScore = %v, want 1.0", got)
		}
	})

	t.Run("irregular_lowers_score", func(t *testing.T) {
		// High dispersion — score should be much lower.
		got := madScore([]float64{10, 20, 50, 100, 500, 1000}, 0)
		if got >= 1.0 || got < 0 {
			t.Errorf("irregular madScore = %v, want in [0,1)", got)
		}
	})

	t.Run("clamped_to_unit_interval", func(t *testing.T) {
		// Manufactured: MAD > median should clamp to 0.
		got := madScore([]float64{1, 1, 1, 100, 100, 100}, 0)
		if got < 0 || got > 1 {
			t.Errorf("madScore = %v out of [0,1]", got)
		}
	})
}

func TestStatisticalScore(t *testing.T) {
	t.Run("regular_combination", func(t *testing.T) {
		// All-same → bowley=1 (q1==q3 guard) and MAD=0 → both sub-scores 1.
		xs := []float64{60, 60, 60, 60, 60, 60}
		got := statisticalScore(xs, 0)
		if got != 1.0 {
			t.Errorf("regular statisticalScore = %v, want 1.0", got)
		}
	})

	t.Run("symmetric_but_dispersed", func(t *testing.T) {
		// Symmetric (bowley=1) but high MAD (mad<1) → combined < 1.
		xs := []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
		got := statisticalScore(xs, 0)
		if got >= 1.0 || got <= 0 {
			t.Errorf("symmetric-dispersed statisticalScore = %v, want in (0,1)", got)
		}
	})

	t.Run("rounded_to_three_places", func(t *testing.T) {
		// Non-trivial inputs; just verify rounding to 3 decimals.
		xs := []float64{1, 2, 3, 4, 5, 6, 7, 100, 200, 1000}
		got := statisticalScore(xs, 0)
		// got*1000 should be (very close to) an integer.
		scaled := got * 1000
		if math.Abs(scaled-math.Round(scaled)) > 1e-9 {
			t.Errorf("statisticalScore = %v not rounded to 3 places", got)
		}
		if got < 0 || got > 1 {
			t.Errorf("statisticalScore = %v out of [0,1]", got)
		}
	})
}

func TestComputeHistogram(t *testing.T) {
	t.Run("empty_window_returns_zeroes", func(t *testing.T) {
		freq, freqCount := computeHistogram([]float64{1, 2, 3}, 5, 5, 24)
		if len(freqCount) != 0 {
			t.Errorf("freqCount = %v, want empty", freqCount)
		}
		for i, v := range freq {
			if v != 0 {
				t.Errorf("freq[%d] = %d, want 0", i, v)
			}
		}
	})

	t.Run("uniform_partitioning", func(t *testing.T) {
		// 24 timestamps, one per bucket, exactly aligned.
		ts := make([]float64, 24)
		for i := range ts {
			ts[i] = float64(i) + 0.5
		}
		freq, freqCount := computeHistogram(ts, 0, 24, 24)
		if len(freqCount) != 24 {
			t.Errorf("freqCount size = %d, want 24", len(freqCount))
		}
		for i, v := range freq {
			if v != 1 {
				t.Errorf("freq[%d] = %d, want 1", i, v)
			}
		}
	})

	t.Run("clamps_to_last_bucket", func(t *testing.T) {
		// Timestamp at the boundary should map to last bucket, not over.
		freq, _ := computeHistogram([]float64{10}, 0, 10, 24)
		if freq[23] != 1 {
			t.Errorf("boundary timestamp not clamped: freq = %v", freq)
		}
	})

	t.Run("all_same_bucket", func(t *testing.T) {
		// Cluster all timestamps into bucket 0.
		freq, freqCount := computeHistogram([]float64{0.1, 0.2, 0.3}, 0, 24, 24)
		if freq[0] != 3 {
			t.Errorf("freq[0] = %d, want 3", freq[0])
		}
		if freqCount[0] != 3 || len(freqCount) != 1 {
			t.Errorf("freqCount = %v, want {0:3}", freqCount)
		}
	})
}

func TestCvScore(t *testing.T) {
	tests := []struct {
		name string
		hist []int
		want float64
	}{
		{"too_few_nonzero", []int{0, 0, 5, 0}, 0},
		{"all_zero", []int{0, 0, 0, 0}, 0},
		{"perfectly_uniform", []int{10, 10, 10, 10}, 1.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cvScore(tt.hist)
			if !almostEqual(got, tt.want, floatTol) {
				t.Errorf("cvScore(%v) = %v, want %v", tt.hist, got, tt.want)
			}
		})
	}

	t.Run("varied_lowers_score", func(t *testing.T) {
		got := cvScore([]int{1, 2, 3, 4, 5})
		if got <= 0 || got >= 1 {
			t.Errorf("varied cvScore = %v, want in (0,1)", got)
		}
	})

	t.Run("high_cv_clamped_to_zero", func(t *testing.T) {
		// std/mean >= 1 should return 0.
		got := cvScore([]int{1, 1, 1, 1, 1, 1, 1, 1, 100})
		if got != 0 {
			t.Errorf("high-CV cvScore = %v, want 0", got)
		}
	})
}

func TestBimodalScore(t *testing.T) {
	t.Run("too_few_total_bars", func(t *testing.T) {
		fc := map[int]int{0: 5, 1: 5}
		if got := bimodalScore(fc, 10, 0.05); got != 0 {
			t.Errorf("bimodalScore totalBars<11 = %v, want 0", got)
		}
	})

	t.Run("too_few_buckets", func(t *testing.T) {
		fc := map[int]int{0: 100}
		if got := bimodalScore(fc, 24, 0.05); got != 0 {
			t.Errorf("bimodalScore len<2 = %v, want 0", got)
		}
	})

	t.Run("two_strong_peaks", func(t *testing.T) {
		fc := map[int]int{0: 100, 5: 100, 10: 1, 15: 1, 20: 1, 21: 1, 22: 1, 23: 1, 1: 1, 2: 1, 3: 1, 4: 1}
		got := bimodalScore(fc, 24, 0.5)
		if got <= 0 || got > 1 {
			t.Errorf("bimodal two-peaks = %v, want in (0,1]", got)
		}
	})

	t.Run("single_peak_no_score", func(t *testing.T) {
		// Only one bucket above 50% threshold → highCount<2 → 0.
		fc := map[int]int{0: 100, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1, 9: 1, 10: 1, 11: 1}
		got := bimodalScore(fc, 24, 0.5)
		if got != 0 {
			t.Errorf("bimodal single-peak = %v, want 0", got)
		}
	})
}

func TestHistScoreRegularity(t *testing.T) {
	t.Run("regular_pattern_high_score", func(t *testing.T) {
		// Evenly spaced timestamps should produce a high regularity score.
		ts := make([]float64, 240)
		for i := range ts {
			ts[i] = float64(i) * 60 // every 60s for 4 hours
		}
		score, totalBars := histScoreRegularity(ts, 0, ts[len(ts)-1])
		if totalBars < 1 {
			t.Errorf("totalBars = %d, want >= 1", totalBars)
		}
		if score < 0 || score > 1 {
			t.Errorf("histScoreRegularity score = %v, want in [0,1]", score)
		}
	})

	t.Run("zero_window_zero_score", func(t *testing.T) {
		score, totalBars := histScoreRegularity([]float64{1, 2, 3}, 5, 5)
		if score != 0 || totalBars != 0 {
			t.Errorf("histScoreRegularity empty-window = (%v,%d), want (0,0)", score, totalBars)
		}
	})
}

func TestDurationScore(t *testing.T) {
	t.Run("too_few_bars_zero", func(t *testing.T) {
		ts := []float64{0, 1, 2}
		got := durationScore(ts, 0, 100, 24)
		if got != 0 {
			t.Errorf("too-few-bars durationScore = %v, want 0", got)
		}
	})

	t.Run("full_coverage_high_score", func(t *testing.T) {
		// Spread across full 24 buckets → coverage and consistency both ~1.
		ts := make([]float64, 24)
		for i := range ts {
			ts[i] = float64(i)
		}
		got := durationScore(ts, 0, 24, 12)
		if got < 0.9 {
			t.Errorf("full-coverage durationScore = %v, want >= 0.9", got)
		}
	})

	t.Run("clamp_to_unit", func(t *testing.T) {
		ts := make([]float64, 24)
		for i := range ts {
			ts[i] = float64(i)
		}
		got := durationScore(ts, 0, 24, 1)
		if got < 0 || got > 1 {
			t.Errorf("durationScore = %v out of [0,1]", got)
		}
	})
}

// TestHistScoreFromHourMapCircadian verifies that histScoreFromHourMap measures
// hour-of-day distribution, not window-relative spread. The same circadian
// activity pattern must produce the same hScore regardless of how many days the
// capture covers. Under the old window-relative bucketing, the 24-hour case and
// the 30-day case produced different scores because each bucket spanned a
// different wall-clock interval.
func TestHistScoreFromHourMapCircadian(t *testing.T) {
	// Uniform activity across all 24 hours-of-day.
	shortMap := make(map[int]int) // 1-day capture, absolute hours 0–23
	for hr := 0; hr < 24; hr++ {
		shortMap[hr] = 10
	}
	longMap := make(map[int]int) // 30-day capture, 720 absolute hour indices
	for day := 0; day < 30; day++ {
		for hod := 0; hod < 24; hod++ {
			longMap[day*24+hod] = 10
		}
	}

	shortScore, shortBars := histScoreFromHourMap(shortMap)
	longScore, longBars := histScoreFromHourMap(longMap)

	if shortBars != 24 {
		t.Errorf("1-day: totalBars = %d, want 24", shortBars)
	}
	if longBars != 24 {
		t.Errorf("30-day: totalBars = %d, want 24", longBars)
	}
	if shortScore != longScore {
		t.Errorf("same circadian pattern: 1-day score=%v, 30-day score=%v — should be equal", shortScore, longScore)
	}
}

// TestHistScoreFromHourMapSingleHour verifies that a beacon firing at only one
// hour of day scores zero. Pre-fix, a 30-day single-hour beacon was spread across
// many window-relative buckets and scored high — indistinguishable from a beacon
// that genuinely ran at all hours of the day.
func TestHistScoreFromHourMapSingleHour(t *testing.T) {
	// Only fires at hour 2 (2am) every day for 30 days.
	m := make(map[int]int)
	for day := 0; day < 30; day++ {
		m[day*24+2] = 5
	}
	score, totalBars := histScoreFromHourMap(m)
	if totalBars != 1 {
		t.Errorf("single hour-of-day: totalBars = %d, want 1", totalBars)
	}
	if score != 0 {
		t.Errorf("single hour-of-day: hScore = %v, want 0", score)
	}
}

// TestHistAndDurScoreOrthogonal proves the two axes are independent after the fix.
// A beacon that fires only at 2am but persists for 30 days:
//   - hScore ≈ 0  (only 1 distinct hour-of-day)
//   - durScore ≈ 1 (spans the entire capture window)
//
// A beacon active across all 24 hours but present only on a single day:
//   - hScore > 0  (all or many hour-of-day buckets active)
//   - durScore = 0 (window coverage too small, below minBars)
func TestHistAndDurScoreOrthogonal(t *testing.T) {
	const startHr = 100 * 24 // arbitrary offset well above 24
	dsMin := float64(startHr) * 3600.0
	dsMax := dsMin + 30*24*3600.0

	// Case 1: fires only at 2am every day for 30 days.
	singleHour := make(map[int]int)
	for day := 0; day < 30; day++ {
		singleHour[startHr+day*24+2] = 5
	}
	firstTs := dsMin + 2*3600.0
	lastTs := dsMin + 29*24*3600.0 + 2*3600.0

	hScore1, _ := histScoreFromHourMap(singleHour)
	dScore1 := durationScoreFromHourMap(singleHour, firstTs, lastTs, dsMin, dsMax, 6)

	if hScore1 != 0 {
		t.Errorf("case1: hScore = %v, want 0 (only 1 hour-of-day active)", hScore1)
	}
	if dScore1 < 0.9 {
		t.Errorf("case1: durScore = %v, want ≥ 0.9 (spans full 30-day window)", dScore1)
	}

	// Case 2: fires at all 24 hours-of-day, but only on day 0.
	allHours := make(map[int]int)
	for hod := 0; hod < 24; hod++ {
		allHours[startHr+hod] = 5
	}
	firstTs2 := dsMin
	lastTs2 := dsMin + 23*3600.0

	hScore2, bars2 := histScoreFromHourMap(allHours)
	dScore2 := durationScoreFromHourMap(allHours, firstTs2, lastTs2, dsMin, dsMax, 6)

	if bars2 != 24 {
		t.Errorf("case2: totalBars = %d, want 24", bars2)
	}
	if hScore2 < 0.5 {
		t.Errorf("case2: hScore = %v, want ≥ 0.5 (all 24 hours active, uniform)", hScore2)
	}
	// 1 day / 30-day window → only ~1 window-relative bucket active → below minBars=6
	if dScore2 != 0 {
		t.Errorf("case2: durScore = %v, want 0 (only 1 day of a 30-day window)", dScore2)
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want float64
	}{
		{"empty", "", 0},
		{"single_char", "a", 0},
		{"all_same", "aaaaaa", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.in)
			if !almostEqual(got, tt.want, floatTol) {
				t.Errorf("shannonEntropy(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}

	t.Run("two_chars_equal_distribution", func(t *testing.T) {
		// "ab" → entropy = 1.0 (perfect bit).
		got := shannonEntropy("ab")
		if !almostEqual(got, 1.0, 1e-9) {
			t.Errorf("shannonEntropy(\"ab\") = %v, want 1.0", got)
		}
	})

	t.Run("case_insensitive", func(t *testing.T) {
		// Lowercased internally — "AB" should match "ab".
		a := shannonEntropy("AB")
		b := shannonEntropy("ab")
		if !almostEqual(a, b, floatTol) {
			t.Errorf("case sensitivity: AB=%v ab=%v", a, b)
		}
	})

	t.Run("uniform_4_chars", func(t *testing.T) {
		// "abcd" → uniform 4-symbol → entropy = log2(4) = 2.
		got := shannonEntropy("abcd")
		if !almostEqual(got, 2.0, 1e-9) {
			t.Errorf("shannonEntropy(\"abcd\") = %v, want 2.0", got)
		}
	})

	t.Run("skewed_distribution_below_max", func(t *testing.T) {
		// "aaab" → skewed → less than uniform 2-symbol case (1.0).
		got := shannonEntropy("aaab")
		if got <= 0 || got >= 1.0 {
			t.Errorf("shannonEntropy(\"aaab\") = %v, want in (0,1)", got)
		}
	})
}

func TestIntervalMultimodalScore(t *testing.T) {
	t.Run("too_few_intervals", func(t *testing.T) {
		// Below the 6-sample floor → defer to the existing math.
		got := intervalMultimodalScore([]float64{60, 60, 60, 60, 60})
		if got != 0 {
			t.Errorf("len<6 should return 0, got %v", got)
		}
	})

	t.Run("single_mode_defers", func(t *testing.T) {
		// Tight single-mode 60s heartbeat — only one peak found, so
		// this routine returns 0 and the caller falls back to the
		// raw Bowley + MAD path. (Which scores it high — this just
		// verifies the deferral.)
		ivs := []float64{60, 60, 60, 60, 60, 60, 60, 60, 60, 60}
		got := intervalMultimodalScore(ivs)
		if got != 0 {
			t.Errorf("single-mode should return 0, got %v", got)
		}
	})

	t.Run("bimodal_tight_high_score", func(t *testing.T) {
		// 60s heartbeat (8 samples) + 600s tasking (8 samples) — two
		// tight, well-separated peaks. Should score high.
		ivs := []float64{
			60, 60, 60, 60, 60, 60, 60, 60,
			600, 600, 600, 600, 600, 600, 600, 600,
		}
		got := intervalMultimodalScore(ivs)
		if got < 0.95 {
			t.Errorf("tight bimodal should score ≥ 0.95, got %v", got)
		}
	})

	t.Run("bimodal_with_jitter", func(t *testing.T) {
		// Realistic jittered bimodal (heartbeat 58-62s, tasking 590-610s).
		// Both peaks should still register as tight.
		ivs := []float64{
			58, 59, 60, 61, 62, 60, 60, 59,
			595, 600, 605, 610, 590, 598, 602, 600,
		}
		got := intervalMultimodalScore(ivs)
		if got < 0.85 {
			t.Errorf("jittered bimodal should score ≥ 0.85, got %v", got)
		}
	})

	t.Run("noisy_distribution_rejects", func(t *testing.T) {
		// Six intervals scattered widely — too many distinct buckets,
		// not a beacon. Should return 0.
		ivs := []float64{1, 5, 50, 100, 600, 1200}
		got := intervalMultimodalScore(ivs)
		if got != 0 {
			t.Errorf("scattered noise should return 0, got %v", got)
		}
	})
}

func TestIntervalEntropyScore(t *testing.T) {
	t.Run("too_few_intervals", func(t *testing.T) {
		got := intervalEntropyScore([]float64{60, 60, 60, 60, 60})
		if got != 0 {
			t.Errorf("len<6 should return 0, got %v", got)
		}
	})

	t.Run("perfectly_concentrated_high_score", func(t *testing.T) {
		// All 10 intervals fall in log2 bucket 5 [32,64) → entropy = 0,
		// no width penalty (dominantIdx=5 < 8) → score ~1.0.
		ivs := []float64{60, 60, 60, 60, 60, 60, 60, 60, 60, 60}
		got := intervalEntropyScore(ivs)
		if got < 0.99 {
			t.Errorf("single-bucket (bucket 5, no penalty) should score ~1.0, got %v", got)
		}
	})

	t.Run("wide_bucket_penalized", func(t *testing.T) {
		// All intervals in [512, 1024) — log2 bucket 9. Without the width gate
		// this would score ~1.0 on single-bucket concentration, producing false
		// positives for "all intervals between 8 and 17 minutes" benign traffic.
		// Penalty: score *= 128/512 = 0.25 → score ≤ 0.25.
		ivs := make([]float64, 10)
		for i := range ivs {
			ivs[i] = 600 + float64(i*40) // 600..960s, all in bucket 9
		}
		got := intervalEntropyScore(ivs)
		if got > 0.26 {
			t.Errorf("bucket-9 wide intervals should score ≤ 0.25 after width penalty, got %v", got)
		}
	})

	t.Run("boundary_bucket8_half_penalty", func(t *testing.T) {
		// All intervals in [256, 512) — bucket 8, penalty × 0.5.
		// Without penalty score would be ~1.0, with penalty ~0.5.
		ivs := make([]float64, 10)
		for i := range ivs {
			ivs[i] = 280 + float64(i*20) // 280..460s, all in bucket 8
		}
		got := intervalEntropyScore(ivs)
		if got > 0.52 {
			t.Errorf("bucket-8 intervals should score ≤ 0.5 after ×0.5 penalty, got %v", got)
		}
	})

	t.Run("jittered_single_mode_still_high", func(t *testing.T) {
		// 60s ± 50% jitter (30s..90s) still lands mostly in buckets
		// 5 (32-64) and 6 (64-128). Entropy stays well below the
		// max, score should be substantially above 0.5 — exactly the
		// case where Bowley + MAD on the raw distribution under-score.
		ivs := []float64{30, 45, 60, 75, 90, 60, 60, 60, 50, 70}
		got := intervalEntropyScore(ivs)
		if got < 0.6 {
			t.Errorf("jittered single-mode should score ≥ 0.6, got %v", got)
		}
	})

	t.Run("scattered_low_score", func(t *testing.T) {
		// 8 intervals across 8 different log2 buckets — maximally
		// scattered. Entropy near log2(8) = 3 bits, normalised
		// against log2(18) = 4.17, score ≈ 0.28.
		ivs := []float64{1, 3, 7, 15, 31, 100, 600, 3600}
		got := intervalEntropyScore(ivs)
		if got > 0.4 {
			t.Errorf("scattered should score < 0.4, got %v", got)
		}
	})
}
