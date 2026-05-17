package analysis

import (
	"math"
	"sort"
	"strings"
)

// fmedian returns the median of xs (does not sort in place — makes a copy).
func fmedian(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := make([]float64, len(xs))
	copy(cp, xs)
	sort.Float64s(cp)
	n := len(cp)
	if n%2 == 1 {
		return cp[n/2]
	}
	return (cp[n/2-1] + cp[n/2]) / 2.0
}

// fmean returns the arithmetic mean of xs.
func fmean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range xs {
		sum += v
	}
	return sum / float64(len(xs))
}

// intervalCV is the coefficient of variation (population stddev / mean)
// of xs, given a pre-computed mean. Zero when mean is non-positive or
// xs is empty. This is the "jitter" the beacon triage header renders as
// a percentage; both beacon emit sites (conn + http_analysis) call it
// so the Jitter field is defined identically regardless of detector.
func intervalCV(xs []float64, mean float64) float64 {
	if mean <= 0 || len(xs) == 0 {
		return 0
	}
	variance := 0.0
	for _, v := range xs {
		d := v - mean
		variance += d * d
	}
	return math.Sqrt(variance/float64(len(xs))) / mean
}

// bowleyScore computes (1 - |Bowley skewness|) on a sorted slice.
// Returns 1.0 when distribution is perfectly symmetric, 0.0 when maximally skewed.
func bowleyScore(xs []float64) float64 {
	n := len(xs)
	if n < 3 {
		return 1.0
	}
	sorted := make([]float64, n)
	copy(sorted, xs)
	sort.Float64s(sorted)

	q2 := fmedian(sorted)
	q1 := fmedian(sorted[:n/2])
	q3 := fmedian(sorted[(n+1)/2:])

	denom := q3 - q1
	if denom < 10 || q2 == q1 || q2 == q3 {
		return 1.0
	}
	skewness := (q1 + q3 - 2*q2) / denom
	return 1.0 - math.Abs(skewness)
}

// madScore computes the MAD-based regularity score.
// Formula: (median - MAD) / median. Returns defaultScore when median == 0.
func madScore(xs []float64, defaultScore float64) float64 {
	if len(xs) == 0 {
		return defaultScore
	}
	med := fmedian(xs)
	if med == 0 {
		return defaultScore
	}
	deviations := make([]float64, len(xs))
	for i, v := range xs {
		deviations[i] = math.Abs(v - med)
	}
	mad := fmedian(deviations)
	score := (med - mad) / med
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return score
}

// statisticalScore combines Bowley and MAD scores, rounded to 3 decimal places.
func statisticalScore(xs []float64, defaultMadScore float64) float64 {
	b := bowleyScore(xs)
	m := madScore(xs, defaultMadScore)
	combined := (b + m) / 2.0
	return math.Round(combined*1000) / 1000
}

// computeHistogram partitions timestamps into nBuckets equal-width bins.
// Returns a slice of bucket counts and a map[bucket_index]count for non-zero buckets.
func computeHistogram(timestamps []float64, datasetMin, datasetMax float64, nBuckets int) ([]int, map[int]int) {
	freq := make([]int, nBuckets)
	if datasetMax <= datasetMin {
		return freq, map[int]int{}
	}
	span := datasetMax - datasetMin
	for _, ts := range timestamps {
		idx := int((ts - datasetMin) / span * float64(nBuckets))
		if idx >= nBuckets {
			idx = nBuckets - 1
		}
		if idx < 0 {
			idx = 0
		}
		freq[idx]++
	}
	freqCount := make(map[int]int)
	for i, v := range freq {
		if v > 0 {
			freqCount[i] = v
		}
	}
	return freq, freqCount
}

// cvScore scores how uniformly populated the histogram buckets are.
// Uses population std dev (not sample).
func cvScore(connHist []int) float64 {
	nonZero := make([]float64, 0, len(connHist))
	for _, v := range connHist {
		if v > 0 {
			nonZero = append(nonZero, float64(v))
		}
	}
	if len(nonZero) < 2 {
		return 0
	}
	mean := fmean(nonZero)
	if mean == 0 {
		return 0
	}
	// Population std dev
	variance := 0.0
	for _, v := range nonZero {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(nonZero))
	std := math.Sqrt(variance)
	cv := std / mean
	// Score: low CV = more regular = higher score
	if cv >= 1.0 {
		return 0
	}
	return 1.0 - cv
}

// bimodalScore detects whether the histogram shows bimodal distribution.
func bimodalScore(freqCount map[int]int, totalBars int, modeSensitivity float64) float64 {
	if totalBars < 11 || len(freqCount) < 2 {
		return 0
	}
	// Find max value
	maxVal := 0
	for _, v := range freqCount {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		return 0
	}
	threshold := float64(maxVal) * modeSensitivity
	// Count buckets at or above threshold
	highCount := 0
	for _, v := range freqCount {
		if float64(v) >= threshold {
			highCount++
		}
	}
	if highCount < 2 {
		return 0
	}
	return float64(highCount) / float64(totalBars)
}

// histScoreRegularity computes the histogram-based regularity score over 24 buckets.
// Returns (score 0-1, totalBars).
func histScoreRegularity(timestamps []float64, datasetMin, datasetMax float64) (float64, int) {
	const nBuckets = 24
	connHist, freqCount := computeHistogram(timestamps, datasetMin, datasetMax, nBuckets)
	totalBars := len(freqCount)

	cv := cvScore(connHist)
	bm := bimodalScore(freqCount, totalBars, 0.05)
	score := cv
	if bm > score {
		score = bm
	}
	return score, totalBars
}

// durationScore measures temporal persistence of a connection pattern.
// Returns the higher of coverage score and consecutive-bucket score.
func durationScore(timestamps []float64, datasetMin, datasetMax float64, minBars int) float64 {
	const nBuckets = 24
	_, freqCount := computeHistogram(timestamps, datasetMin, datasetMax, nBuckets)
	totalBars := len(freqCount)
	if totalBars < minBars {
		return 0
	}

	// Coverage: fraction of dataset window covered
	if len(timestamps) == 0 {
		return 0
	}
	first := timestamps[0]
	last := timestamps[len(timestamps)-1]
	for _, ts := range timestamps {
		if ts < first {
			first = ts
		}
		if ts > last {
			last = ts
		}
	}
	coverage := 0.0
	if datasetMax > datasetMin {
		coverage = (last - first) / (datasetMax - datasetMin)
	}

	// Consecutive bucket run
	longestRun := 0
	currentRun := 0
	for i := 0; i < nBuckets; i++ {
		if freqCount[i] > 0 {
			currentRun++
			if currentRun > longestRun {
				longestRun = currentRun
			}
		} else {
			currentRun = 0
		}
	}
	consistency := float64(longestRun) / 12.0
	if consistency > 1 {
		consistency = 1
	}

	if coverage > consistency {
		return coverage
	}
	return consistency
}

// intervalMultimodalScore augments the timing-axis regularity score
// for beacons whose intervals cluster around 2-4 distinct values
// rather than one. Bowley + MAD on the raw distribution penalise
// such beacons heavily — a 60s heartbeat plus a 600s tasking cycle
// looks like noise to median-centric statistics, even though both
// modes are individually tight. This routine bins intervals on a
// log2 axis, identifies peaks, and scores each peak's tightness
// independently. Returns 0 (deferring to the existing math) when
// the distribution is single-mode (≤1 peak), too noisy (≥5 peaks),
// or any peak is too loose to qualify as regular. The caller takes
// max(raw, multimodal) so single-mode beacons are unaffected.
func intervalMultimodalScore(intervals []float64) float64 {
	if len(intervals) < 6 {
		return 0
	}
	// Buckets cover 2^i to 2^(i+1) seconds for i in [0, 17], reaching
	// ~3 days. Beacon periods of operational interest fall within.
	const nBuckets = 18
	buckets := make([][]float64, nBuckets)
	for _, iv := range intervals {
		if iv <= 0 {
			continue
		}
		idx := int(math.Log2(iv))
		if idx < 0 {
			idx = 0
		}
		if idx >= nBuckets {
			idx = nBuckets - 1
		}
		buckets[idx] = append(buckets[idx], iv)
	}

	maxCount := 0
	for _, b := range buckets {
		if len(b) > maxCount {
			maxCount = len(b)
		}
	}
	if maxCount == 0 {
		return 0
	}

	// Peak: a bucket with count ≥ 50% of the max bucket. Adjacent
	// peak-buckets merge, since a single mode can straddle a log2
	// boundary (e.g. a 60s mode lands in [32,64) but tail samples
	// at 65s spill into [64,128)).
	const peakThreshold = 0.5
	threshold := float64(maxCount) * peakThreshold
	type peak struct{ samples []float64 }
	var peaks []peak
	var current peak
	inPeak := false
	for _, b := range buckets {
		if len(b) > 0 && float64(len(b)) >= threshold {
			current.samples = append(current.samples, b...)
			inPeak = true
		} else if inPeak {
			peaks = append(peaks, current)
			current = peak{}
			inPeak = false
		}
	}
	if inPeak {
		peaks = append(peaks, current)
	}

	// Multimodal classification fires for 2-4 peaks. Single-peak
	// distributions are handed back to the existing Bowley+MAD math.
	// Five-or-more peaks are too scattered to be a beacon.
	if len(peaks) < 2 || len(peaks) > 4 {
		return 0
	}

	// Per-peak tightness via the same (median - MAD) / median formula
	// the existing math uses. A peak that's not at least 0.5-tight is
	// rejected as insufficiently regular.
	const peakTightnessFloor = 0.5
	totalCount := 0
	weighted := 0.0
	for _, p := range peaks {
		if len(p.samples) < 2 {
			return 0
		}
		med := fmedian(p.samples)
		if med <= 0 {
			return 0
		}
		deviations := make([]float64, len(p.samples))
		for i, v := range p.samples {
			deviations[i] = math.Abs(v - med)
		}
		mad := fmedian(deviations)
		score := (med - mad) / med
		if score < 0 {
			score = 0
		}
		if score > 1 {
			score = 1
		}
		if score < peakTightnessFloor {
			return 0
		}
		weighted += score * float64(len(p.samples))
		totalCount += len(p.samples)
	}
	if totalCount == 0 {
		return 0
	}
	return weighted / float64(totalCount)
}

// intervalEntropyScore returns a regularity score based on how
// concentrated the interval distribution is across log2 buckets. A
// perfectly regular beacon places every interval in one bucket
// (entropy = 0, score = 1.0). A scattered distribution spreads across
// many buckets (entropy approaches log2(nBuckets), score approaches
// 0). Orthogonal to Bowley + MAD: a beacon at 60s ± 50% jitter scores
// poorly on MAD (deviations are large relative to the 60s median) but
// well here, because every interval still lands in the same one or
// two log2 buckets. Caller takes max(raw, multimodal, entropy) so a
// low entropy score never penalises a beacon the other paths catch.
// Returns 0 below the 6-sample floor.
func intervalEntropyScore(intervals []float64) float64 {
	if len(intervals) < 6 {
		return 0
	}
	const nBuckets = 18
	counts := make([]int, nBuckets)
	total := 0
	for _, iv := range intervals {
		if iv <= 0 {
			continue
		}
		idx := int(math.Log2(iv))
		if idx < 0 {
			idx = 0
		}
		if idx >= nBuckets {
			idx = nBuckets - 1
		}
		counts[idx]++
		total++
	}
	if total == 0 {
		return 0
	}
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		entropy -= p * math.Log2(p)
	}
	maxEntropy := math.Log2(float64(nBuckets))
	if maxEntropy <= 0 {
		return 0
	}
	score := 1.0 - entropy/maxEntropy
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return score
}

// shannonEntropy computes Shannon entropy of a lowercase string.
func shannonEntropy(s string) float64 {
	s = strings.ToLower(s)
	n := float64(len(s))
	if n == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
