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

// madScore computes the RITA MAD-based regularity score.
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
// Uses population std dev (not sample) matching RITA.
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

// histScoreRITA computes the histogram-based regularity score over 24 buckets.
// Returns (score 0-1, totalBars).
func histScoreRITA(timestamps []float64, datasetMin, datasetMax float64) (float64, int) {
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
