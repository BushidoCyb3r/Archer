package analysis

import (
	"math"
	"sort"
)

// Spectral beacon detection — Lomb-Scargle periodogram for unevenly-
// spaced connection timestamps.
//
// Why this exists. The statistical timing-axis path (Bowley skewness
// + MAD on inter-arrival intervals, augmented by multimodal and
// entropy rescues) explicitly fails on a single class of beacon: one
// with significant jitter around a single fixed period. A connection
// every 60s ± 30s has terrible CV/MAD scores (the distribution looks
// noisy) but very clear periodic structure in the frequency domain —
// a sharp peak at 1/60 Hz even with substantial timing noise.
// Adversaries who care about evading timing-regularity detection use
// jitter deliberately.
//
// Why Lomb-Scargle, not FFT. Standard FFT requires uniformly-sampled
// data. Connection events are unevenly-spaced in time, so an FFT
// would require either resampling onto a regular grid (introduces
// binning artifacts and bin-choice tuning) or zero-padding the gaps
// (introduces low-frequency artifacts). Lomb-Scargle handles
// unevenly-spaced timestamps natively — it was designed for
// astronomical time series where observations are sparse and
// scattered. Same algorithm Press & Rybicki documented in 1989; this
// is the canonical form.
//
// Why this is a rescue, not a replacement. Lomb-Scargle is O(N×M)
// per pair (N observations, M frequency-grid points). At Archer
// scale (≤200 reservoir-sampled timestamps per pair, ~200
// frequencies) that's bounded, but it's still CPU-hungrier than the
// statistical math. The integration runs spectral only when the
// statistical path already failed — pairs that scored well don't
// need rescue. See SpectralRescueThreshold in config.
//
// References:
//   - Lomb, N.R. 1976. "Least-squares frequency analysis of unequally
//     spaced data."
//   - Scargle, J.D. 1982. "Studies in astronomical time series
//     analysis. II. Statistical aspects of spectral analysis of
//     unevenly spaced data."
//   - Press, W.H. & Rybicki, G.B. 1989. "Fast algorithm for spectral
//     analysis of unevenly sampled data."

// rayleighPower computes the DC-corrected Rayleigh (Schuster) periodogram
// power at a single angular frequency omega. This is the right form for
// impulse trains (timestamp periodicity, not amplitude periodicity).
//
// Correction for finite-window spectral leakage. The naive Rayleigh
// formula P = (cSum² + sSum²)/N assumes timestamps are uniformly
// distributed over the observation window. For non-integer window/period
// ratios, the mean of cos(ωt_k) over a uniform distribution is non-zero:
//
//	E[cos(ωt)] = sinc(ωW/2) · cos(ω·t_center)
//
// where sinc(x) = sin(x)/x and t_center = (t₀+t₀+W)/2. This bias is
// ∝ N/(2k+1)² at the peaks T/(k+0.5) for integer k. For N=6500 events
// over 9 months, the k=4 bias peak reaches power ≈34 at FAP=12 — a
// systematic false-positive, not a statistical one. Subtracting the
// expected means before computing power restores the Exp(1) null
// distribution at all frequencies, including long-period ones.
//
// Under the corrected null (random arrivals, no periodicity) the power
// is exponentially distributed with mean 1.0. A peak of e.g. 12 means
// false-alarm probability ≈ exp(-12) ≈ 6e-6 per frequency tested. With
// M=2000 grid points, expected total FAP at threshold 12 is M·exp(-12)
// ≈ 0.012 — about one false alarm per 80 background pair evaluations at
// this threshold.
//
// Why Rayleigh, not the more-general Lomb-Scargle with tau-adjustment.
// The classical Lomb-Scargle adds a phase-reference shift (tau =
// atan2(Σ sin(2ωt), Σ cos(2ωt)) / 2ω) so the sin/cos basis is
// orthogonal at the data's exact phase distribution. For amplitude
// time series (astronomy, the original use case) this matters. For
// impulse trains where every event has the same y_k = 1, tau is
// degenerate at the fundamental of a uniformly-spaced signal —
// sin² accumulates to zero, causing a divide-by-zero or numerical
// flake. The DC-corrected Rayleigh form sidesteps this without losing
// detection power: harmonics still appear at their true positions, the
// fundamental wins for any signal with non-trivial jitter, and the
// null-distribution mean-1 property holds.
//
// O(N) per call. Each timestamp is a unit-height impulse — we score
// whether events cluster at a particular phase, not whether their
// amplitude oscillates. Assumes timestamps are sorted so [0] is the
// minimum and [n-1] is the maximum.
func rayleighPower(timestamps []float64, omega float64) float64 {
	n := len(timestamps)
	if n < 4 {
		return 0
	}
	var cSum, sSum float64
	for _, t := range timestamps {
		cSum += math.Cos(omega * t)
		sSum += math.Sin(omega * t)
	}
	// DC-correction: subtract expected means for a uniform-distribution
	// baseline over the observation window.
	//   E[cos(ωt)] = sinc(ωW/2) · cos(ω·t_center)
	//   E[sin(ωt)] = sinc(ωW/2) · sin(ω·t_center)
	// where sinc(x) = sin(x)/x and t_center = t₀ + W/2.
	t0 := timestamps[0]
	halfW := (timestamps[n-1] - t0) / 2.0
	omegaHalfW := omega * halfW
	var sinc float64
	if omegaHalfW < 1e-10 {
		sinc = 1.0
	} else {
		sinc = math.Sin(omegaHalfW) / omegaHalfW
	}
	fn := float64(n)
	tCenter := t0 + halfW
	cSum -= fn * sinc * math.Cos(omega*tCenter)
	sSum -= fn * sinc * math.Sin(omega*tCenter)
	return (cSum*cSum + sSum*sSum) / fn
}

// SpectralResult is the per-pair output of spectralScore. Returned
// rather than via multiple values so the caller doesn't have to
// remember the order; the Detail-string renderer in conn.go and
// http_analysis.go uses Period and Power independently of Score.
type SpectralResult struct {
	// Score in [0, 1]. 0 = no plausible periodicity above noise; 1 =
	// strongly periodic, well past the false-alarm threshold. Linearly
	// proportional to log-confidence above the threshold, clamped at
	// 1 once the peak is 2× the threshold. Based on the strongest
	// peak within [minPlausiblePeriod, maxPlausiblePeriod].
	Score float64
	// Period in seconds at the strongest plausible spectral peak.
	// Meaningful only when Score > 0.
	Period float64
	// RawPower is the un-normalised Lomb-Scargle value at Period.
	RawPower float64
	// DominantPeriod is the overall strongest peak when it was outside
	// the plausible range and therefore rejected. Zero when the
	// dominant peak was plausible, or no above-threshold peak exists.
	// Exposed so the call site can log the rejected artifact.
	DominantPeriod float64
	// DominantPower is the Lomb-Scargle power at DominantPeriod.
	DominantPower float64
}

// spectralScore runs Lomb-Scargle over a logarithmically-spaced
// period grid and returns the strongest plausible peak and its score.
//
// Algorithm:
//  1. Sort timestamps (Lomb-Scargle requires nothing of order but
//     downstream consumers want a chronological sequence anyway).
//  2. Compute observation window = last - first. Period grid spans
//     5s (the floor below which Archer's analysts don't care; ICMP
//     ping is faster than that but isn't C2-relevant) to window/2
//     (the Nyquist limit — can't reliably detect a period longer
//     than half the observation span).
//  3. 2000 log-spaced periods. Log spacing matches how operators
//     think about beacons (60s, 600s, 3600s — orders of magnitude
//     apart matter more than absolute deltas).
//  4. Evaluate Lomb-Scargle power at each period. Track two running
//     bests: the overall dominant peak, and the best peak within
//     [minPlausiblePeriod, maxPlausiblePeriod].
//  5. Score the plausible peak against the FAP threshold. If it
//     clears, return a rescue. If the overall dominant peak was
//     outside the plausible range, populate DominantPeriod so the
//     call site can log the rejected artifact.
//
// minPlausiblePeriod is derived from the pair's median inter-arrival
// interval at the call site: ivMedian/5. This is a lower bound only —
// the gate is intentionally asymmetric.
//
// Two-sided plausibility bounds.
//
// Lower bound (minPlausiblePeriod): rejects burst-clustering artifacts
// whose period is orders of magnitude shorter than the observed cadence.
// A 5s clustering artifact in a stream with 43 000s median (ratio 1/8600)
// is clearly implausible. Derived at the call site as ivMedian/5.
//
// Span-aware upper bound (window/3, internal): a period longer than one
// third of the observation window is supported by fewer than three
// complete cycles. The DC-correction in rayleighPower removes systematic
// windowing-bias (which was the dominant source of spurious long-period
// peaks). The window/3 floor is the residual minimum-cycles guard.
// TestSpectralScore_PlausibilityGate_LongPeriodNoise validates that N=6500
// uniform-random timestamps over 9 months produce no FAP-clearing peaks
// in the plausible range with the corrected implementation.
//
// The span cap is intentionally separate from maxPlausiblePeriod. The
// ivMedian×N symmetric gate blocked burst-connect beacons (a C2 that
// connects 10 times in a burst then goes quiet for 23h has ivMedian≈360s
// and true period≈86400s — ratio 240×). The span cap does not suppress
// this: 10 daily cycles span 864 000s, so window/3 = 288 000s >> 86 400s.
// Pass maxPlausiblePeriod <= 0 to skip the explicit upper bound (only the
// span cap applies). Pass minPlausiblePeriod <= 0 to disable rescue.
//
// minObservations and fapThreshold are passed through from config so
// operators can tune. Defaults documented in config.go.
func spectralScore(timestamps []float64, minObservations int, fapThreshold float64, minPlausiblePeriod, maxPlausiblePeriod float64) SpectralResult {
	// Without a lower-bound reference point the rescue is unconstrained.
	if minPlausiblePeriod <= 0 {
		return SpectralResult{}
	}
	if len(timestamps) < minObservations {
		return SpectralResult{}
	}
	if minObservations < 8 {
		// Defensive floor below which the math is unreliable
		// regardless of operator config. Lomb-Scargle on fewer than
		// 8 observations produces spurious peaks at frequencies that
		// happen to align with two or three samples — sub-floor data
		// passes the algorithm but the output is noise.
		return SpectralResult{}
	}

	sorted := make([]float64, len(timestamps))
	copy(sorted, timestamps)
	sort.Float64s(sorted)
	window := sorted[len(sorted)-1] - sorted[0]
	if window <= 0 {
		return SpectralResult{}
	}

	const (
		minPeriod = 5.0
		// nFreqs controls grid resolution. Peak width in the
		// periodogram is ~ period/window (relative), so for a typical
		// hunt session (W ≈ 3600..86400s) and beacon period 60s, the
		// peak is 0.07% to 1.7% wide. 2000 points gives ~0.34%
		// relative spacing, half the worst-case peak width, so the
		// scan reliably catches the peak. CPU cost stays bounded:
		// 2000 grid × 2000 reservoir = 4M trig pairs per pair,
		// ~200ms each on modern hardware, gated to pairs where
		// statistical scoring failed.
		nFreqs = 2000
	)
	maxPeriod := window / 2.0
	if maxPeriod < minPeriod {
		return SpectralResult{}
	}

	logMin := math.Log(minPeriod)
	logMax := math.Log(maxPeriod)
	// Minimum-cycles floor: require at least 3 complete cycles to claim
	// a period is real. Below this floor the periodogram sees fewer than
	// 3 peaks to align, making statistical confidence marginal regardless
	// of power. The DC-correction in rayleighPower handles the main
	// windowing-bias source; this cap is the residual reliability guard.
	maxReliablePeriod := window / 3.0
	// Track both the overall dominant peak (may be an artifact) and the
	// strongest peak within the plausible period range separately. This
	// prevents a burst-clustering artifact from overshadowing a weaker
	// but genuine periodic signal at a plausible cadence.
	var bestPower, bestPeriod float64
	var plausiblePower, plausiblePeriod float64
	for i := 0; i < nFreqs; i++ {
		p := math.Exp(logMin + (logMax-logMin)*float64(i)/float64(nFreqs-1))
		omega := 2 * math.Pi / p
		power := rayleighPower(sorted, omega)
		if power > bestPower {
			bestPower = power
			bestPeriod = p
		}
		aboveMin := p >= minPlausiblePeriod
		belowMax := p <= maxReliablePeriod && (maxPlausiblePeriod <= 0 || p <= maxPlausiblePeriod)
		if aboveMin && belowMax && power > plausiblePower {
			plausiblePower = power
			plausiblePeriod = p
		}
	}

	if plausiblePower < fapThreshold {
		// No plausible periodic signal above noise.
		res := SpectralResult{Period: plausiblePeriod, RawPower: plausiblePower}
		// If a strong peak existed but was outside the plausible range,
		// record it so the call site can log the rejected artifact.
		if bestPower >= fapThreshold && bestPeriod != plausiblePeriod {
			res.DominantPeriod = bestPeriod
			res.DominantPower = bestPower
		}
		return res
	}

	// Normalise: linear from 0 at threshold to 1 at 2×threshold. A
	// peak that just barely crosses the FAP cutoff doesn't deserve
	// to dominate the composite score, but a peak well past it
	// should ceiling at the same 1.0 the statistical detector
	// produces on a perfectly-regular beacon.
	score := (plausiblePower - fapThreshold) / fapThreshold
	if score > 1.0 {
		score = 1.0
	}
	res := SpectralResult{Score: score, Period: plausiblePeriod, RawPower: plausiblePower}
	// If a stronger artifact peak exists outside the plausible range,
	// record it for calibration diagnostics in the detail string.
	if bestPeriod != plausiblePeriod && bestPower > plausiblePower {
		res.DominantPeriod = bestPeriod
		res.DominantPower = bestPower
	}
	return res
}
