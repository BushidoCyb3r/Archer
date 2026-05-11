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

// rayleighPower computes the Rayleigh (Schuster) periodogram power at
// a single angular frequency omega. This is the right form for impulse
// trains (timestamp periodicity, not amplitude periodicity):
//
//	P(omega) = (1/N) * [(Σ cos(omega*t_k))^2 + (Σ sin(omega*t_k))^2]
//
// Under the null hypothesis (random Poisson arrivals, no periodicity)
// the power is exponentially distributed with mean 1.0, so a peak of
// e.g. 12 means false-alarm probability ≈ exp(-12) ≈ 6e-6 per frequency
// tested. With M=200 grid points, expected total FAP at threshold 12
// is M·exp(-12) ≈ 0.001 — about one false alarm per thousand
// background-noise pair evaluations, which matches Archer's
// noise-tolerance budget.
//
// Why Rayleigh, not the more-general Lomb-Scargle with tau-adjustment.
// The classical Lomb-Scargle adds a phase-reference shift (tau =
// atan2(Σ sin(2ωt), Σ cos(2ωt)) / 2ω) so the sin/cos basis is
// orthogonal at the data's exact phase distribution. For amplitude
// time series (astronomy, the original use case) this matters. For
// impulse trains where every event has the same y_k = 1, tau is
// degenerate at the fundamental of a uniformly-spaced signal —
// sin² accumulates to zero, causing a divide-by-zero or numerical
// flake. The Rayleigh form sidesteps this without losing detection
// power: harmonics still appear at their true positions, the
// fundamental wins for any signal with non-trivial jitter, and the
// null-distribution mean-1 property holds.
//
// O(N) per call. Each timestamp is a unit-height impulse — we score
// whether events cluster at a particular phase, not whether their
// amplitude oscillates.
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
	return (cSum*cSum + sSum*sSum) / float64(n)
}

// SpectralResult is the per-pair output of spectralScore. Returned
// rather than via multiple values so the caller doesn't have to
// remember the order; the Detail-string renderer in conn.go and
// http_analysis.go uses Period and Power independently of Score.
type SpectralResult struct {
	// Score in [0, 1]. 0 = no periodicity above noise; 1 = strongly
	// periodic, well past the false-alarm threshold. Linearly
	// proportional to log-confidence above the threshold, clamped at
	// 1 once the peak is 2× the threshold.
	Score float64
	// Period in seconds at the spectral peak. Meaningful only when
	// Score > 0 — below the FAP threshold the peak is noise.
	Period float64
	// RawPower is the un-normalised Lomb-Scargle value at the peak,
	// useful for logging and threshold calibration. Compare against
	// FAPThreshold to understand "how far above noise" the peak sat.
	RawPower float64
}

// spectralScore runs Lomb-Scargle over a logarithmically-spaced
// period grid and returns the strongest peak and its score.
//
// Algorithm:
//  1. Sort timestamps (Lomb-Scargle requires nothing of order but
//     downstream consumers want a chronological sequence anyway).
//  2. Compute observation window = last - first. Period grid spans
//     5s (the floor below which Archer's analysts don't care; ICMP
//     ping is faster than that but isn't C2-relevant) to window/2
//     (the Nyquist limit — can't reliably detect a period longer
//     than half the observation span).
//  3. 200 log-spaced periods. Log spacing matches how operators
//     think about beacons (60s, 600s, 3600s — orders of magnitude
//     apart matter more than absolute deltas).
//  4. Evaluate Lomb-Scargle power at each period, track the peak.
//  5. Compare peak to false-alarm threshold. Below threshold →
//     return zero (the peak is noise). Above → return normalised
//     score.
//
// minObservations and fapThreshold are passed through from config so
// operators can tune. Defaults documented in config.go.
func spectralScore(timestamps []float64, minObservations int, fapThreshold float64) SpectralResult {
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
		// peak is 0.07% to 1.7% wide. 200 points across log(5..W/2)
		// is too coarse — peaks get skipped between grid points. 2000
		// points gives ~0.34% relative spacing, half the worst-case
		// peak width, so the bestPower iteration reliably catches the
		// peak. CPU cost stays bounded: 2000 grid × 200 reservoir =
		// 400K trig pairs per pair, ~20 ms each on modern hardware.
		// For 1000 pairs in a run that's 20 seconds of spectral work,
		// gated to pairs where statistical scoring failed (see
		// SpectralRescueThreshold in the call site).
		nFreqs = 2000
	)
	maxPeriod := window / 2.0
	if maxPeriod < minPeriod {
		return SpectralResult{}
	}

	logMin := math.Log(minPeriod)
	logMax := math.Log(maxPeriod)
	var bestPower, bestPeriod float64
	for i := 0; i < nFreqs; i++ {
		p := math.Exp(logMin + (logMax-logMin)*float64(i)/float64(nFreqs-1))
		omega := 2 * math.Pi / p
		power := rayleighPower(sorted, omega)
		if power > bestPower {
			bestPower = power
			bestPeriod = p
		}
	}

	if bestPower < fapThreshold {
		// Peak is consistent with random Poisson arrivals; return
		// the period (useful for debug) but score zero so the
		// rescue pattern at the call site treats this as "no
		// rescue."
		return SpectralResult{Period: bestPeriod, RawPower: bestPower}
	}

	// Normalise: linear from 0 at threshold to 1 at 2×threshold. A
	// peak that just barely crosses the FAP cutoff doesn't deserve
	// to dominate the composite score, but a peak well past it
	// should ceiling at the same 1.0 the statistical detector
	// produces on a perfectly-regular beacon.
	score := (bestPower - fapThreshold) / fapThreshold
	if score > 1.0 {
		score = 1.0
	}
	return SpectralResult{Score: score, Period: bestPeriod, RawPower: bestPower}
}
