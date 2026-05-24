package analysis

import (
	"math"
	"math/rand/v2"
	"testing"
)

// TestSpectralScore_PerfectPeriodicSignal verifies the algorithm
// correctly identifies a perfectly periodic series. A beacon every
// 60s for 100 connections (no jitter) should score very high. The
// reported period may be the fundamental OR any integer divisor of
// it (perfect periodicity puts identical power at every harmonic;
// the log-spaced grid resolves whichever harmonic it hits first).
// Real-world data has jitter that naturally suppresses harmonics —
// see the jittered-beacon test for the realistic case.
func TestSpectralScore_PerfectPeriodicSignal(t *testing.T) {
	const period = 60.0
	const n = 100
	timestamps := make([]float64, n)
	for i := 0; i < n; i++ {
		timestamps[i] = float64(i) * period
	}

	// Wide plausible range so the test exercises the detection path, not the gate.
	res := spectralScore(timestamps, 16, 12.0, 1, math.MaxFloat64)
	if res.Score < 0.99 {
		t.Errorf("Score = %.3f; want >= 0.99 for a perfectly periodic signal", res.Score)
	}
	// Accept the fundamental or any harmonic — period must be such
	// that fundamental/period is a small integer (1, 2, 3, …, 12 for
	// our grid floor of 5s).
	ratio := period / res.Period
	rounded := math.Round(ratio)
	if rounded < 1 || math.Abs(ratio-rounded)/ratio > 0.05 {
		t.Errorf("Period = %.2f; want a divisor of %.0f (the fundamental or one of its harmonics)", res.Period, period)
	}
}

// TestSpectralScore_JitteredBeacon is the canonical rescue case —
// the exact signal shape the statistical detector explicitly misses.
// 150 connections targeting a 60s schedule with ±18s bounded jitter
// around each target. Real C2 jitter is bounded around a reference
// clock, not IID-accumulating (which would make the phase drift
// monotonically and destroy periodicity). At per-interval CV ≈ 0.3
// the Bowley/MAD math scores low; the spectral peak should still be
// clearly above the FAP threshold.
func TestSpectralScore_JitteredBeacon(t *testing.T) {
	const period = 60.0
	const sigma = 18.0
	const n = 150
	rng := rand.New(rand.NewPCG(42, 42))

	timestamps := make([]float64, n)
	for i := 0; i < n; i++ {
		// Bounded jitter around target schedule i*period. Each
		// timestamp is independently jittered — phase doesn't
		// accumulate. Uniform(-sigma, sigma) bounds the deviation.
		timestamps[i] = float64(i)*period + (rng.Float64()*2-1)*sigma
	}

	res := spectralScore(timestamps, 16, 12.0, 1, math.MaxFloat64)
	if res.Score < 0.3 {
		t.Errorf("Score = %.3f; want >= 0.3 for a jittered beacon at σ/T ≈ 0.3 (the case statistical math misses)", res.Score)
	}
	if math.Abs(res.Period-period)/period > 0.15 {
		t.Errorf("Period = %.2f; want 60.0 ± 15%% (jitter widens the peak)", res.Period)
	}
	// Confirm DC-correction did not reduce sensitivity below FAP=12.
	if res.RawPower < 12 {
		t.Errorf("RawPower = %.1f; want >= 12 (FAP threshold) — DC-correction must not deafen the detector", res.RawPower)
	}
}

// TestSpectralScore_PoissonNoise verifies the null hypothesis. A
// random Poisson-arrival stream has no periodic structure; Lomb-
// Scargle should produce peaks consistent with FAP noise, and the
// thresholded score should be zero.
func TestSpectralScore_PoissonNoise(t *testing.T) {
	const n = 200
	const meanInterval = 60.0
	rng := rand.New(rand.NewPCG(7, 7))

	timestamps := make([]float64, n)
	t0 := 0.0
	for i := 0; i < n; i++ {
		// Exponential inter-arrival times → Poisson process.
		t0 += -meanInterval * math.Log(1-rng.Float64())
		timestamps[i] = t0
	}

	res := spectralScore(timestamps, 16, 12.0, 1, math.MaxFloat64)
	// Poisson noise occasionally produces a peak that crosses the
	// FAP threshold — that's the "false alarm" the threshold names.
	// At FAP_threshold=12 and M=200 frequencies tested, the
	// expected per-frequency p ≈ exp(-12) ≈ 6e-6, so M*p ≈ 1.2e-3 —
	// about 0.12% of test runs would see a spurious peak with this
	// RNG seed. Setting Score >= 0.5 as the loud-failure tolerance:
	// even if a noise peak crosses the threshold, it shouldn't
	// strongly suggest periodicity.
	if res.Score >= 0.5 {
		t.Errorf("Score = %.3f for pure Poisson noise; expected near-zero or modest false-alarm (threshold=12)", res.Score)
	}
}

// TestSpectralScore_BelowFloor verifies the minObservations guard.
// Below the floor the function returns zero without attempting the
// computation — the math is unreliable on too few samples.
func TestSpectralScore_BelowFloor(t *testing.T) {
	timestamps := []float64{0, 60, 120, 180, 240, 300} // 6 samples
	res := spectralScore(timestamps, 16, 12.0, 1, math.MaxFloat64)
	if res.Score != 0 {
		t.Errorf("Score = %.3f for 6 samples (floor=16); want 0", res.Score)
	}
	// Below 8 absolute floor: should also return 0 regardless of cfg.
	res = spectralScore(timestamps, 4, 12.0, 1, math.MaxFloat64)
	if res.Score != 0 {
		t.Errorf("Score = %.3f with min_obs=4 (defensive floor=8); want 0", res.Score)
	}
}

// TestSpectralScore_ZeroWindow verifies degenerate inputs where all
// timestamps are identical (window = 0). Real data won't produce this
// but the function must not panic or NaN.
func TestSpectralScore_ZeroWindow(t *testing.T) {
	timestamps := make([]float64, 20)
	for i := range timestamps {
		timestamps[i] = 1000.0
	}
	res := spectralScore(timestamps, 16, 12.0, 1, math.MaxFloat64)
	if res.Score != 0 {
		t.Errorf("Score = %.3f for zero-window input; want 0", res.Score)
	}
}

// TestSpectralScore_Deterministic verifies the algorithm produces
// identical output across 5 runs on identical input. Lomb-Scargle is
// deterministic (no randomness), but a future optimisation that
// e.g. parallelises frequency evaluation could accidentally break
// this. The test guards the property.
func TestSpectralScore_Deterministic(t *testing.T) {
	const period = 60.0
	timestamps := make([]float64, 100)
	for i := range timestamps {
		timestamps[i] = float64(i) * period
	}

	first := spectralScore(timestamps, 16, 12.0, 1, math.MaxFloat64)
	for trial := 0; trial < 5; trial++ {
		got := spectralScore(timestamps, 16, 12.0, 1, math.MaxFloat64)
		if got.Score != first.Score || got.Period != first.Period || got.RawPower != first.RawPower {
			t.Errorf("trial %d: non-deterministic output. first=%+v got=%+v", trial, first, got)
		}
	}
}

// TestRayleighPower_KnownValue is a regression check on the core
// math. For N perfectly-periodic impulses evaluated at the true
// frequency, P(omega) should equal N: every cos term hits 1, every
// sin term hits 0, so cSum² + sSum² = N² and dividing by N gives N.
// FAP threshold of 12 is easily crossed for N >= 13.
func TestRayleighPower_KnownValue(t *testing.T) {
	const period = 10.0
	const n = 20
	timestamps := make([]float64, n)
	for i := 0; i < n; i++ {
		timestamps[i] = float64(i) * period
	}
	omega := 2 * math.Pi / period
	power := rayleighPower(timestamps, omega)
	// At the true frequency with N=20, expected power ≈ N = 20.
	// Allow small numerical wiggle.
	if math.Abs(power-float64(n)) > 0.1 {
		t.Errorf("Rayleigh power at the true frequency = %.4f; want ≈ N = %d", power, n)
	}
}

// TestSpectralScore_PlausibilityGate_ArtifactRejected verifies that a
// strong burst-clustering artifact whose period is far below the lower
// plausibility bound is rejected and does not produce a rescue score.
// This is the core false-positive suppression the gate was added for:
// reservoir sampling of a bursty connection stream can produce a tight
// cluster of timestamps that yields a strong Lomb-Scargle peak at a
// very short period (5–10s) even though the pair's median inter-arrival
// is hours. Before the gate, this produced CRITICAL beaconing findings
// on long-lived management sessions.
//
// The gate is lower-bound only (no upper bound). Any period shorter
// than ivMedian/5 is implausible; any period longer is allowed —
// because burst-connect beacons (connect 10×/hour, silent 23h) have
// true spectral periods >> median inter-arrival interval.
func TestSpectralScore_PlausibilityGate_ArtifactRejected(t *testing.T) {
	// Simulate the false-positive: a 60s periodic signal embedded in a
	// stream whose median inter-arrival is 26 280s (~7h 18m, matching
	// the production case). 60s << 26280/5 = 5256s → rejected.
	const period = 60.0
	const n = 100
	const medianInterval = 26280.0
	timestamps := make([]float64, n)
	for i := 0; i < n; i++ {
		timestamps[i] = float64(i) * period
	}

	minP := medianInterval / 5.0 // 5256s — lower bound only
	res := spectralScore(timestamps, 16, 12.0, minP, 0)

	if res.Score > 0 {
		t.Errorf("Score = %.3f; want 0: the 60s artifact at 1/%.0f of median should be rejected by the lower-bound plausibility gate", res.Score, medianInterval/period)
	}
	// The artifact should be reported in DominantPeriod so the call site
	// can log it for calibration.
	if res.DominantPeriod == 0 {
		t.Errorf("DominantPeriod = 0; want the rejected artifact period to be populated")
	}
}

// TestSpectralScore_PlausibilityGate_BurstConnectBeaconPasses verifies
// that a burst-connect beacon with true period >> median inter-arrival
// is NOT blocked by the gate. This is the false-negative case the old
// symmetric gate introduced: a beacon that connects 10×/hour in a
// burst then goes quiet for 23h has ivMedian ≈ 360s and true period ≈
// 86400s. The 5×upper gate blocked it; the lower-bound-only gate
// correctly allows it.
func TestSpectralScore_PlausibilityGate_BurstConnectBeaconPasses(t *testing.T) {
	// Burst-connect pattern: 6 connections at 60s intervals, then 23h
	// silence, repeating for 10 days. True period = 86400s.
	const burstInterval = 60.0
	const burstSize = 6
	const cycleLen = 86400.0
	const cycles = 10
	n := cycles * burstSize
	timestamps := make([]float64, n)
	for c := 0; c < cycles; c++ {
		for b := 0; b < burstSize; b++ {
			timestamps[c*burstSize+b] = float64(c)*cycleLen + float64(b)*burstInterval
		}
	}
	// ivMedian ≈ 60s (within-burst interval dominates the sorted IVs).
	// The plausible lower bound is 60/5 = 12s. The true 86400s period is
	// 86400/12 = 7200× above the lower bound — it passes the gate.
	minP := burstInterval / 5.0 // 12s
	res := spectralScore(timestamps, 16, 12.0, minP, 0)
	if res.Score < 0.5 {
		t.Errorf("Score = %.3f; want >= 0.5: burst-connect beacon (period 86400s, ivMedian 60s) should pass the lower-bound-only gate", res.Score)
	}
	// Confirm DC-correction did not reduce power below FAP for a signal with
	// near-integer window/period cycles (9.0 cycles here).
	if res.RawPower < 12 {
		t.Errorf("RawPower = %.1f; want >= 12 — DC-correction must leave near-integer-cycle beacons above FAP", res.RawPower)
	}
}

// TestSpectralScore_PlausibilityGate_RealBeaconPasses verifies that a
// plausible beacon signal passes the gate. A 60s beacon evaluated with
// a lower bound of 12s (ivMedian/5) should score well.
func TestSpectralScore_PlausibilityGate_RealBeaconPasses(t *testing.T) {
	const period = 60.0
	const n = 100
	timestamps := make([]float64, n)
	for i := 0; i < n; i++ {
		timestamps[i] = float64(i) * period
	}

	// Lower bound: period/5 = 12s. No upper bound (pass 0).
	res := spectralScore(timestamps, 16, 12.0, period/5.0, 0)
	if res.Score < 0.99 {
		t.Errorf("Score = %.3f; want >= 0.99: a 60s beacon with lower bound 12s should rescue", res.Score)
	}
}

// TestSpectralScore_PlausibilityGate_InvalidBounds verifies that
// zero or negative minPlausiblePeriod disables rescue entirely. The
// call site derives minP from ivMedian, which is zero when no intervals
// exist. maxPlausiblePeriod <= 0 means "no upper bound" (not disabled).
func TestSpectralScore_PlausibilityGate_InvalidBounds(t *testing.T) {
	const period = 60.0
	timestamps := make([]float64, 100)
	for i := range timestamps {
		timestamps[i] = float64(i) * period
	}

	// Zero or negative minP disables rescue.
	for _, minP := range []float64{0, -1, -100} {
		res := spectralScore(timestamps, 16, 12.0, minP, 0)
		if res.Score != 0 {
			t.Errorf("minP=%.0f: Score = %.3f; want 0 (invalid lower bound must disable rescue)", minP, res.Score)
		}
	}
	// maxP <= 0 means no upper bound, NOT disabled — beacon should still score.
	res := spectralScore(timestamps, 16, 12.0, 1, 0)
	if res.Score < 0.99 {
		t.Errorf("maxP=0 should mean no upper bound; Score = %.3f; want >= 0.99", res.Score)
	}
}

// TestSpectralScore_PlausibilityGate_LongPeriodNoise validates that the
// DC-corrected Rayleigh periodogram does not produce spurious FAP-clearing
// peaks at long periods on genuinely random data.
//
// Before the DC-correction, the naive Rayleigh form had systematic bias
// ∝ N/(2k+1)² at periods T/(k+0.5) for integer k. For N=6500 over 9
// months, the k=4 bias peak reached expected power≈34 at FAP=12 —
// a systematic false-positive, not a tail-of-distribution false alarm.
// The correction subtracts the expected means, restoring the Exp(1) null.
//
// Test design: 200 seeds × N=500 uniform timestamps over a 9-month window.
// N=500 keeps the per-seed cost low; the window length (not N) is the
// variable that revealed the original bias. The assertion is rate-based:
// the observed exceedance fraction must stay within 4× the theoretical
// per-seed false-alarm probability (nominalP ≈ 0.007), not a magic count.
//
// Calibration:
//
//	nominalP ≈ 920 effective grid points × exp(-12) ≈ 0.006–0.007.
//	Under Binomial(200, 0.007): μ=1.4, 4×nominal bound = 5.6 obs, which
//	sits at the 99.8th percentile — false-flap rate < 0.2%.
//	A 3× degraded implementation (true p ≈ 0.021) produces >5 exceedances
//	about 35% of the time, making regression visible within a few CI runs.
//
// strongCount==0 is a separate zero-tolerance gate: a Score>=0.5 peak
// (power>=18) has expected count 200 × 920 × exp(-18) ≈ 3e-3 per full
// run — this should never happen under a correct null.
func TestSpectralScore_PlausibilityGate_LongPeriodNoise(t *testing.T) {
	const n = 500
	const duration = 23_400_000.0 // 9 months in seconds
	const seeds = 200
	// Nominal per-seed exceedance probability under the corrected Exp(1) null.
	// Plausible range [minP, window/3] spans ~46% of the log-spaced grid's
	// 2000 points → ~920 effective frequencies. Nominal = 920 × exp(-12) ≈ 0.006.
	// Using 0.007 to absorb grid-spacing discretisation at window boundaries.
	const nominalP = 0.007

	minP := (duration / n) / 5.0 // ivMedian/5 for this density

	var exceedCount, strongCount int
	for seed := uint64(0); seed < seeds; seed++ {
		rng := rand.New(rand.NewPCG(seed, seed^0xdeadbeef))
		timestamps := make([]float64, n)
		for i := range timestamps {
			timestamps[i] = rng.Float64() * duration
		}
		res := spectralScore(timestamps, 16, 12.0, minP, 0)
		if res.Score > 0 {
			exceedCount++
		}
		if res.Score >= 0.5 {
			strongCount++
			t.Logf("seed %d: Score=%.3f power=%.1f period=%.0fs (%.3f×window)",
				seed, res.Score, res.RawPower, res.Period, res.Period/duration)
		}
	}

	// Rate-based assertion: observed fraction must be ≤ 4× nominal.
	// With 200 seeds and nominalP=0.007, the 4× bound (0.028 → ≤5 obs)
	// is at the 99.8th percentile of the correct null — <0.2% false flap.
	observedRate := float64(exceedCount) / float64(seeds)
	if observedRate > 4*nominalP {
		t.Errorf("observed exceedance rate %.4f > 4×nominal %.4f (%d/%d seeds had Score > 0); "+
			"DC-correction may be leaking — check rayleighPower mean subtraction",
			observedRate, 4*nominalP, exceedCount, seeds)
	}
	if strongCount > 0 {
		t.Errorf("%d/%d seeds produced Score >= 0.5; want 0 — "+
			"strong long-period peaks indicate systematic bias surviving DC-correction",
			strongCount, seeds)
	}
}

// BenchmarkSpectralScore measures end-to-end cost on a representative
// pair — 200 timestamps (reservoir cap) over a 1-hour window. The
// rescue gate (only run when statistical scoring failed) bounds how
// often this fires per run; the per-pair cost has to be in the
// low-tens-of-ms range for the per-run total to stay reasonable.
func BenchmarkSpectralScore(b *testing.B) {
	const period = 60.0
	const sigma = 18.0
	const n = 200
	timestamps := make([]float64, n)
	for i := 0; i < n; i++ {
		timestamps[i] = float64(i) * period
	}
	_ = sigma
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = spectralScore(timestamps, 16, 12.0, 1, math.MaxFloat64)
	}
}
