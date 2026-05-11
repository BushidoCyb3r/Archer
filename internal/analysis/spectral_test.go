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

	res := spectralScore(timestamps, 16, 12.0)
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

	res := spectralScore(timestamps, 16, 12.0)
	if res.Score < 0.3 {
		t.Errorf("Score = %.3f; want >= 0.3 for a jittered beacon at σ/T ≈ 0.3 (the case statistical math misses)", res.Score)
	}
	if math.Abs(res.Period-period)/period > 0.15 {
		t.Errorf("Period = %.2f; want 60.0 ± 15%% (jitter widens the peak)", res.Period)
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

	res := spectralScore(timestamps, 16, 12.0)
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
	res := spectralScore(timestamps, 16, 12.0)
	if res.Score != 0 {
		t.Errorf("Score = %.3f for 6 samples (floor=16); want 0", res.Score)
	}
	// Below 8 absolute floor: should also return 0 regardless of cfg.
	res = spectralScore(timestamps, 4, 12.0)
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
	res := spectralScore(timestamps, 16, 12.0)
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

	first := spectralScore(timestamps, 16, 12.0)
	for trial := 0; trial < 5; trial++ {
		got := spectralScore(timestamps, 16, 12.0)
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
		_ = spectralScore(timestamps, 16, 12.0)
	}
}
