# jittered_beacon

100 connections at period 60s with ±30s bounded jitter (CV ≈ 0.38)
from `192.168.1.50` to `198.51.100.77:443`. 100 samples pushes
`beaconConfMod` to 1.0.

## What this scenario exercises

This is a **regression baseline** for the spectral beacon-detection
augmentation added alongside the existing
Bowley/MAD/multimodal/entropy timing-axis pipeline. The fixture
exercises:

1. A jittered beacon (CV > the tight-beacon range the original
   Bowley/MAD math handles cleanly).
2. The full statistical-augmentation chain — multimodal +
   entropy — already in place pre-spectral.
3. The spectral wiring path, which is invoked when
   `cfg.SpectralEnabled && tsScore < SpectralRescueThreshold`.

On this fixture the entropy/multimodal augmentations score the
beacon high enough that the spectral rescue gate doesn't fire
(`tsScore=0.68` > the default `SpectralRescueThreshold=0.5`),
so the expected finding's Detail has no "Spectral rescue:" tag.
The baseline asserts that spectral integration doesn't break
detection on the kind of beacon the existing math handles.

## What this scenario does NOT exercise

The spectral rescue path firing on a beacon the statistical
pipeline genuinely misses. That requires inputs where Bowley + MAD
+ multimodal + entropy all simultaneously score low (`tsScore <
0.5`) but a Lomb-Scargle peak survives (`σ/period < 0.45`,
sample count ≥ 16). Constructing such a fixture synthetically is
fragile — the existing statistical augmentations are robust
enough that any plausibly-realistic jittered signal triggers
multimodal or entropy first.

The spectral algorithm itself is verified by
`internal/analysis/spectral_test.go` — perfect-period detection,
jittered-beacon detection at CV ≈ 0.3, Poisson-noise rejection
above the false-alarm threshold, defensive zero-window handling,
and deterministic output across trials. Rescue-band calibration
on real captures is operator work, not synthetic-test work.

## Expected output

One `Beaconing` finding plus the host-risk roll-up. The Detail
string carries the standard `ts/ds/hist/dur` components; no
"Spectral rescue:" tag because the rescue gate didn't open on
this fixture.
