# Spectral Rescue Tuning Manual

An operator's guide to dialing in the spectral path's false-positive
vs. true-positive trade-off against your traffic. The math is in
`docs/DETECTION_METHODS.md` §2 — this doc is the *how-to-tune-it*
companion.

> **Default values ship calibrated for typical enterprise traffic.**
> If you're seeing reasonable Beaconing findings and no flood of
> spectral-rescued false positives, you don't need this doc.

---

## When you need this doc

Tune the spectral knobs when one of these is happening:

1. **Too many spectral-rescued findings to triage** — the rescue path
   is catching things that turn out to be operational noise (cron
   jobs, health probes, NTP, RSS pollers, backup clients).
2. **A known C2 sample escapes detection** — you have ground truth
   (a red-team exercise, a known-bad capture, a malware-lab pcap)
   and the rescue path isn't firing on it.
3. **Per-run cost is too high** — analyze passes are slower than
   acceptable and spectral overhead is measurable in the run timing.
4. **You're calibrating for a non-typical environment** — air-gap
   networks, OT/ICS captures, or anywhere the baseline timing
   distributions look different from enterprise IT traffic.

Otherwise: leave the knobs alone.

---

## The plausibility gate and span cap

Neither is a tunable knob — both are fixed correctness guards.

### Lower-bound gate (`ivMedian / 5`)

A rescued period must be ≥ `ivMedian / 5`. Any peak shorter than that is
burst-structure noise: the periodogram is finding intra-burst rhythm, not
beacon cadence. The gate is lower-bound only — no upper bound — because
burst-connect beacons (C2 that opens several connections in a burst then
goes quiet for hours) have a legitimate spectral period far above `ivMedian`.
An upper bound would suppress those real detections.

### Span cap (`window / 3`, internal)

The scan also excludes periods longer than one-third of the observation
window. A period that long is supported by fewer than three complete
cycles, making statistical confidence marginal. This cap is the primary
mechanism excluding very-long-period leakage artifacts when observation
windows are short (29–43 days for 1 Ms-class artifacts). DC-correction
reduces but does not zero these peaks; the span cap excludes them from
the plausible range.

**Important:** as deployment windows grow, peaks that previously sat above
`window/3` enter the plausible range. A pair whose corpus-spotcheck Section
2 row shows `[artifact 1.25Ms suppressed]` at a 30-day window may produce
a 1.25 Ms rescue at a 45-day window if that peak retains higher power than
the shorter plausible winner. Run `corpus-spotcheck.sh` after each corpus
extension to confirm behavior hasn't changed.

### The `[artifact Xs suppressed]` detail tag

This tag means the rescue *succeeded* on a shorter period, and a longer
peak with higher raw power was excluded by the span cap — not by the gate,
not by DC-correction zeroing it. That longer peak crossed FAP=12 and
outranked the winner on raw power; only the span cap kept it out. This is
the class to watch in Section 2 of the spotcheck.

### When a rescue is fully blocked

If both mechanisms reject the only strong periodogram peak, the pair still
emits a beacon finding via the statistical path — it just doesn't receive
the spectral score boost. The blocked count is recorded per run in
`analysis_stats` and appears in Section 3 of `corpus-spotcheck.sh`. Two
populations contribute: low-ratio hits (ratio < 0.2, lower-bound gate)
and high-ratio hits (ratio >> 1, span cap with < 3 cycles). Non-zero
counts are normal. A sudden spike warrants checking whether a legitimately
periodic pair is being systematically under-scored.

### Validation

After any analysis run: `bash corpus-spotcheck.sh`. Exit 0 means no rescued
finding violates the lower-bound gate. Run it after every full re-analysis
when the spectral code or corpus changes.

---

## The four knobs

All four live in **Settings → Beaconing**. Each one shifts a
different trade-off.

> As of v0.25.0 these same four knobs also govern the timing axis of
> the **DNS Beaconing** detector (`docs/DETECTION_METHODS.md` §9.6) —
> it reuses the identical statistical→multimodal→entropy→Lomb-Scargle
> pipeline on `(src, apex)` query timing. There are no
> DNS-beacon-specific spectral knobs; tuning here moves conn-level,
> HTTP, and DNS beacon rescue together.

### 1. Enable spectral rescue *(default: ON)*

The master kill switch. Off means the spectral path never runs;
Beaconing scoring falls back to the three statistical paths
(Bowley + MAD, multimodal-peak, entropy-on-occupancy). The
statistical paths are still strong on tight beacons — turning
spectral off doesn't blind the detector, it just gives up on the
bounded-jitter shape.

**Turn off when:**
- Real-corpus calibration shows the false-positive rate dominates
  the value of the catches, *and* you've already tried tuning the
  other three knobs.
- You're running an analyze pass on a constrained host and the
  ~4 ms/pair overhead matters.
- You're isolating which detection path is responsible for a
  noisy finding — flipping spectral off and re-running tells you
  whether the finding survives without it.

**Leave on otherwise.** The rescue catches a class of beacons
the statistical paths can't see (σ/period < ~0.45 jittered C2),
and the per-run cost on a typical hunt session is a few seconds.

### 2. Min observations *(default: 16, hard floor: 8)*

Minimum number of timestamps the spectral ring buffer must hold before the
spectral path will run. Below this number Lomb-Scargle output
becomes unreliable — too few points to resolve a periodogram peak
above the noise floor.

| Value | Effect |
|---|---|
| **8** (the hard floor) | Maximum sensitivity; fires on the smallest viable pairs. Higher FP rate. |
| **16** (default) | Balanced. Suitable for typical beacon analysis runs. |
| **24-32** | More conservative. Skips small-sample pairs that have weak statistical confidence. |
| **48+** | Aggressive filtering. Only fires on well-sampled long-running beacons. Misses ephemeral short-duration C2. |

**Raise it when:** small-sample false positives dominate (rare
HTTP polls that happen to look periodic over their 10-15
observations, then go silent).

**Lower it when:** you have ground truth on a short-duration
beacon escaping detection, and the Detail-line shows the ring
buffer was below threshold.

> **Below 8 is rejected by the analyzer regardless of config.**
> The math isn't trustworthy and the false-positive rate climbs
> nonlinearly.

### 3. FAP threshold *(default: 12)*

The Lomb-Scargle peak's power must exceed this value before the
rescue can fire. Lower is more permissive; higher is stricter.

Under the Rayleigh null hypothesis (random Poisson arrivals),
per-frequency false-alarm probability ≈ `exp(-FAP_threshold)`:

| Value | Per-frequency FAP | Reading |
|---|---|---|
| 9 | ≈ 1.2e-4 | Aggressive — catches weak peaks. Expect 5-20x more rescue fires than default. |
| 12 (default) | ≈ 6.1e-6 | Calibrated baseline. |
| 14 | ≈ 8.3e-7 | Conservative. |
| 16 | ≈ 1.1e-7 | Strict — only obvious frequency-domain structure. ~10x fewer fires than default. |
| 18 | ≈ 1.5e-8 | Very strict; you'll lose marginal jittered-beacon catches. |

**Raise it (stricter) when:** the rescue fires on legitimate
periodic traffic — cron jobs, scheduled health probes, RSS
pollers. Their Lomb-Scargle peaks are real but low-power; nudging
the threshold from 12 → 14 removes most without losing the
high-power true positives.

**Lower it (more permissive) when:** ground truth shows a known
jittered C2 sample's Detail line carries `Spectral rescue: ...
power=10.4 ...` against your FAP=12 — the peak was there, the
threshold was the gate that closed it.

> **Sanity check before adjusting:** read the actual `power=X`
> value in the Detail line of a few suspect findings. The number
> tells you whether the peak is borderline (power within 2 of
> threshold) or unambiguous (power 20+).

### 4. Rescue gate *(default: 0.5)*

The statistical timing-score threshold below which spectral is
allowed to run. The statistical paths handle obvious cases; the
rescue gate decides what counts as "the statistical path needs
help."

| Value | Effect |
|---|---|
| 0.3 | Restrictive — spectral only rescues pairs the statistical path scored ≤ 0.3 (clear failures). |
| 0.5 (default) | Balanced. Roughly: "the statistical path was unconvinced; let spectral try." |
| 0.7 | Permissive — spectral runs on most pairs (including ones that already scored medium-high). |
| 1.0 | Spectral runs on every pair regardless of statistical score. Cost goes up; rescue rate plateaus because the statistical path was usually right when it scored high. |

**Raise it when:** spectral catches a meaningful number of pairs
that the statistical path had partially-scored (~0.5-0.7) and
the rescue brings them clearly across the threshold. You're
trading CPU for catches.

**Lower it when:** the rescue is wasting cycles on
already-statistically-confident pairs that gained nothing from
spectral. Watch the CPU profile of an analyze pass; if the
spectral phase dominates and the rescue rate is low, the gate
is the dial.

---

## The iteration loop

There's no closed-form "tune to these numbers for your network"
recipe — you have to measure. The shape of the loop:

1. **Run an analyze pass with current settings.** Note: total
   Beaconing findings, count of spectral-rescued findings (filter
   chip on the Findings tab), CPU/wall time of the analyze phase.
2. **Triage the rescue chip.** Click each spectral-rescued
   finding. For each, decide: true positive (matches your
   threat model), false positive (clearly legitimate), or
   inconclusive.
3. **Adjust one knob at a time.** Multi-knob changes obscure
   which lever produced which effect.
4. **Re-run** ("Discard findings & re-analyze" from the
   admin menu — gives a clean full pass).
5. **Compare.** TP rate up + FP rate down = keep going in that
   direction. TP rate down = pull back.

Two anti-patterns to avoid:

- **Tuning on one suspect finding.** A single example doesn't
  generalize. Wait for at least 5-10 rescued findings to assess
  a knob direction.
- **Tuning on a recent pass that didn't include known-bad
  ground truth.** If you don't have positive examples in your
  capture, you're tuning the FP side blind — easy to over-tighten
  and break detection that didn't have a chance to show up.

---

## Reading the Detail line

The full diagnostic tag on a spectral-rescued finding looks
like:

```
Connections: 200 | Mean interval: 60.4s | CV: 0.32 |
Score components: ts=0.62 ds=0.85 hist=0.71 dur=0.40 conf=1.00 |
Spectral rescued: score=0.91 (dominant period 60.3s, power 37.2, FAP threshold 12.0)
```

Four numbers in the rescue tag, each telling you something
calibration-relevant:

| Field | What to read it for |
|---|---|
| `score=0.91` | The spectral path's contribution to the final `ts`. Above 0.7 = strong rescue; 0.5-0.7 = marginal. |
| `dominant period 60.3s` | What the implant's actual cadence appears to be. Match against known C2 default beacon intervals (CS 60s, Empire 5min) or against legitimate periodicity in your environment (cron `* */15 * * *` → 900s). |
| `power 37.2` | How far above the noise floor the peak rose. **This is the dial you most often need.** Power 12.1 against FAP=12 is borderline; power 37 against FAP=12 is unambiguous. |
| `FAP threshold 12.0` | What the threshold was on this run. Echoed so you can correlate against the active setting. |

**Common patterns:**

- **Cron job FP**: dominant period exactly 60s / 300s / 900s /
  3600s, low-medium power (15-25), regular as clockwork.
  Raising FAP threshold to 14-16 removes most without affecting
  jittered C2 (which usually has cleaner non-round periods).
- **Health probe FP**: very tight period (often <30s), high
  power, very persistent. Best handled via operator allowlist
  for the specific host:port, not by global threshold change.
- **Jittered C2 catch**: period in the 30-300s range, power
  20-50, ts statistical score below 0.5. The win.
- **Reservoir-underpopulated edge case**: only 8-12
  observations, dominant period near the window/2 cap.
  Generally raise min-observations.

**Evolution chart.** Days where spectral rescue was active are
marked with a distinct indicator on the 30-day score evolution
chart in the finding detail pane. This makes it easy to spot
when a beacon started relying on the spectral path — often a
sign of increasing jitter on the implant side, or of ring buffer
underpopulation on low-frequency channels.

---

## Common scenarios

### Scenario 1 — "Too many cron-job rescues"

Symptom: 30+ spectral-rescued findings per pass, most are
internal `cron.daily` → external NTP/RSS/update servers.

Approach:
1. Sample 5 of them. Verify Detail line shows power in the
   15-25 range (borderline) and round-number periods (60s,
   300s, 3600s).
2. Bump FAP threshold from 12 → 14. Re-analyze.
3. Re-count. If still too many, go 14 → 16. The cron-job
   pattern usually resolves between 14 and 16.

Don't:
- Disable spectral entirely. You lose the bounded-jitter catch
  surface to remove a class of FP that calibration can handle.
- Lower the rescue gate. That makes the FP cost-per-rescue
  worse, not better.

### Scenario 2 — "Known C2 sample isn't being caught"

Symptom: red-team / known-bad capture has a beacon at
60s ± 18s jitter; the finding's `ts` is below threshold but
the rescue didn't fire.

Approach:
1. Click the finding (or grep the export). Read the Detail
   line — does it have a `Spectral rescued:` tag at all?
2. **No tag:** rescue gate didn't open. Check the statistical
   `ts` score. If it's above the current rescue gate (default
   0.5), raise the gate to 0.6 or 0.7.
3. **Tag present but `score < tsScore`:** spectral ran but
   didn't win. Read the `power=X` value.
   - **Power well below FAP threshold:** Lomb-Scargle didn't
     find a peak. The jitter is high enough that frequency-
     domain doesn't help either; nothing to tune.
   - **Power near or above FAP threshold but score still low:**
     check min-observations. The ring buffer may have been small.

### Scenario 3 — "Analyze pass is too slow"

Symptom: spectral phase is taking minutes; you have thousands
of pairs.

Approach:
1. Profile or count: how many pairs fired spectral? Each pair
   is ~4 ms; 1000 pairs = ~4 seconds.
2. If the count is high and the rescue rate is low (e.g., 800
   pairs ran spectral, 12 got rescued), lower the rescue gate
   (0.5 → 0.3). Most of the work was on already-low-score
   pairs that spectral couldn't help.
3. If lowering the gate doesn't help: the ring buffer cap is
   the better dial — but that's an internal constant, not a
   setting.

### Scenario 4 — "I changed something and now I have no
spectral findings at all"

Likely you over-tightened. Walk it back one knob at a time:

1. FAP threshold: above 18, almost nothing fires. Drop to 14
   first.
2. Min observations: above 48, only very long-running beacons
   qualify. Drop to 24.
3. Rescue gate: below 0.3, spectral runs only on near-zero-ts
   pairs, which are usually pairs with too few observations
   anyway. Restore to 0.5.

If you forgot what you changed: revert all four knobs to the
defaults (16 / 12 / 0.5 / on) and re-run.

---

## What spectral can't be tuned around

The rescue path has hard limits. No knob will recover these:

- **σ/period > ~0.45**: the spectral peak itself washes out
  (sinc(π·σ/T) → 0). The signal is destroyed; rescuing it
  would mean flagging legitimate sporadic traffic too.
- **Pairs with fewer than 8 observations.** Hard-coded floor;
  the math doesn't work below it regardless of config.
- **Aperiodic implants** (true random scheduling, beacon-on-
  event-not-time). Spectral assumes periodicity exists to be
  found.
- **Single-shot or short-burst activity** that doesn't span
  enough of the analysis window. The ring buffer won't hold
  enough timestamps.
- **Pairs whose only strong peak is below `ivMedian/5`.**
  The plausibility gate blocks these as burst-structure noise.
  They still emit beacon findings via the statistical path;
  only the spectral score boost is suppressed.
- **High-frequency local traffic with genuine long-period structure.**
  mDNS pairs (`_tcp.local`, `_udp.local`) and similar broadcast
  traffic with sub-30 s median intervals accumulate enough
  observations to produce real weekday/weekend periodogram peaks
  at 6–10 day periods. These cross FAP=12 after DC-correction
  because the structure is genuine, not an artifact. The detector
  cannot distinguish "real weekly rhythm" from "weekly C2 cadence"
  without additional signal. Allowlist known-benign mDNS pairs, or
  confirm a spectral-rescued mDNS finding with a second axis
  (TI hits, data-size regularity, persistence score) before acting.

For these, lean on the other detectors (data exfiltration,
lateral movement, TI hits, weird events) rather than trying to
expand spectral's reach.

---

## Reference: defaults at a glance

```
SpectralEnabled              = true
SpectralMinObservations      = 16
SpectralFAPThreshold         = 12
SpectralRescueThreshold      = 0.5
```

Set in `internal/config/config.Default()`. The Settings dialog
reads and writes these via `/api/settings`. Defaults are the
right starting point for typical enterprise IT traffic. Move
from defaults only with a real measurement in front of you.
