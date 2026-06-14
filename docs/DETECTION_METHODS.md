# Archer Detection Methods — How and Why

This document explains, in plain terms but with the underlying math, how Archer
finds bad things in Zeek logs.

---

## 1. The big picture

Archer ingests parsed Zeek logs (`conn.log`, `dns.log`, `ssl.log`, `http.log`,
`notice.log`, `files.log`, `x509.log`) and runs a set of independent analyzers.
Each analyzer does one of three things:

1. **Pattern match** against a known-bad list (JA3 hashes, C2 ports, suspicious
   TLDs, suspicious user-agent strings, regex on URIs).
2. **Threshold count** an aggregate (bytes transferred, NXDOMAIN replies,
   unique subdomains, connection counts).
3. **Statistical regularity test** on a stream of events to decide whether the
   stream looks "too regular to be human." This is what catches beacons.

The output of every analyzer is a `Finding` with a type, severity, a 1–100
score, and a free-form detail string explaining the math behind it. A final
**Host Risk Score** pass aggregates the per-finding signals into one composite
score per source IP.

Two design choices matter for understanding what follows:

- **Reservoir sampling (interval statistics).** Beacon analysis would
  otherwise need to remember every inter-arrival interval per (src, dst) pair.
  On a 3 GB capture that is a lot of memory. Archer keeps a bounded random
  sample of size *N* using Algorithm R (Vitter, 1985). Every observed value
  has an equal probability *N / total_seen* of being in the sample. Standard
  sample statistics (mean, median, variance, MAD) are unbiased estimators of
  the population values, so the regularity scores below are mathematically
  valid even though Archer never sees the full stream at once.

  **What this precludes.** Reservoir sampling shuffles the intervals into a
  random order to fit the cap, so by scoring time the slice has lost its
  temporal sequence. Order-independent statistics (Bowley, MAD, histogram
  counts, Shannon entropy on bucket counts) work fine on a reservoir;
  anything that needs the consecutive-interval relationship
  (autocorrelation, time-lag clustering) does not. If a future detector
  needs *consecutive-interval* information, it has to maintain a parallel
  bounded-window sample that preserves order alongside the existing
  reservoir — they're not derivable from each other.

- **Ring buffer (spectral timestamps).** The spectral rescue path (§2.2(a))
  maintains a *separate* ring buffer of the most recent N connection
  timestamps (not intervals). A uniform random reservoir samples earlier
  timestamps with increasing probability as the stream grows, biasing the
  Lomb-Scargle input toward the start of the observation window and degrading
  the periodogram SNR for long-running pairs. The ring buffer overwrites the
  oldest entry when full, keeping the most recent N timestamps. `spectralScore`
  sorts internally before running the periodogram; the benefit of the ring
  over the reservoir is recency-biased selection, not physical ordering.
- **Lazy state allocation.** Per-pair statistics are not allocated until a pair
  has been seen at least 3 times. High-cardinality, low-count pairs (one-off
  scans, NAT noise) never consume memory.

---

## 2. Beacon — the headline detection

**What it is.** A beacon is a host that "phones home" on a regular cadence:
every 60 seconds, every 5 minutes, every hour. Malware C2 implants do this so
the operator can issue commands. Legitimate software also beacons — NTP,
software updaters, telemetry — so a regularity test by itself is not enough.
Archer scores beaconiness on four independent axes and combines them.

**Where in the code.** `internal/analysis/conn.go` — the main loop populates
per-pair `beaconState`, and the post-processing block at line 234 computes the
score.

### 2.1 Inputs per (source IP, destination IP) pair

For every connection in `conn.log` between the same source and destination,
Archer tracks:

- The list of inter-arrival intervals `Δt_i = t_{i+1} − t_i` (capped to 1000
  via reservoir sample).
- The list of `orig_bytes` payload sizes (capped to 1000).
- A 24-hour-of-day histogram of when the connections happened.
- The first and last timestamps in this pair, and the dataset-wide first and
  last timestamps.
- A per-destination-port roll-up — connection count, byte volume (both
  directions), and first/last-seen timestamp — for every port the pair
  touched.

A pair is only scored if it has at least `BeaconMinConnections` connections
(default 4) and at least 3 intervals.

**Local-infrastructure destinations are dropped first.** A connection whose
destination is multicast (224.0.0.0/4, ff00::/8 — mDNS, SSDP, LLMNR), the
limited broadcast address, the unspecified address, or IPv6 link-local
(fe80::/10) is skipped before any conn detector sees it. These are local
network chatter, never a routable C2 endpoint, but they are *not* RFC-1918, so
they slip the `!isPrivateIP(dst)` egress gate — without this an mDNS printer or
an SSDP-announcing TV reads as a perfectly periodic Beacon (and as a Strobe,
off-hours transfer, etc.) to an "external" host. The same drop covers every
conn detector: beacon, strobe, exfil, off-hours, long-connection, C2 Port, and
Protocol on Unexpected Port (`isLocalInfraDest` in `types.go`).

**Destination-port labeling.** Connections are aggregated per
`(sensor, source, destination)` — *not* per port — so a beacon that runs on
a single port is still scored on all of that pair's traffic. The finding's
`dst_port` is the **modal** port: the one carrying the most connections (ties
broken by the lower port number for determinism). Earlier the port came from
the *first-seen* connection, so an unrelated early connection on a different
port — an SSH probe a few minutes before the HTTPS beacon proper — mislabeled
the whole finding. Every other port the pair touched is surfaced in the Detail
line's **co-traffic** segment (§2.3) rather than silently dropped, so the
minority-port context is never lost. Because `dst_port` feeds `Fingerprint()`
and the `beacon_history` key, correcting the label re-keys a multi-port
beacon's identity once on the first pass after the change.

### 2.2 The four sub-scores

Each sub-score is in `[0, 1]`. The final beacon score is

```
beacon_score = clamp(100 × (0.25·ts + 0.25·ds + 0.25·hist + 0.25·dur) × prevalence_mod × conf_mod, 1, 100)
```

`prevalence_mod` is the per-destination prevalence adjustment (§2.2(e)).
`conf_mod` is the sample-size confidence modifier (§2.2(f)).
Pairs scoring below 40 after both modifiers are suppressed — no finding is
emitted. Severity of emitted findings:

| Score range | Severity |
|-------------|----------|
| 85–100      | Critical |
| 70–84       | High     |
| 50–69       | Medium   |
| 40–49       | Low      |

Pairs already flagged as Strobe are excluded from beacon emit entirely —
a strobe is a degenerate beacon, and emitting both would be a double-count.

#### (a) ts_score — timing regularity

A beacon has tightly clustered intervals. We measure that two ways and average.

**Bowley skewness on intervals.** The Bowley coefficient of skewness is

```
B = ((Q3 − Q2) − (Q2 − Q1)) / (Q3 − Q1)
  = (Q1 + Q3 − 2·Q2) / (Q3 − Q1)
```

where `Q1, Q2, Q3` are the first, second (median), and third quartiles of the
intervals. `B` is in `[−1, 1]`. A symmetric distribution gives `B ≈ 0`. Heavy
right-skew (occasional very long gaps) drives `B` toward `+1`.

We turn skewness into a regularity score with

```
bowley_score = 1 − |B|
```

so a perfectly symmetric distribution gives 1.0 and a maximally skewed one
gives 0.

**Stability guard.** If `Q3 − Q1 < 0.05 × Q2` (IQR less than 5% of the
median), the denominator is near-zero relative to the scale of the
distribution and Bowley returns 1.0 instead of dividing. The threshold
is relative so it is correct at both sub-second strobe timescales and
multi-hour slow-C2 timescales — an absolute-seconds threshold would
misfire on one end or the other.

**Median Absolute Deviation on intervals.** MAD is the median of
`|x_i − median(x)|`. Where the standard deviation is destroyed by a single
huge outlier, MAD shrugs it off. Define

```
mad_score = (median − MAD) / median
```

clamped to `[0, 1]`. If every interval equals the median, `MAD = 0` and the
score is 1. As intervals scatter, `MAD` approaches `median` and the score
approaches 0.

**Combined.** `raw_ts = (bowley_score + mad_score) / 2`, rounded to 3
decimals. Both halves agreeing that the intervals are tightly clustered is what
we want.

**Multimodal augmentation.** Bowley and MAD on the raw distribution penalise
beacons whose intervals cluster around 2-4 distinct values (heartbeat +
tasking, idle + active, multiple compromised processes on one host). The
median lands between modes, MAD blows up, and `mad_score` collapses. The
`intervalMultimodalScore` helper bins intervals on a log2 axis, identifies
peaks (≥50% of the max bucket count, adjacent peak-buckets merged), and
scores each peak's tightness with the same `(median − MAD) / median` formula
applied within the cluster. Returns 0 (deferring to the raw math) for
single-mode distributions, 5+-mode distributions, or any peak below a 0.5
tightness floor. Otherwise returns a count-weighted average of per-peak
tightness.

**Entropy augmentation.** A jittered single-mode beacon (60s ± 50% jitter)
scores poorly on MAD — the deviations are large relative to the 60s median —
even though every interval still lands in the same one or two log2 buckets.
The `intervalEntropyScore` helper computes Shannon entropy of the bin-count
distribution (same log2 buckets) and normalises against `log2(nBuckets)`.
A perfectly concentrated distribution scores 1.0; a maximally scattered
distribution scores ≈0. Orthogonal to Bowley + MAD: it cares about *which
buckets* are populated, not the spread *within* a bucket.

**Entropy width gate.** The log₂ binning produces buckets of increasing width:
bucket 0 covers [1, 2s), bucket 5 covers [32, 64s), bucket 9 covers
[512, 1024s). For wide buckets, high entropy is not meaningful — "all
intervals are somewhere between 512s and 1024s" occupies one bucket and
scores near 1.0 despite carrying no structure. When the dominant bucket index
is ≥ 8 (bin width ≥ 256 s), the entropy score is penalised by `128 /
bucketLow`, where `bucketLow` is the lower bound of the dominant bucket in
seconds: bucket 8 (256s lower bound) → × 0.5; bucket 9 (512s) → × 0.25.
Tightly clustered intervals in buckets 0–7 (widths 1–128 s) are unaffected.

**Spectral rescue.** The three statistical paths above all derive
from the inter-arrival *interval distribution*. A beacon whose
intervals are spread enough to confuse every distribution-based
score (Bowley + MAD on raw values, multimodal on log2-binned
peaks, entropy on bin occupancy) can still have very clear
*frequency-domain* structure. Adversaries who care about evading
timing-regularity detection use exactly this shape: a fixed
schedule with bounded random jitter around it. The intervals look
noisy; the spectrum has a sharp peak.

The spectral path runs a Lomb-Scargle periodogram over the pair's
most-recent-N connection timestamps, held in a ring buffer (see §1).
Lomb-Scargle (rather than a binned FFT) handles unevenly-spaced data
natively, sidestepping bin-choice tuning. The Rayleigh power form gives the standard
null-hypothesis distribution (exponential with mean 1.0 under
Poisson arrivals), so the false-alarm threshold has a clean
interpretation: power > 12 corresponds to per-frequency false
alarm ≈ exp(-12) ≈ 6e-6, and across the 2000-point log-spaced
period grid (5s to window/2) total expected FAP ≈ 0.001 per pair.

**DC-correction.** For timestamps distributed uniformly across a
long observation window, the expected values of the cosine and sine
sums in `rayleighPower` are non-zero at non-integer window/period
ratios — a mathematical bias that produces spurious high-power peaks
on genuinely random pairs. Before computing power, the analyzer
subtracts the expected mean contribution of the window shape
(E[cos(ωt)] = sinc(ωW/2)·cos(ω·t_center) and the equivalent sine
term). This correction is exactly zero when the window contains a
near-integer number of cycles (sinc(kπ) = 0), so real periodic
signals are unaffected. The correction *reduces* but does not *zero*
peaks at non-integer ratios — real long-period structure in traffic
(e.g., weekday/weekend rhythms in high-frequency local traffic) can
still cross FAP=12 after correction.

**Plausibility gate and span cap.** Two independent mechanisms bound
what counts as a plausible beacon period:

1. **Lower-bound gate (`ivMedian/5`).** A peak shorter than
   one-fifth of the median inter-arrival interval is burst-structure
   noise — the periodogram is finding intra-burst rhythm, not beacon
   cadence. The gate is lower-bound only; there is no upper bound.
   Burst-connect beacons (C2 that opens several connections in a burst
   then goes quiet for hours) have a legitimate spectral period far
   above `ivMedian`, and an upper bound would block those detections.

2. **Span cap (`window/3`, internal).** A period longer than one
   third of the observation window is supported by fewer than three
   complete cycles. This cap is the primary suppressor of very-long-
   period leakage artifacts when observation windows are short (29–43
   days for 1 Ms-class artifacts). The DC-correction reduces but does
   not zero these peaks; the span cap excludes them from the plausible
   range. As deployment windows grow, peaks that previously sat above
   `window/3` slide into the plausible range — run `corpus-spotcheck.sh`
   after each corpus extension to confirm the gate is still holding.

When both mechanisms reject the only strong peak, the pair still
emits a beacon finding via the statistical path (without the spectral
score boost), and the blocked count is recorded in `analysis_stats`.

**`[artifact Xs suppressed]` in the Detail line.** This tag appears
when the rescue *succeeded* on a shorter plausible period AND a
longer-period peak had higher raw power but was excluded by the span
cap. It does not mean the artifact was blocked by the gate. It means:
DC-correction did not zero it, the gate did not reject it, the span
cap excluded it, and a weaker shorter-period signal won. If those
pairs' observation windows grow until the artifact enters the plausible
range, the artifact becomes the dominant rescue candidate. Check Section
2 of `corpus-spotcheck.sh` on subsequent runs for this class.

The path is gated to keep its CPU cost off the hot path:
1. **`SpectralEnabled` flag** (default on). Operator can disable
   if real-corpus calibration shows too many false positives or if
   per-run runtime budget is tight.
2. **Rescue-only invocation.** Spectral runs only when the
   statistical chain already scored `ts < SpectralRescueThreshold`
   (default 0.5) — pairs that scored well don't get spectral run
   on them.
3. **Reservoir floor.** Below `SpectralMinObservations` (default
   16) the path returns zero. Below 8 it short-circuits
   defensively regardless of operator config — the math is
   unreliable on too few samples.

When the spectral path wins (`spec.Score > tsScore`), the
Beacon finding's Detail string gets a tag:

```
Connections: 200 | Mean interval: 60.4s | CV: 0.32 |
Score components: ts=0.62 ds=0.85 hist=0.71 dur=0.40 |
ts_layers: raw=0.31 mm=0.12 ent=0.08 |
Spectral rescued: score=0.62 (period 60.3s, 22.8×median, power 37.2, threshold 12.0)
```

So an analyst triaging the finding can see which signal drove
the timing score. A beacon at CV ≈ 0.5 that scored High via
spectral rescue is operationally different from one that scored
High via Bowley + MAD: the former is more likely deliberately
jittered C2, the latter more likely tight automation.

As of v0.34.0, all three pre-spectral layer scores are always
surfaced in the detail string (`ts_layers: raw=X mm=Y ent=Z`)
regardless of which layer won. `raw` is the Bowley + MAD score,
`mm` is the multimodal score (non-zero only when the interval
distribution clusters around 2–4 distinct values), and `ent` is
the entropy score (non-zero when intervals land in a small number
of log₂ buckets despite high variance). These values are also
stored in `beacon_history` (migration 0024) so longitudinal
layer analysis is possible across the 30-day retention window.

**CPU cost.** ~4 ms per pair on a 200-timestamp ring against the
2000-point grid. Combined with the rescue-only gate, a hunt-
session run with 1000 pairs sees at most a few seconds of
spectral overhead total. Real cost scales linearly with the
number of pairs the rescue gate opens for, which is bounded by
how good the statistical-augmentation chain already is — on
real traffic, that's typically a small minority.

**Final timing score.** `ts_score = max(raw_ts, multimodal,
entropy, spectral)`. Each path only contributes when the others
miss; single-mode tight beacons see no change because the
distribution-based paths already score ≈1.0 and the spectral
gate doesn't open.

#### (b) ds_score — payload size regularity (data size)

The same Bowley + MAD math is applied to the `orig_bytes` distribution.
Beacons usually send a near-fixed-size heartbeat ("am I still alive?"), so
the bytes-per-connection distribution is also tight. The default MAD score
when there are no bytes is `0.0` (i.e., we *don't* give credit for absent
data, unlike timing where we default to 1.0).

#### (c) hist_score — circadian hour-of-day uniformity

Connections are bucketed by **hour of day** (`timestamp_hour % 24`),
producing 24 fixed clock-hour buckets (0 = midnight, 12 = noon). This is
window-length-independent: a beacon that fires only at 2am every day for
30 days populates a single bucket (low `hist_score`), while a beacon
active across all hours of the day scores high. Previously this used 24
equal-width bins spanning the full capture window, making `hist_score` and
`dur_score` measure the same window-coverage signal on long captures.

For this pair, every connection lands in its clock-hour bucket. We then
compute two scores and take the higher:

**Coefficient-of-Variation score.** Over the buckets that have at least one
hit (`n ≥ 2`),

```
μ = mean(non_zero_bucket_counts)
σ = sqrt( (1/n) · Σ (x_i − μ)² )      // population std-dev
CV = σ / μ
cv_score = max(0, 1 − CV)             // 0 if CV ≥ 1
```

A perfectly even spread across populated buckets gives `CV → 0` and
`cv_score → 1`. Bursty traffic concentrated in one bucket gives high CV and a
score near 0.

**Bimodal score.** Two diurnal peaks (e.g., a beacon that fires only during
office hours) would tank the CV score even though the underlying activity is
regular. The bimodal score forgives that pattern:

```
threshold = max_bucket_count × 0.05
high = count of buckets ≥ threshold
bimodal_score = high / total_populated_buckets   if total ≥ 11 and high ≥ 2
              = 0                                otherwise
```

The intuition: if many buckets are at least 5% as full as the busiest one, the
distribution is broad and recurring rather than a one-off spike.

`hist_score = max(cv_score, bimodal_score)`.

#### (d) dur_score — temporal persistence

Did the beacon run across the recent capture, or was it active only for a brief
window? Two scores, take the max.

**Persistence is measured over a bounded trailing window, not the full corpus.**
The 24 window-relative buckets span `[dataset_max − W, dataset_max]` where
`W = beaconPersistenceWindowSec` (7 days), or the whole corpus when it is
shorter than `W`. Without this cap, the buckets divided the *entire* ingest
history, so the credit a beacon earned for "running a long time" shrank as the
operator retained more logs — a 20-day beacon scored Critical against a 30-day
store but only High against a 9-month store, purely because the 24 bins got
wider. Anchoring to the most recent `W` days makes persistence
**retention-invariant**: a beacon active across the last week scores the same no
matter how much older history sits behind it. When the corpus is ≤ `W` (most
synthetic fixtures, short hand-fed captures) the window is the whole corpus and
the score is identical to the pre-cap behaviour. Activity older than the window
clamps into the first bin (the same boundary handling the unbounded form used
for the earliest record). These remain **window-relative** buckets, distinct
from the clock-hour buckets `hist_score` uses.

**Coverage.** `coverage = (last_ts − max(first_ts, window_min)) / W`, clamped to
1.0. A beacon active end-to-end across the trailing window gets 1.0.

**Longest-consecutive-bucket run.** Walk the 24 window-relative buckets from
start to end. The longest run of consecutive non-empty buckets, divided by 12,
is the "consistency" score (clamped to 1.0). A run of 12 consecutive non-empty
buckets ≈ half the window of continuous activity.

`dur_score = max(coverage, consistency)`. Below 6 populated buckets total
(`minBars = 6`) the score is forced to 0 — there isn't enough activity to
meaningfully claim "persistence." (At `W = 7 days` with 24 buckets, that floor
is ~1.75 days of activity; a sub-day-old beacon legitimately has no persistence
signal yet, which is by design — catch those via timing/data-size regularity and
the fingerprint-rarity enrichment in §2.3, not persistence.)

#### (e) Prevalence modifier

After the four sub-scores are combined into a raw beacon score, a
per-destination prevalence adjustment is applied based on how many distinct
internal hosts the analyzer observed contacting that destination within the
same sensor's conn logs:

| Condition | Adjustment |
|-----------|-----------|
| Destination contacted by ≥ 50% of all observed internal sources | × 0.85 |
| Destination contacted by ≤ 2% of sources, with ≥ 50 total sources observed | × 1.15 |
| All other cases | × 1.00 |

The damper (× 0.85) catches common infrastructure — NTP servers, CDN IPs,
OS update endpoints — that every host on the network contacts regularly and
that would otherwise generate noisy medium-confidence beacons. The boost
(× 1.15) highlights rare destinations on large enough networks that rarity is
meaningful; the ≥ 50-source guard prevents the bonus from firing on small
sensor deployments where every external IP looks rare by definition.

The modifier uses prevalence data built from `conn.log` Phase 1 observations.
HTTP Beacon reads the same map. For HTTP-only analysis runs (no conn.log),
no prevalence adjustment is applied.

#### (f) conf_mod — sample-size confidence

A beacon scored from 4 connections carries far more uncertainty than one
scored from 400. `conf_mod` scales the composite down for low-sample
observations and converges to 1.0 at full confidence:

```
conf_mod = 0.5 + 0.5 × clamp( (n − minN) / 96, 0, 1 )
```

where `n` is the observed connection count and `minN` is the configured
minimum (`BeaconMinConnections`, `HTTPBeaconMinRequests`, or
`DNSBeaconMinQueries` depending on the detector). At exactly the minimum,
`conf_mod = 0.5` and the composite is halved. At `minN + 96` and above,
`conf_mod = 1.0` and the score is unaffected. Beacons at low counts with
composite × 0.5 below 40 are suppressed entirely — no finding is emitted.

The current modifier value appears in the detail string as `conf=<value>`.
Re-analyzing a corpus with few-connection pairs will lower their scores;
pairs that depended on the full composite to clear the emit floor may
disappear. That is the intended behaviour — a 4-connection "beacon" is not
actionable evidence.

### 2.3 Detail line interpretation

A finding might read:

```
Connections: 1287 | Mean interval: 60.3s | CV: 0.04 |
Score components: ts=0.97 ds=0.95 hist=0.91 dur=1.00 conf=1.00 |
ts_layers: raw=0.97 mm=0.00 ent=0.91
```

- **CV** here is the coefficient of variation of the *intervals* themselves
  (not the bucket counts), included as an at-a-glance regularity number.
  `CV = stddev(intervals) / mean(intervals)`. Below ~0.1 is suspiciously
  regular; above ~1.0 is human-driven.
- The four sub-scores tell you which axis dominated.
- **ts_layers** breaks down the timing score: `raw` (Bowley + MAD),
  `mm` (multimodal rescue), `ent` (entropy rescue). The composed `ts`
  is the max of these three plus spectral if it fired.
- **co-traffic to dst** appears only on a multi-port pair. It lists every
  destination port *other* than the labeled (modal) one this `(src, dst)`
  pair touched, each as `port×conns (bytes, first→last)` — e.g.
  `co-traffic to dst: 22×8 (14.1 KB, 2026-05-08 04:11→2026-05-31 09:02)`.
  This is how a minority port — folded into the same beacon because
  aggregation is per-pair, not per-port (§2.1) — stays visible after the
  finding is labeled with the dominant port. Absent for the common
  single-port beacon.

As of v0.25.0 the detail pane renders a **structured triage header**
above this raw line — jitter % (the interval CV as a percentage),
"every 47s ± 3s", median interval, sample size, and the per-axis
sub-score breakdown — so the same numbers are readable in the first
five seconds without parsing the pipe-delimited string. The four
sub-scores and the `mean_interval` / `median_interval` / `jitter` /
`sample_size` fields are serialized on the single-finding API and
persisted as `findings` columns (migration 0018, NEW-89 closure), so
they survive a server restart and the preserve-historical
carry-forward. No score formula changed — the numbers are only newly
visible and durable.

As of v0.27.0 the detail pane and the findings filter expose three
further beacon-triage surfaces, all of them analyst-facing only —
again **no score formula, threshold, finding type, or `Fingerprint()`
changed**, and the golden corpus is unchanged:

- **Sub-score filtering.** The findings filter accepts comparisons and
  inclusive `[lo TO hi]` ranges on each of the four sub-axes via the
  query bar's `tscore` / `dscore` / `hist` / `dur` fields; the triage
  header labels these **Timing** / **Data size** / **Histogram** /
  **Persistence** — the same `ts`/`ds`/`hist`/`dur` axes §2.2 describes,
  spelled out for the analyst.
  The composite score averages the axes, so a real implant profile —
  tight timing, short duration (a staging beacon) — sits below a score
  threshold despite textbook rhythm. The sub-score filter turns the
  score into a queryable signature space: `tscore:>=0.8 AND dur:<=0.3`
  pulls exactly the short-lived tight-cadence spikes the average
  buries. Any sub-score bound implicitly scopes results to beacon
  types (a structural-zero axis on a non-beacon can't satisfy a bare
  upper bound). See §2.2 for what each axis measures.
  As of v0.49.0 the raw triage metrics behind the header are queryable
  too — `conns` (sample size / observation count), `meanint` / `medint`
  (mean / median inter-arrival interval, seconds), and `jitter` (the
  interval CV, raw — `0.42`, not `42%`) — with the same comparisons,
  ranges, and beacon-scoping as the sub-scores: `conns:<=10000`,
  `meanint:>=3600`, `jitter:<0.2`. These read the migration-0018 columns
  directly, so they're filterable wherever the sub-scores are.
- **JA3 / JA4 cross-reference.** A conn-level Beacon finding carries
  the TLS client fingerprint of its seed connection (lifted from the
  same `ssl.log` index that resolves the SNI). When the sensor runs the
  Zeek JA4+ plugin the finding carries JA4; stock Zeek produces JA3.
  The detail view shows how many *other* beacons in the dataset share
  that fingerprint via `ja4_sibling_count` / `ja3_sibling_count`, and
  one click (**TLS Pivot**) filters to all of them. Because an implant
  family reuses its TLS stack, a shared fingerprint across pairs is
  implant-family attribution — the same logic §10.1–10.2 use for the
  standalone Malicious JA3/JA4 detectors, now joined to the beacon view.
- **Fingerprint rarity + cross-host cluster (enrichment).** The sibling
  count above is computed over *emitted beacon findings only*, so it
  cannot tell a rare implant fingerprint from a ubiquitous browser one,
  and is blind to siblings that scored below the beacon emit floor.
  To close that gap, `analyzeSSL` builds a per-fingerprint prevalence map
  over **every TLS connection** in the pass (not just beacons) — total
  connections, distinct internal sources, distinct destinations — pushed
  to the store after each full pass (`SetFingerprintPrevalence`). At read
  time the single-finding handler resolves a conn-level beacon's seed
  fingerprint against that snapshot (`Store.FingerprintConcern`) into a
  severity-style **concern level** and a one-line summary, returned on the
  finding JSON as `fp_concern` / `fp_detail` and rendered as a colour-coded
  **FP rarity** row in the Detail pane. A fingerprint reaching
  ≤ `fpRareDstFanoutMax` (8) destinations reads as **rare** (an implant
  phones a tiny C2 set; a browser/SDK fingerprint reaches thousands), and
  ≥ `fpClusterMinSrcs` (2) internal hosts sharing one rare fingerprint is
  the cross-host implant-family signal. The concern tiers: rare clustered
  JA4 → `critical` (red), rare single-host JA4 → `high` (orange), rare
  clustered JA3 → `medium` (yellow), rare single-host JA3 → `low` (green),
  common → `none` (white). JA4 is preferred (GREASE-robust, stable); a
  JA3-only match is capped a tier lower and carries a collision warning
  because generic Go/Python/Rust stacks collide on one JA3. **This is
  enrichment only — it never alters score or severity.** A corpus-wide false-positive sweep
  showed that on a cloud-heavy network benign automation (DoH resolvers,
  CDN/SaaS edges) is statistically indistinguishable from cloud-hosted C2
  by any single axis — including fingerprint rarity — so the rarity signal
  is surfaced to *rank a hunter's attention*, never to auto-elevate a
  finding. It also survives cloud-hosting (the fingerprint is the
  malware's, not the host's), which the destination IP/ASN cannot.
  The same snapshot drives a **fingerprint-first hunt surface** — the
  **TLS Fingerprints** inventory (`Store.FingerprintInventory`,
  `GET /api/fingerprints`), which ranks every high-signal fingerprint in
  the capture (known-bad C2 matches plus rare/clustered shapes, concern
  ≥ medium) so a hunter can start from the fingerprint and pivot down to
  its findings — including a rare fingerprint that emitted no finding at
  all. Same concern math as the per-finding badge (`fingerprintConcernLevel`),
  same enrichment-only contract: the inventory never alters a score.
- **HTTP-beacon URI footprint.** An HTTP Beacon finding carries the
  request-path footprint of its `(src,dst,host)` group
  (count-descending, capped). A benign beacon hits one stable
  endpoint; a C2 has a small fixed set of control paths (`/poll`,
  `/cmd`, `/upload`). The multi-path footprint is one of the strongest
  "implant, not a chatty app" discriminators. It is aggregated *before*
  the `(Type,src,dst,port)` fingerprint dedup that keeps one finding
  per group, so the surviving finding carries the whole footprint.

### 2.4 What this catches and what it misses

Catches: fixed-interval implants (Cobalt Strike default 60s, Empire 5min,
custom RATs), long-running tunnels with constant-size keepalives.

Catches (via the spectral rescue path): bounded-jitter beacons —
fixed schedule with random offsets around each scheduled
timestamp. The statistical paths score these poorly because the
interval distribution looks spread; Lomb-Scargle finds the
underlying period because phase doesn't accumulate. Burst-connect
beacons (multiple connections per burst, long silence between
bursts) are also caught: the plausibility gate is lower-bound only
so legitimate long spectral periods are not blocked. The
`Spectral rescue: period≈Xs` tag in the Detail line marks
findings that the frequency-domain path rescued.

Misses (intentionally, to limit false positives): adversarial
jitter at σ/period > 0.45 where the spectral peak itself washes
out (sinc(π·σ/T) → 0). Above that threshold, the timing signal
is effectively destroyed and rescuing it would risk flagging
legitimate sporadic traffic. The histogram and bytes axes still
contribute if those signals survive.

Known false-positive class — long-period rescues on high-frequency
local traffic: a pair with sub-30 s median intervals accumulates
enough observations to produce genuine periodogram peaks at 6–10 day
periods (weekday/weekend traffic rhythm), crossing FAP=12 after
DC-correction. These produce spectral-rescued findings at score 95+
that are operationally benign; DC-correction cannot suppress them
because the structure is real. The dominant offender — mDNS — is now
removed upstream: `.local` queries and multicast/broadcast/link-local
destinations are dropped before any detector (§2.1, §9.6), so they
never reach the spectral path. What remains is other chatty *unicast*
local traffic (an internal telemetry agent on a tight interval).
Analyst response: allowlist the pair, or require a second axis (TI
hit, data-size regularity, high persistence) before acting.

### 2.5 DGA hostname augmentation

A beacon to `pool.ntp.org` is operational noise; the same timing
shape to `kx9j3qm2pflw.com` is high-confidence C2. After the
Beacon, HTTP Beacon, and DNS Beacon detectors emit, a
post-Phase-2 sweep in `internal/analysis/dga.go` looks at each
finding's destination Hostname and decides whether the registrable
domain looks algorithmically generated.

**Where the Hostname comes from.** conn-level Beacon gets it
from `sslUIDIndex` (TLS SNI). HTTP Beacon gets it from the
`Host` header in `http.log`. DNS Beacon gets it from the query
apex (`k.apex`) — a DNS C2 beacon to a DGA-generated domain name
is a first-class signal, so the same augmentation applies.
Pure-TCP beacons to bare IPs without observable DNS get no DGA
scoring — the future dns.log correlation path is deferred.

**Two metrics, both must agree.** The scorer operates on the
SLD (the second-level component of the registrable domain):

| Metric | English range | DGA range | Default threshold |
|---|---|---|---|
| Shannon entropy (bits/char) | 2.5 – 3.5 | 3.8 – 4.5 | `dga_entropy_threshold` 3.5 |
| Mean bigram log-probability | -2.5 to -3.5 | -5.0 to -7.5 | `dga_bigram_threshold` -4.5 |

Both must cross before the augmentation fires. Either alone
produces too many false positives on legitimate algorithmic-
looking hostnames.

**The bump.** +15 to score (capped at 99), one-step severity
upgrade (Low→Medium, Medium→High, High→Critical). Detail line
is appended with the diagnostic tag:

```
DGA-suspect destination: kx9j3qm2pflw.com (SLD=kx9j3qm2pflw, entropy=3.58, bigram=-5.55)
```

so analysts can verify which numbers tripped the bump and
calibrate the thresholds against their own traffic.

**Allowlists, in order of precedence:**

1. Built-in CDN suffix list in `cdnAllowlistSuffixes` (cloudfront,
   azure, akamai, fastly, github.io, etc.) — short-circuits
   inside `dgaHostnameScore` before any scoring runs.
2. SLD floor: SLDs shorter than 7 chars get no score (entropy
   estimates on tiny strings are unreliable, and DGAs typically
   produce 8-25 char names).
3. Operator allowlist (`Store.AllowlistMatcher`) — checked
   against the full Hostname inside `applyDGAScoring` for
   per-deployment "we know this is legitimate" suppressions.

**Limitations:**
- No Public Suffix List in v1. `kx9j3qm2pflw.co.uk` extracts SLD
  as `co` (not `kx9j3qm2pflw`) and gets missed. Most real-world
  DGAs register `.com / .net / .org / .top / .xyz / .info`.
- No DNS-log correlation: TCP beacons to raw IPs that resolved
  via dns.log before the analysis window don't get scored.

**Calibration.** The Settings → Detection → Beacon pane has both
threshold inputs alongside an enable toggle. Bump the entropy
threshold up (3.8) if English-shaped names are tripping; drop
the bigram threshold (more negative, e.g. -5.0) if DGA names
are escaping. Always check the Detail-line entropy/bigram
values before tuning — operators have seen one or two specific
hostnames trigger and bumped a global threshold when the right
fix was an allowlist entry.

### 2.6 Score evolution history

A score on its own is a snapshot. A score moving across days is
a triage signal: a beacon whose composite is steadily climbing
is escalating; one that's decaying is probably a misconfigured
client that fixed itself. The score-evolution chart in the
finding detail pane surfaces this trajectory.

**Where the data comes from.** `internal/store/beacon_history.go`
hooks `Store.SetFindings`: every time a Beacon, HTTP Beacon,
or DNS Beacon finding lands, one row is written to `beacon_history`
keyed by `(Finding.BeaconHistoryKey(), today_UTC)` with the
composite score plus the four sub-axis components (Timing, Data size,
Histogram, Persistence — stored as `ts_score`/`ds_score`/`hist_score`/
`dur_score`). The PRIMARY KEY on `(fingerprint, day_utc)` plus
`INSERT … ON CONFLICT DO UPDATE` means **a single daily row
captures both the highest score observed that day (`max_score`)
and the most recent reading (`last_score`)**. Under sub-daily
watch cadence or admin-triggered re-analysis, a beacon that
spiked at noon and fell back by evening is recorded as
`max_score=88, last_score=50` — the chart renders the max,
and the analyst sees the trajectory shift the next morning.

**Peak characterization on a score tie (NEW-84, v0.26.0).**
`max_score` / `max_score_at` stay strict-greater, so the recorded
peak value and the time it was first reached never move on an
equal-score pass (NEW-76 semantics preserved). But the `severity`
and the four sub-axis columns describe *that* peak, and severity is
not a pure function of the numeric score: the DGA augmentation
(§2.5) forces a beacon one step up (e.g. High → Critical) even when
its +15 leaves the composite unchanged below the 80 Critical cutoff
(raw 64 → 79). If an earlier same-day non-DGA pass recorded that
same 79 as High, a strict-greater gate would leave the row stuck at
High while the beacon is really Critical. So the
peak-characterization columns (severity + ts/ds/hist/dur)
additionally update when the score *ties* the recorded max and the
new pass is strictly more severe, compared via an explicit severity
rank (the column is TEXT — lexical order is not severity order). A
later benign equal-score pass still cannot downgrade the recorded
peak.

Pre-v0.16.1 used `INSERT … ON CONFLICT DO NOTHING` with a
justifying comment claiming the morning pass was "the more
representative score." That reasoning was technically wrong —
the analyzer scores against an accumulated reservoir window, not
"today's logs," so neither pass is structurally more
representative than the other — and the silent-drop behavior
hid the exact adversarial-tuning pattern the chart is supposed
to surface. NEW-76 from the eighteenth audit round drove the
redesign.

**Fingerprint vs Finding.Fingerprint().** The history table uses
a wider identity that includes Hostname and URI (canonical
string joined by ASCII Unit Separator, not hashed — see
`Finding.BeaconHistoryKey`). The existing `Finding.Fingerprint()`
is intentionally coarser (just `{Type, SrcIP, DstIP, DstPort}`)
because it keys analyst-state preservation across re-analyses;
collapsing host/uri into one identity is what an analyst wants
for "one note per beacon family." But for history rows, two
HTTP beacons sharing a destination IP but going to different
`(host, uri)` need separate trend lines or the chart shows
mixed signal — hence the wider history key.

**Retention.** 30 days, hard-coded. The chart range is also 30
days so longer retention is invisible without UI changes.
`Store.PurgeBeaconHistory()` runs on the watch's
first-tick-of-operator-day gate — the same condition that
triggers the full-pass analyze — so the sweep fires exactly
once per day regardless of how many incremental ticks happen.

**The API.** `GET /api/findings/{id}/history` returns
`[{day_utc, max_score, max_score_at, last_score, last_score_at,
severity, ts_score, ds_score, hist_score, dur_score,
spectral_rescued, spectral_period}, ...]`
sorted ascending. `spectral_rescued` is `1` when the Lomb-Scargle
periodogram rescued the beacon that day (ts sub-axis fell below
`SpectralRescueThreshold` but the periodogram found a significant
dominant period); `spectral_period` is the dominant period in seconds
(`0` means not rescued or period was not resolved). The evolution chart
marks rescued days with a distinct indicator so the analyst can
distinguish spectral-only days from full-score days. Returns `[]` (not
404) for non-Beacon types so the SPA can call unconditionally on any
finding-detail open. See `docs/API.md` for the full shape.

**The chart.** SVG-rendered in a modal opened from the **Score Chart**
button in the action footer. Five lines:
- Composite **Score** (bold, severity color) on the 0–100 axis
- **Timing / Data size / Histogram / Persistence** (thinner,
  distinct colors) on the 0–1 axis sharing the same plot

Reading the chart:
- A flat high score is a stable, persistent C2 channel.
- Climbing Timing with stable Data size = the beacon is becoming
  more regular over time (initial-jitter implant settling into a
  rhythm, or an operator-side scheduling cleanup).
- Climbing Persistence with flat Timing/Data size = the channel is
  staying alive longer each day; the implant's session-keepalive is
  succeeding.
- Sudden drop with no corresponding `IsNew` re-emergence = the
  beacon went silent. Either remediation or the implant
  switched destinations (cross-reference with the Correlated
  Activity row for the same src).

**What this is not.** This is not a real-time stream — the
chart updates once per UTC day. For intra-day timing detail
the Beacon Chart dialog (interval reservoir) is the right
view. The two charts answer different questions:
beacon_history = "how is this beacon changing over weeks";
TSData reservoir = "what does its timing distribution look
like in this analysis window."

---

### 2.7 Port-Hopping Beacon — naming the port-rotation evasion

**Where.** `internal/analysis/conn.go` (`portHopSignature`, applied at
the conn-beacon emit site).

**The signal.** Some C2 deliberately rotates the destination port
between callbacks — same implant, same server, but the port walks
4444 → 8080 → 9001 → 5555 → … to defeat any rule keyed on a single
port. Archer is already immune to that evasion at the *detection*
layer: the beacon key is `(sensor, src, dst)` and **excludes the
port**, so every callback to the server collapses into one beacon
regardless of which port it landed on. The timing, data-size, and
persistence sub-scores are computed over the whole rotation, so a
port-hopper scores exactly as a fixed-port beacon would.

What was missing was a *name*. Before this, a 6-port hopper showed up
as an ordinary `Beacon` whose Detail carried a "co-traffic to dst"
footnote listing the other ports — easy to skim past. The
**Port-Hopping Beacon** type makes the evasion a first-class,
pivotable finding.

**The classifier.** Purely downstream of detection — it reads the
per-port breakdown the beacon already carries (`beaconState.portStats`)
and never gates a finding, so no detection is gained or lost relative
to the plain `Beacon` path. A qualifying beacon is relabeled when both:

- it touched **≥ 5 distinct destination ports**
  (`portHopMinDistinctPorts`), and
- **no single port carried ≥ 50%** of its connections
  (`portHopMaxModalShare`) — i.e. there is no primary channel with
  incidental side-traffic; the spread *is* the pattern.

Both thresholds are global constants in `conn.go`, not per-deployment
settings: a port-hopping channel is defined by its shape, which doesn't
vary by site. Tune them on corpus evidence, not in the UI.

**Score and downstream.** Identical to the `Beacon` it was — same
score, same four sub-scores, same `beacon_history` rows, same
`+30` host-risk weight (`risk.go`), same beacon-family UI (Beacon
Chart, Score Chart, triage header). `model.IsBeaconType` returns true
for it, so the `type:beacons` family selector, exports, and the
beacon-history endpoint all include it; an exact `type:"Beacon"`
query does not.

**Detail line.** Replaces the `Beacon` co-traffic footnote with
`Port-hopping: N dst ports [P×c, …], no dominant port (max X%)` —
the port list is count-descending, so the (sub-50%) modal port and its
share read first.

**False positives.** Legitimate clients that fan out across an
ephemeral-port service — some P2P, some RPC frameworks — can trip the
shape. The relabel doesn't change the score, so a benign port-hopper
that scored low as a beacon still scores low; treat the type as a
triage lens, not a verdict.

### 2.8 Per-channel beacon scoring — surfacing a beacon hidden in noise

**Where.** `internal/analysis/analyzer.go` (`splitChannels`, `scoreChannel`),
fed by `conn.go` (`beaconState.chanRecs`), run at enrichment (Phase 2.5).

**The problem.** The beacon key is `(sensor, src, dst)` — port excluded
(§2.7), and *channel* excluded too. So two TLS channels to the same
destination that differ only by JA3 — say a chatty CDN/telemetry client on
one fingerprint and a periodic C2 on another, both on 443 — are aggregated
into one beacon. When the noisy channel's irregular timing and variable
payloads are interleaved with the clean channel's, the **blended** score is
dragged down: a clean C2 can hide inside its own co-traffic and present as a
merely-MEDIUM beacon an analyst skims past.

**The split (Fork A — non-destructive overlay).** The conn analyzer retains
each beacon's UID-bearing connections (capped at `beaconChanRecCap`, in time
order — not reservoir-sampled, because per-channel intervals must be exact).
JA3 isn't known at fold time (it lives in `ssl.log`, indexed in parallel), so
the split is deferred to enrichment, once `sslUIDIndex` resolves each UID's
fingerprint. `splitChannels` then partitions the retained connections by JA3
and, for each channel, re-runs the **identical** four-axis + spectral stack the
blend uses (`scoreChannel`), so the channel's score is directly comparable.

**Promotion rule.** A channel is emitted as its own `Beacon` finding (carrying
a `Channel` = `"ja3:<hash>"` discriminator) only when it (a) has at least
`BeaconMinConnections` connections, (b) clears the beacon emit floor, and (c)
scores **strictly higher** than the blend. Consequences of the rule:

- The blend is **always kept** — the overlay never replaces it, so no
  detection is ever lost to fragmentation (the failure mode that sank the
  earlier per-port-split design).
- A lone dominant channel scores ≈ the blend and is **not** promoted — no
  duplicate when there's really only one channel.
- Connections without a JA3 (non-TLS, or Zeek captured none) stay represented
  by the blend; only fingerprinted channels split out.
- Host Risk Score reflects the **higher** of blend and channels via its
  max-per-type rule, so a hidden CRITICAL channel raises host risk rather than
  being averaged into the blend's mediocre score.

**Identity.** `Channel` enters `Finding.Fingerprint()` (and the `channel`
column, migration 0035), so a promoted channel keeps analyst state — status,
notes — separate from its blend across re-analyses and never collides with it.
The blend's identity (`Channel=""`) and every existing on-disk key are
unchanged.

**Detail line.** `Per-channel beacon (JA3 <short> / SNI <host>) split from a
blended beacon to <dst> | … | blend score was N` — the trailing blend score
makes the "hidden inside a lower-scoring aggregate" relationship explicit.

**False positives / the gate.** Because promotion requires out-scoring the
blend, the overlay can't add a *lower*-confidence finding than already existed.
The risk is fragmentation noise — many channels promoted by a thin margin.
`corpus-spotcheck.sh` Check 6 (per-channel census) is the gate: a concentration
of promoted channels at LOW/MEDIUM means the promotion margin is too generous
and should be widened. The blend is unaffected either way.

---

### 2.9 Multi-Stage Beacon — cross-host C2 staging

**Where.** `internal/analysis/stage.go`. Runs in phase 3.5, right after the
same-pair correlation roll-up and before host-risk scoring.

**The phenomenon.** An operator lands on host A, A beacons to a C2 endpoint,
the operator moves laterally to host B, and B starts beaconing to the *same*
C2. The single-pair beacon detectors see two unrelated beacons; the staging
detector binds them. The conviction lift is that a single host beaconing to a
rare destination is the ambiguous case analysts agonize over, but two or more
internal hosts independently beaconing to the *same rare* destination, staged
in time, is much harder to explain benignly — and the bound finding can score
CRITICAL and ring the bell even when no individual beacon would.

**Inputs.** Beacon-family findings (`Beacon`, `HTTP Beacon`, `DNS Beacon`,
`Port-Hopping Beacon`) that already cleared the emit floor — this run plus the
historical union (a host present in both counts once; the fresh copy's ID is
the one linked). It never mints new low-quality findings; it only binds
credible ones.

**The gate (high-precision conjunction).** All must hold:

1. **≥ `stagingMinHosts` (2) distinct internal hosts** converging on one
   `(sensor, external dst)`.
2. **Rare destination** — `≤ stagingMaxDstSources` (6) unique internal sources
   talking to it (the per-sensor prevalence map from the conn scan). This is
   the false-positive killer: a CDN / O365 / update server has hundreds of
   sources and is excluded; a real staging cluster is a small fan-in to a rare
   dst.
3. **Clustered onsets** — the spread between earliest and latest beacon onset
   is `≤ stagingWindowHours` (48h). Onsets weeks apart read as independent
   niche-app users, not one campaign.

The destination must be external (internal→internal convergence is out of
scope). The Campaigns view remains the broad, high-recall fan-in lens over
*all* multi-host destinations; this detector is the narrow conviction beside
it, not a replacement.

**Scoring.** **HIGH (80)** for a staged cluster on its own. **CRITICAL (96 —
above the 95 bell threshold)** when corroborated by any of: a `Lateral
Movement` finding linking two participants (the staging mechanic itself), a
`TI Hit (IP)` on the destination, or a `Malicious JA3`/`Malicious JA4` on the
destination. Corroboration earns the conviction tier; it is not a hard gate, so
real staging still surfaces (at HIGH) when the lateral hop wasn't captured.

**Identity and roll-up handling.** Anchored on patient zero (earliest-onset
host) as `SrcIP`, the C2 as `DstIP`, with the contributing beacon IDs in
`Correlations` (the `+N corr` chip) and the full host/onset timeline plus the
corroboration reason in the detail string. It is an `IsRollupType`, so
`SetFindings` purges stale instances whose cluster no longer regenerates, the
host-risk weight table excludes it (its constituent beacons already count), and
the same-pair correlation roll-up excludes it from its eligible set on
subsequent runs (no recursive feedback).

**Calibration.** All thresholds are global constants in `stage.go`, not Settings
knobs (calibration discipline). With no labeled malicious corpus to tune
against, the gate is deliberately stingy — under-fire by design. The worst case
from imperfect thresholds is a rare HIGH cluster on a rare shared internal-use
cloud app, never a CRITICAL false-positive storm (corroboration is required for
CRITICAL). Widen on first real-corpus contact.

### 2.10 Exfil-over-C2 corroboration on the beacon detail

A beacon to a rare external destination is the channel; data leaving the network
to that *same* destination is the payload. When both fire on one
`(sensor, src, dst)`, the beacon finding's detail says so directly — appended as
`Exfil-over-C2 corroboration: same destination also shows <signals>` — so the
analyst reading the beacon sees the second axis without pivoting. The
corroborating signals are the conn-derived egress/exfil detectors whose
destination is the real external endpoint: `Database Protocol Egress`, `Admin
Protocol Egress`, `Data Exfiltration`, and `Protocol on Unexpected Port`
(`internal/analysis/beacon_corroborate.go`). It applies to the conn-based beacon
types (`Beacon`, `HTTP Beacon`, `Port-Hopping Beacon`); `DNS Beacon` is excluded
because its destination is the resolver, not the C2 endpoint, so a same-dst
egress would be coincidental. This is **annotation-only** — it enriches the
story, it does not change the beacon's score or severity (the pair-level lift is
the `Correlated Activity` roll-up's job, §3-wide; bumping a beacon's rank on
corroboration is a calibration-gated change held for real-corpus evidence). The
signal list is sorted so the detail string is stable across re-runs, and detail
is outside the finding fingerprint, so analyst state on the beacon is preserved.

### 2.11 DNS context on port-53 beacons

A conn-level `Beacon` on destination port 53 has three possible truths:
cadence to a resolver the host legitimately uses, DNS C2 riding through
that resolver (which the `DNS Beacon` detector scores per queried domain,
§9.6), or raw-socket C2 squatting on 53 because that port egresses
everywhere. The dns.log resolver index built during DNS analysis tells the
first apart from the last, and the annotation pass
(`internal/analysis/dns_context.go`, phase 3.45) writes the answer onto the
beacon's detail:

- **Pair carried real queries** → `DNS context: active resolver for this
  source (N queries, M domains) — per-domain cadence is scored by DNS
  Beacon.` Resolver chatter; a pair-allow candidate.
- **Pair carried none** → `DNS context: no DNS queries observed on this
  pair — port-53 transport without DNS semantics.` The evasion tell worth
  a close look. When Zeek's DPD labelled the flow `dns` but dns.log has
  nothing for the pair, the message softens to a possible dns.log coverage
  gap instead — the honest read.
- **Sensor ships no dns.log at all** → no annotation either way; "no DNS
  queries observed" would be a false claim when the log simply isn't
  collected.

Like §2.10 this is **annotation-only** — no score or severity change;
whether the no-DNS-semantics case deserves a boost is a calibration-gated
decision held for real-corpus evidence.

`DNS Beacon` findings get the inverse bridge: because their destination is
the queried apex (the channel identity), the detail carries
`Resolved: <ip, …>` — the A/AAAA answers seen for that apex in dns.log
(IPs only, CNAMEs filtered, capped at 8) — so the analyst can pivot from
the FQDN to conn traffic and TI on the addresses behind it.

---

## 3. HTTP Beacon

**Where.** `internal/analysis/http_analysis.go`.

Same four-axis scoring as TCP beaconing, but the grouping key is
`(src, dst, host, uri)` rather than just `(src, dst)`. The minimum request
count is `HTTPBeaconMinRequests` (default 8). Otherwise the math is identical:
Bowley + MAD on intervals, Bowley + MAD on `orig_ip_bytes`, the same circadian
hour-of-day histogram, the same persistence test, and the same `conf_mod`
sample-size modifier with `HTTPBeaconMinRequests` as the base.

The DGA hostname augmentation (see §2.5) applies on the `host`
component of the (src, host, uri) key — HTTP Beacon
findings with DGA-shaped Host headers get the same +15 score
and severity bump.

This catches implants that beacon over HTTP/HTTPS to a fixed URL — common in
Cobalt Strike, Sliver, Mythic, and most red-team frameworks.

---

## 4. Strobe

**What it is.** One source talks to one destination an *enormous* number of
times. Worm propagation, scan loops, and malformed clients all look like this.

**Formula.** For each `(src, dst)` pair, both conditions must hold:

- `count ≥ StrobeMinConnections` (default 100) — count floor
- `count / span ≥ StrobeMinRatePerSec` (default 0.5/s) — rate gate

where `span` is `last_timestamp − first_timestamp` for the pair. If either
condition fails the pair is not classified as Strobe. The rate gate is the
primary discriminator: a slow C2 beacon firing once a minute for 30 days has
count 43 200 (above any count threshold) but rate ≈ 0.017/s (well below
0.5/s), so it is correctly left for the Beacon detector.

```
score = clamp( 50 + 15·log10(count), 1, 88 )
```

The detail string reports both count and rate: `Connection count: N | Rate: R/s (threshold: ≥0.5/s)`.

**Strobe suppresses Beacon.** A pair where Strobe fires (both conditions
met) is excluded from the Beacon analyzer's output. A pair where only the
count floor is met but the rate gate fails is passed to the Beacon analyzer
— it is a slow beacon, not a strobe.

---

## 5. Long Connection

**What it is.** A single TCP connection with a duration measured in hours. The
attack rationale: long-haul reverse shells, SSH tunnels, RDP-over-tunnel.
Legitimate cause: VPN sessions, video calls, NFS mounts.

**Formula.** `hours = duration_seconds / 3600`. If `hours ≥ LongConnMinHours`
(default 1.0), emit:

```
score = clamp( 50 + hours/8, 1, 95 )
severity = High if hours > 24 else Medium
```

The slope `+1 per 8 hours` is gentle so that a 4-hour video call (~50.5)
scores noticeably below an 18-hour reverse shell (~52.25) but well below a
multi-day persistent tunnel.

---

## 6. Data Exfiltration

**What it is.** Asymmetric outbound transfer — the source sent dramatically
more bytes than it received. Real exfil rarely cares about the response;
download-heavy traffic (web browsing) is the inverse pattern.

**Formula.** Per `(src, dst)` aggregate `orig_bytes` and `resp_bytes`. Skip
if `dst` is a private IP (we only flag exfil to the internet). Convert the
outbound to MB. If `MB < ExfilMinBytesMB` (default 5 MB), skip.

```
ratio = orig_bytes / resp_bytes        if resp_bytes > 0
      = ExfilRatioThreshold + 1        if resp_bytes == 0 and orig_bytes > 0
```

Trigger if `ratio ≥ ExfilRatioThreshold` (default 10.0).

```
score = clamp( 55 + 12·log10(MB + 1), 1, 92 )
```

Severity is always `Critical`. The `+1` inside the log avoids `log10(0)` for
edge cases right at the threshold.

---

## 7. Off-Hours Transfer

**What it is.** Data leaving the network at 03:00 local time is more
suspicious than the same volume at 13:00, when nobody is watching dashboards.

**Formula.** Determine "off hours" from config. Default window is
`[OffHoursStart=22, OffHoursEnd=6]`, i.e., 22:00–06:00 interpreted in the
configured `timezone` (UTC when unset or unparseable). Because the window
crosses midnight, the comparison logic handles both wrap-around and
non-wrap-around cases.

For each `(src, dst)` outside private space, sum `orig_bytes` that occurred
inside the off-hours window. If the total is at least `OffHoursMinMB`
(default 1 MB):

```
score = clamp( 45 + 12·log10(MB + 1), 1, 78 )
severity = Medium
```

**Shared host-pair budget (v0.55.0).** Strobe (§4), Data Exfiltration
(§6), and Off-Hours Transfer (§7) all accumulate per-`(src, dst)` state
during the conn pass. To bound memory on very large corpora that pass
is capped at 500,000 tracked host-pairs; pairs first seen *after* the
cap is reached are not tracked, so these three detectors may undercount
on such a corpus. A status-banner warning fires when the cap engages, so
the undercount is never silent. **The Beacon detector is unaffected** —
its pair map is not capped, and the cap can only over-include a beacon
(by skipping a Strobe exclusion), never drop one. No score formula,
threshold, or finding type changed.

---

## 8. Lateral Movement, C2 Port, Protocol on Unexpected Port, Admin Protocol Egress, and Database Protocol Egress

These are pure pattern-match detections — no math, just categorical lookups.

**Lateral Movement.** Both `src` and `dst` are in RFC 1918 space and the flow
matches on either of two axes. **Port axis:** `dst_port` is one of the
lateral-movement ports — 445 (SMB), 3389 (RDP), 135 (WMI/RPC), 5985/5986
(WinRM), 22 (SSH), 23 (Telnet), 5900 (VNC). **Service axis:** Zeek's DPD
fingerprints the flow as an admin/lateral protocol (`ssh`, `rdp`, `rfb`/VNC,
`telnet`, `smb`, `dce_rpc` — the `lateralMovementServices` table in
`heuristics.go`) on a port *outside* that port set. Because every standard
lateral port is already in the port set, the service axis only adds the evasion
case the port view can't see: a remoting protocol tunneled over a non-standard
port (RDP over 443, SSH on 8022). Score is fixed at 78, severity High, on
either axis; the detail names whether the port or the protocol triggered it.
The service axis augments the port axis, it does not replace it — WinRM rides
`http` and is DPD-blind, so it stays port-only (5985/5986), and a blank or
unrecognized service simply falls through to the port check. Deduped per
`src→dst:port` so a noisy AD environment doesn't drown the analyst.

**C2 Port.** `dst` is public and `dst_port` matches a known-bad port (4444/4445
for Metasploit defaults, 31337 for Back Orifice, the IRC/Tor/proxy ports, etc.,
as listed in the `KnownC2Ports` table). Score 75, severity High — but
cross-checked against Zeek's DPD: when the port is one a benign protocol also
legitimately uses (`http` on 3128/8008/8888) and DPD confirms that protocol is
what's actually running, the finding is **downgraded to Medium (score 50) and
annotated** rather than firing High, since it's most likely the legitimate
service (a Squid proxy, JupyterLab, a generic web service) and not an implant
squatting the port. The finding is never dropped — real C2 on these ports still
surfaces through the beacon, JA3/JA4, and TI paths, which key on behavior rather
than the port number. A blank DPD result, or a protocol that *isn't* expected on
the port, leaves the finding at High (and the mismatch case is independently
caught by Protocol on Unexpected Port, below).

**Protocol on Unexpected Port.** Where C2 Port keys on the *port*, this detector
keys on the *protocol*. Zeek's dynamic protocol detection (DPD) inspects the
actual bytes of a flow and stamps `conn.log`'s `service` field with the L7
protocol it recognizes — `http`, `ssl`, `ssh`, `dns`, `smtp`, `ftp` — regardless
of which port it rode in on. The detector compares that service against the set
of ports the protocol is *expected* on (`expectedServicePorts` in
`heuristics.go`, a curated whitelist: `http` → 80/8080/8000/8008/8081/8888/3128,
`ssl` → 443/8443/993/995/465/…, `ssh` → 22/2222, etc.). A recognized service on
a port outside its set — `http` on 8443, `ssl` on 4444 — is a finding. This is
the answer to "an implant is speaking HTTP on a random high port to dodge my
port-based egress rules, and a port-only view can't see it." DPD often stamps a
multi-label service for one flow (`ssl,http`); the field is split and evaluated
per label, so `ssl,http` on 9443 fires, but `ssl,http` on 443 does not — `ssl` is
legitimate on 443, so the flow reads as benign HTTPS rather than a smuggled
protocol.

Score 70 (High), bumped to 75 when the port is *also* a known C2 default — a
protocol mismatch landing on 4444 is strictly more suspicious than one on an
arbitrary port. The DPD service is stamped onto the finding's `service` field
(persisted, migration 0036) and is queryable as `service:http`.

Two deliberate scoping decisions:
- **External destinations only.** Like C2 Port, this fires only when `dst` is
  public. Internal hosts legitimately bind services to arbitrary ports (an
  internal tool on `:9000`), so internal→internal mismatches are out of scope to
  keep the false-positive rate low.
- **Recognized protocols only.** When DPD can't fingerprint a flow — an encrypted
  tunnel it doesn't understand, a custom protocol — `service` is empty and
  nothing fires. This catches *known* protocols on the *wrong* port, not
  unrecognized tunnels. It's the high-value common case, not total coverage.

A connection can legitimately produce both a `C2 Port` and a `Protocol on
Unexpected Port` finding (e.g. `ssl` on 4444): they're distinct, corroborating
signals — one says "this port is a known C2 default," the other "DPD confirms a
real protocol running where it shouldn't" — and both contribute to the host's
risk roll-up.

**Admin Protocol Egress.** Where Lateral Movement watches *internal→internal*
admin traffic, this watches the same protocol family heading the other way:
*internal→external*. An internal host that speaks an interactive
remote-administration protocol — `ssh`, `rdp`, `rfb` (VNC), or `telnet`, the
`adminEgressServices` table in `heuristics.go` — to a public destination is
remote admin reaching the internet. That's rarely legitimate outbound and is a
common reverse-shell, exposed-RDP, and hands-on-keyboard egress signature. Like
the other service-aware conn detectors it keys on Zeek's DPD service, so it
catches the protocol on *any* port (RDP tunneled out over 443 fires just the
same). Severity is tiered by how suspicious the protocol is outbound: `telnet` /
`rdp` / `rfb` egress is **High (score 72)**; `ssh` egress is **Medium (score
50)**, because legitimate outbound SSH is common (cloud administration,
git-over-ssh) — surfaced for awareness and allowlisting (pair-allowlist the
known destinations) rather than treated as a conviction. The DPD service is
stamped on the finding and queryable as `service:rdp`, etc. WinRM rides `http`
and is DPD-blind, so it isn't covered here — that's the documented coverage gap
of keying on DPD.

**Database Protocol Egress.** The same internal→external shape, for the database
protocol family: an internal host speaking a cleartext database wire protocol —
`mysql`, `postgresql`, `mongodb`, or `redis` (the `svcDatabase` category in the
service catalog) — to a public destination. A bare database protocol crossing to
the internet is almost never legitimate: it means DB credentials and data are
moving in cleartext over the public network, or an exposed/abused database, or
exfiltration over a database channel. The detector keys on the catalog category
rather than a second hardcoded list, so it tracks the catalog as new DB labels
are added. **High (score 72).** There's a built-in false-positive floor: a
managed cloud database (RDS, Atlas, Redis Cloud) is normally reached over TLS,
which Zeek labels `ssl` — so DPD only stamps the bare `mysql`/`postgresql`/etc.
label on the *cleartext* flow, which is exactly the case worth flagging. A known
cloud-DB endpoint that genuinely accepts cleartext is the one benign pattern to
pair-allowlist.

---

## 9. DNS Detections

**Where.** `internal/analysis/dns.go`.

### 9.1 NXDOMAIN flood (DGA proxy)

Domain Generation Algorithms produce hundreds of pseudo-random domains and the
malware queries them sequentially until one resolves. The other 199 produce
NXDOMAIN. We count NXDOMAIN replies per source.

If `nxdomain_count ≥ DNSNXDomainThreshold` (default 200):

```
score = clamp( 45 + 15·log10(count), 1, 85 )
severity = High
```

### 9.2 DNS tunneling — per-query heuristics

Examines the leftmost label of every DNS query and flags it as tunneling-like
if **any** of the following are true:

1. **Long label.** `len(label) ≥ DNSTunnelLabelLen` (default 40 chars). Most
   real subdomains are short; tunnels encode payload bytes into the label.
2. **High entropy.** Shannon entropy of the label, computed as

   ```
   H(s) = − Σ p_c · log2(p_c)
   ```

   for each character `c` in the lowercased label. Fires only when
   `H ≥ DNSTunnelEntropy` (default 3.5 bits) **and** the label is at least
   `dnsEntropyMinLabelLen` (30) chars — the length floor excludes short
   compound-English hostnames (e.g. `google-site-verification`) whose
   per-character entropy is high but which aren't tunnels.
3. **Deep nesting.** The query has `≥ DNSTunnelMinDepth` dots (default 5).
   Nested labels are how DNS tunneling tools fragment payloads.

(A fourth signal — `qtype == "TXT"`/`"NULL"` firing on its own — was removed:
every SPF/DKIM/DMARC/ACME TXT query tripped it, flooding false positives.
Real tunnelers couple TXT/NULL with long/high-entropy/deep labels, which the
three signals above already catch.)

If any condition fires, deduplicate per `(src, apex)` and emit:

```
score = clamp( int(min(55 + 6·entropy, 88)), 1, 95 )   // inner min caps at 88
severity = High
```

### 9.3 DNS tunneling — subdomain diversity

A second-pass aggregate. For each `(src, apex)` we collect the set of unique
subdomains. If `|set| ≥ DNSUniqueSubdomainMin` (default 50):

- Sample up to 200 subdomains, compute Shannon entropy of each, average.
- `score = clamp( int(min(55 + 6·avg_entropy, 90)), 1, 95 )`  (inner min caps at 90)
- Severity is High if `avg_entropy > 3.0`, else Medium.

The distinct-subdomain set is bounded at `apexSubCap` (4096) per `(src, apex)` so
a DGA/tunnel host hammering one apex can't retain an unbounded string set; the
score is unaffected (cardinality only needs to clear the gate, and the entropy
sample reads at most 200), and the count renders as `N+` when the cap is hit.

### 9.4 Suspicious TLD

Categorical match against a curated list of free / abused TLDs (`.tk`, `.ml`,
`.gq`, `.cf`, etc.). Score 52, severity Medium. Deduped per `(src, apex)`.

### 9.5 DoH Bypass

A TLS session on port 443 to an IP in `DoHIPs` (Cloudflare 1.1.1.1, Google
8.8.8.8, Quad9, NextDNS, etc.) is DNS-over-HTTPS, which evades on-prem DNS
logging. Score 62, severity Medium. Source: `ssl.log` (DoH is an HTTPS
session — it never appears in `dns.log`). When the SNI field is present,
the detail includes the resolver hostname (e.g. `dns.google`) so the analyst
can confirm resolver identity without a separate lookup.

### 9.6 DNS Beacon — query-cadence on (sensor, src, apex)

The gap this closes: a regular-cadence, low-entropy, low-diversity DNS
heartbeat to a single FQDN — the Cobalt-Strike DNS-C2 shape — slips
*both* other DNS-aware paths and the conn-level beacon detector. DNS
Tunneling (§9.2/§9.3) needs long high-entropy labels or high subdomain
diversity; this has neither. Beacon (§2) is keyed on `conn.log` IP
pairs and never consumes DNS query timing; a DoH-free DNS beacon may
produce no conn-level beacon at all.

**Key.** `(sensor, src, apex)`, apex = eTLD+1 via the Mozilla Public
Suffix List (same extraction the diversity path uses). The sensor
dimension prevents timing streams from different Quiver collectors
from merging — events seen by two sensors are not causally related,
and combining them produces false inter-arrival intervals. Every
non-NXDOMAIN query to the triple contributes its inter-arrival interval
to an Algorithm-R reservoir — the exact timing machinery §2 runs for
IP pairs, reused here.

**Score composition** (each axis in [0,1]):

- **timing (weight 0.5)** — `statisticalScore` → multimodal → entropy
  → Lomb-Scargle spectral rescue. Identical recipe to §2.2(a); the
  spectral knobs (`SpectralEnabled`, FAP, min-obs, rescue gate) are the
  global ones, reused unchanged.
- **inverse subdomain-diversity (weight 0.25)** — `1 − subs/DNSUniqueSubdomainMin`.
  A fixed-FQDN heartbeat has ≈1 unique label (≈1.0); the score decays
  as diversity climbs.
- **window-coverage (weight 0.25)** — the average of the §2.2(c)
  histogram-regularity and §2.2(d) duration helpers. The duration helper
  uses the same bounded trailing persistence window as §2.2(d) (most
  recent 7 days of that sensor's dns.log span, or the whole span when
  shorter), so DNS-beacon persistence is retention-invariant too.

`score = clamp(100·(ts·0.5 + div·0.25 + cov·0.25), 1, 100)`; Critical
≥ 80, else High. DNS Beacon carries the same structured triage
fields as §2 (sample size, mean/median interval, jitter), the
`ts/hist/dur` sub-scores, and the beacon chart TSData payload (the
timing-scatter chart in the Beacon Chart dock tab is populated the same
as conn and HTTP beacons). `ds_score` is intentionally left zero (DNS
has no payload-size axis — the diversity axis is detector-internal and
surfaced in the Detail string, not overloaded onto `ds_score`).

**Three scoping rules keep it from double-counting and off benign noise:**

- **Diversity gate.** At or above `DNSUniqueSubdomainMin` the apex is
  exfil-shaped — DNS Tunneling owns it, and Correlated Activity links
  the two if the cadence is also regular. DNS Beacon does not fire.
- **NXDOMAIN exclusion.** NXDOMAIN responses are dropped from the
  cadence accumulation entirely: a beacon to a sinkholed/dead C2 is
  the NXDOMAIN-flood detector's finding (§9.1), and resolver-retry
  behaviour on failed lookups contaminates inter-arrival timing.
- **mDNS exclusion.** A `.local` query (RFC 6762 multicast DNS — link-local
  service discovery to 224.0.0.251/ff02::fb on UDP 5353, never a routable
  resolver lookup or C2) is dropped at the record level, ahead of *every* DNS
  detector — not just this one. mDNS device announcements have a naturally
  regular cadence that otherwise scores HIGH (a `samsung.local` printer or TV
  reading as a beacon), and their rotating service names
  (`_airplay._tcp.local`, …) inflate the Subdomain DGA diversity counter.
  Excluding `.local` at the source beats asking every operator to allowlist
  each device name.

**Port.** Every DNS finding's `DstPort` is the transport port of the first
contributing query (`id.resp_p`), not a hardcoded 53 — so a detection over DoT
(853) or an internal resolver on an odd port is labelled honestly. It defaults
to 53 only when the record omits the field. (The DNS keys are name-based, so the
port is informational, not part of identity. The one exception is DNS NXDOMAIN
Flood, a per-source roll-up across many apexes, which stays `(network)`/`53`.)

**Benign suppression.** Before scoring, an apex matching the built-in
CDN/cloud suffix allowlist (shared with the DGA augmentation, §2.5) or
the operator's curated allowlist is skipped — a constant-cadence
resolver/telemetry/CDN apex would otherwise aggregate every query
under one key and read as periodic.

**Calibration.** `DNSBeaconMinQueries` (Settings → Detection → DNS → *DNS Beacon
Min Queries*, default 20) is the sample-size floor — the minimum
queries to a `(src, apex)` before scoring, analogous to
`BeaconMinConnections`. The same `conf_mod` sample-size modifier (§2.2(f))
applies, using `DNSBeaconMinQueries` as the base. The timing/spectral math
reuses the global beacon knobs; there are no DNS-beacon-specific scoring
knobs.

**What it misses.** A beacon resolving via DoH is invisible to
`dns.log` entirely (no query records to time) — a TLS/SNI-layer
problem, out of scope here. DoH *usage* is still surfaced independently
by §9.5.

---

## 10. SSL/TLS Detections

**Where.** `internal/analysis/ssl.go`.

### 10.1 Malicious JA3

**What JA3 is.** A JA3 hash fingerprints a TLS *client* from its
`ClientHello`. Five fields are taken in order — TLS version, the
cipher-suite list, the extension list, the supported elliptic curves,
and the EC point formats — concatenated as comma-joined decimal values
separated by `-`, and MD5'd. The hash is deterministic for a given TLS
stack: it captures *how* the client negotiates, not *what* it talks to,
so it is independent of destination IP, SNI, or port.

**Why it catches implants.** Malware that statically links its own TLS
(Cobalt Strike's BeaconHTTPS, many Go/.NET implants) negotiates with a
fixed, often non-browser cipher/extension ordering, so every beacon
from every infected host produces the *same* JA3 — and that JA3 differs
from the host's browser/OS traffic. A curated hash is therefore a
high-confidence, low-false-positive signal: it does not depend on
timing, volume, or payload.

**What Archer does.** `ssl.go` reads the `ja3` field Zeek writes to
`ssl.log` (Archer consumes Zeek's value — it does not compute JA3
itself, so a sensor whose Zeek build lacks the JA3 script produces no
`ja3` and this detector cannot fire). The hash is looked up in
`KnownBadJA3` (a static, curated `map[hash]→framework-label` in
`heuristics.go` — Cobalt Strike default profiles, Metasploit, Sliver,
Brute Ratel; not feed-driven) **unioned with the operator JA3/JA4 IOC
list** (the *JA3 / JA4* tab of the IOC modal, or the *Mark malicious*
button on the TLS Fingerprints wall — `Analyzer.SetOperatorFingerprints`,
applied on the full-analysis path). An exact match against either source
emits **Malicious JA3**, score **95**, severity **Critical**, deduped per
`(src, dst, ja3)`; the label rides in the Detail string (`Operator IOC`
for an operator-supplied hash, the framework name for a built-in) and the
type carries risk weight 40 — the highest tier, because an exact
known-C2-stack match is about as unambiguous as network-only evidence
gets. The built-in table and the operator list are indistinguishable
downstream — only the Detail label differs.

**What it misses.** Exact-match only: a single changed cipher,
extension, or TLS-version bump in the implant's stack yields a new hash
the curated list won't have, so JA3 is strong against *unmodified*
tooling and weak against *recompiled/tuned* tooling. Legitimate
applications that share a TLS library can collide on one benign JA3, so
the list is deliberately conservative (curated, not heuristic). GREASE
(randomized extension/cipher values, RFC 8701) and uTLS/refraction-style
*randomized* fingerprints defeat static JA3 entirely — see §10.2 for
JA4, the structured successor that is GREASE-robust and human-readable.

### 10.2 Malicious JA4

**What JA4 is.** JA4 (FoxIO, 2023) is the structured successor to JA3.
Instead of MD5-hashing the raw `ClientHello` fields, JA4 produces a
human-readable string whose prefix encodes the TLS version, TCP/QUIC
transport, cipher-suite count, extension count, and ALPN, followed by
two 12-character truncated SHA-256 hashes of the cipher list and the
extension list. Example: `t12d190800_d83cc789557e_16bbda4055b2` is TLS
1.2, TCP, 19 ciphers, 8 extensions, no ALPN — immediately readable
without consulting a lookup table. JA4 is GREASE-robust (GREASE values
are excluded from the sorted lists before hashing) and more stable
across TLS library point-releases than JA3.

**Requirement.** JA4 requires the Zeek **JA4+** plugin on the sensor.
Stock Zeek `ssl.log` only carries `ja3` / `ja3s`. Archer reads `ja4`
opportunistically — an empty value is normal on stock sensors and never
an error.

**What Archer does.** `ssl.go` reads the `ja4` field (lowercased) and
looks it up in `KnownBadJA4` (same `heuristics.go`, same curated
`map[fingerprint]→label` pattern as JA3). The initial table covers
Cobalt Strike v4.9.1 in four variants (wininet/winhttp transport ×
SNI-present/absent) and IcedID loader, sourced from the FoxIO public
JA4+ database (`github.com/FoxIO-LLC/ja4`). An exact match emits
**Malicious JA4**, score **95**, severity **Critical**, deduped per
`(src, dst, ja4)`; risk weight 40 (same as JA3).

Sliver is intentionally absent from `KnownBadJA4`: its JA4 fingerprint
is identical to the generic Go `net/http` stack and would false-positive
on any Go service. This is the key difference from JA3 — JA4's
structured prefix makes per-tool fingerprints more collision-resistant
for *tool-specific* settings (cipher ordering, extension set), but
Go/Python/Rust runtimes still share their TLS stacks across legitimate
and malicious users.

**What it misses.** Same exact-match constraint as JA3. Cobalt Strike
Malleable C2 profiles that randomize the `ClientHello` field ordering or
mimic a browser stack will produce a different JA4 and evade this check.
The FoxIO database is the primary source for new entries — operators
should cross-reference `github.com/FoxIO-LLC/ja4/ja4plus-mapping.csv`
as new C2-exclusive fingerprints are documented and add them to
`KnownBadJA4` in `heuristics.go`.

### 10.3 SSL No-SNI

An *established* TLS session with no `server_name` extension is unusual.
Browsers and almost all modern clients send SNI. The absence is suspicious.

- If `dst_port` is a known C2 port → score 82, severity High.
- Otherwise → score 35, severity Low.

### 10.4 Domain Fronting

Joins `ssl.log` and `http.log` via the Zeek connection UID. If the SSL SNI is
*different* from the HTTP `Host` header, the client is using domain fronting:
the TLS handshake reaches an allowed CDN host, but the inner HTTP request
targets a different (likely-blocked) host through the same CDN. Score 88,
severity Critical.

This one is especially robust: it's not a probabilistic score, it's a
structural mismatch that has very few legitimate causes.

---

## 11. HTTP Detections

**Where.** `internal/analysis/http_analysis.go`.

### 11.1 Suspicious User-Agent

Substring match against a list of automation-flavored UAs (`curl`, `wget`,
`python-requests`, `powershell`, `go-http-client`, etc.). Score 30, severity
Low. Low score because legitimate scripts use these too — it's context.

### 11.2 Cobalt Strike URI checksum8

Cobalt Strike's default malleable C2 profile uses URIs whose ASCII byte sum
modulo 256 equals 92 (x86 stager) or 93 (x64 stager). The check:

```
csChecksum8(uri) = ( Σ byte_value(c) for c in uri ) mod 256
```

If the result is 92 or 93, score 93, severity Critical, with the variant
labeled. This is a notoriously useful detection because most CS operators
never change the default profile.

### 11.3 C2 URI Pattern (regex set)

A list of compiled regular expressions for paths used by common implants
(`/api/v1/checkin`, `/jquery-3.3.1.min.js` to non-jQuery hosts, etc.). Score
91, severity Critical.

### 11.4 Suspicious File Download

Either the response MIME type matches `SuspiciousMIMETypes`
(`application/x-msdownload`, `application/x-dosexec`, ...) or the URI ends
with a suspicious extension (`.exe`, `.dll`, `.ps1`, `.scr`, ...). Score 72,
severity High.

---

## 12. Threat Intel Hits

**Where.** `internal/analysis/ti.go` (IP and domain matches),
`internal/analysis/files.go` (`checkFileHashes` for hash matches).
Cross-annotation in `internal/server/ti_crossnote.go`.

**Finding types.** As of v0.7.0, what was a single `Threat Intel Hit`
type splits three ways based on what was actually matched:

| Type              | What matches                                                       |
|-------------------|--------------------------------------------------------------------|
| `TI Hit (IP)`     | dst IP against FeodoTracker / URLhaus IPs / OTX / AbuseIPDB / MISP / OpenCTI IP+CIDR |
| `TI Hit (Domain)` | dst domain against URLhaus hosts / MISP / OpenCTI domains          |
| `TI Hit (Hash)`   | files.log md5/sha1/sha256 against MISP / OpenCTI hash indicators   |

Pre-v0.7.0 findings carry the legacy `Threat Intel Hit` type; the
`model.IsThreatIntelType` helper recognizes both old and new strings,
so the IOC Hits tab, notification bell, host-risk weighting, and
cross-annotator handle them uniformly.

### 12.1 Pipeline placement

Phase 0 (`prefetchFeeds`) runs concurrently with the rest of analysis startup
and pulls two open feeds into memory: Feodo Tracker (botnet C2 IPs) and
URLhaus (malware distribution IPs + hosts; the `csv_online` slice — currently
active URLs only). It also snapshots the configured MISP / OpenCTI feeds
from the cached `Store.EnabledFeedIndicators()` (memoized — see v0.7.0
release notes for the cache).

Phase 3 runs three matchers in parallel:

- `checkTI` — IP and domain matches against built-in feeds + MISP/OpenCTI
- `checkSuspiciousURLs` — domain matches against HTTP host headers
  (separate finding type with URI context)
- `checkFileHashes` — file-hash matches against MISP/OpenCTI hash buckets

The TI phase is also reachable on its own via `Analyzer.AnalyzeTIOnly` —
runs Phase 0 + Phase 3 (`checkTI` + `checkSuspiciousURLs` +
`checkFileHashes`) without any of the statistical phases. Used by the
archive IOC re-scan and by the watch loop's incremental ticks (see
section 12.9 below).

### 12.2 Sources of destinations

`checkTI` builds a per-destination → per-source observation map from four
sources, in this order:

1. **`conn.log`** — every external (non-private) `id.resp_h`, with the
   `id.orig_h` that contacted it, the responder port, and `ts`. This is the
   critical-path source: a one-shot connection to a Feodo C2 may not trip
   any other detector (no beacon score, no suspicious port), so the dst set
   has to come from the raw conn pass, not from already-generated findings.
2. **`dns.log`** — every queried name (skipping records whose query is itself
   an IP), with `id.orig_h` (the host that issued the query) and `qtype_name`
   (A/AAAA/TXT/...).
3. **`http.log`** — every `host` header, with `id.orig_h`, `id.resp_p`, and
   the request `uri`. Hostnames that are bare IPs are routed to the IP map
   instead of the domain map.
4. **Existing findings** — any non-synthetic `DstIP` from findings already
   produced by earlier phases. Pulls the finding's `SrcIP` along when it's a
   real IP (skipping the `(TI)`, `(network)`, `(escalation)`, `(cert)`
   placeholders). This catches dsts the log scans above might miss — for
   example, a `Lateral Movement` finding whose dst was synthesised from a
   reassembled session.

Each `(dst, src)` pair stores one observation (port, ts, proto, qtype, uri,
count). Repeated contacts from the same src bump count but never allocate
a new entry, bounding memory under pathological volumes and giving
`count` as a useful signal in the resulting Detail string.

### 12.3 Feed matching

| Feed                | Match against              | Emits as          | Score | Severity                         | Auth                   |
|---------------------|----------------------------|-------------------|-------|----------------------------------|------------------------|
| FeodoTracker        | dst IPs                    | `TI Hit (IP)`     | 99    | CRITICAL                         | none (public)          |
| URLhaus IPs         | dst IPs                    | `TI Hit (IP)`     | 97    | CRITICAL                         | none (public)          |
| URLhaus hosts       | dst domains                | `TI Hit (Domain)` | 97    | CRITICAL                         | none (public)          |
| OTX (AlienVault)    | dst IPs (cap 20/run)       | `TI Hit (IP)`     | `min(70 + pulses*3, 99)` | HIGH; CRITICAL if pulses ≥ 7   | API key       |
| AbuseIPDB           | dst IPs (cap 10/run)       | `TI Hit (IP)`     | `min(50 + score/5, 99)`  | HIGH; CRITICAL if confidence ≥ 80 | API key    |
| MISP / OpenCTI IP   | dst IPs / CIDR membership  | `TI Hit (IP)`     | 90    | HIGH                             | per-feed config        |
| MISP / OpenCTI dom. | dst domains                | `TI Hit (Domain)` | 90    | HIGH                             | per-feed config        |
| MISP / OpenCTI hash | files.log md5/sha1/sha256  | `TI Hit (Hash)`   | 90    | HIGH                             | per-feed config        |

OTX/AbuseIPDB are rate-capped per analysis run because both have free-tier
quotas an analyst's box can chew through quickly on a busy day. Feodo,
URLhaus, MISP, and OpenCTI are bulk fetches, so cap doesn't apply.

**IPv6 IOC matching.** IP-shaped entries in all three match surfaces
(IOC list, operator allowlist, MISP/OpenCTI feed matchers) are
canonicalized via `net.ParseIP().String()` before storage and lookup.
A non-canonical IPv6 form in an IOC list (e.g.
`2606:4700:4700:0:0:0:0:1111`) matches the compressed form Zeek emits
(`2606:4700:4700::1111`) and vice versa. IPv4 and domain entries are
unaffected. (Added v0.33.0.)

### 12.4 Emit shape — one TI Hit per (src, dst, port)

A feed match emits **one TI Hit finding per distinct `(src, dst, port)`
triple** that contacted the bad dst. The emit step has two passes: a
per-dst merge that collapses overlapping TI sources (multiple feeds
flagging the same destination), then a per-src fan-out across every
internal host that contacted the merged dst.

**Pass 1 — per-dst merge.** When the same destination is flagged by
more than one TI source (e.g. a MISP indicator that's also in
FeodoTracker, or an IP in both OTX and AbuseIPDB), the merge collapses
the matching `tiHit` records to one entry per dst:

- Score / Severity = the highest of any matching source (Feodo's 99
  Critical wins over a feed's 90 High)
- Detail = every source's verdict joined with `" | "` so the analyst
  still sees full provenance (`URLhaus malware distribution IP: 1.2.3.4 |
  MISP indicator match: 1.2.3.4`)
- Source label = source names joined with `" + "` (`URLhaus + MISP`)

This merge landed in v0.21.0. Pre-fix the per-src fan-out below ran
once per (dst, source) pair × once per contacting src, producing N×M
findings with identical `Fingerprint(Type, SrcIP, DstIP, DstPort)`.
`SetFindings`'s carry-forward branch returned the same `old.ID` for
all the duplicates, the second `INSERT` collided on the UNIQUE
primary key, and the entire `saveFindings` transaction rolled back —
leaving the DB stuck in its pre-Analyze state while the in-memory
`s.findings` reflected the new findings (visible as "rollups
disappear after rebuild"). Per-host TI signal is unchanged; only the
raw row count drops.

**Pass 2 — per-src fan-out.** For each merged dst, the emit step
walks every distinct internal source that contacted it and emits one
TI Hit finding per src:

- `SrcIP` = the real internal host (`id.orig_h` from conn/dns/http)
- `DstIP` = the matched IP or domain
- `DstPort` = observed responder port for IP hits; `53` for DNS-sourced
  domain hits; `80` for HTTP-sourced domain hits
- `Timestamp` = first observed contact time (Zeek `ts`), not analyzer
  wall-clock — so the row sorts naturally next to the actual traffic
- `SourceFile` = the merged source label from Pass 1 — a single feed
  name (`FeodoTracker` / `URLhaus` / `OTX` / `AbuseIPDB`) when only
  one source matched, or sources joined with `" + "` (`URLhaus + MISP`)
  when multiple matched
- `Detail` = the merged Pass 1 Detail plus an evidence suffix:
  - `… — observed via conn on port 443 (12 session(s))`
  - `… — observed via HTTP on port 80 (3 request(s))`
  - `… — DNS A query (5 lookup(s))`
  - `… — HTTP request to /malware.exe (1 request(s))`

This turns what was previously a dead-end `(TI) → 1.2.3.4` row into a
triagable per-host record an analyst can ack/escalate/pivot from. The raw-log
lookup (`/api/findings/{id}/raw`) also starts working for TI hits, since the
`(src, dst)` pair now matches real records on disk.

### 12.5 Fallback to `(TI)` placeholder

When `checkTI` can't attribute a src to a matched dst — typically when the
dst was pulled from a synthetic finding in Source 4 and no fresh log
evidence supports it — the emit step keeps the legacy single-row form with
`SrcIP = "(TI)"` and the original feed verdict in Detail. This is the "I
know this dst is bad but can't tell you who talked to it" case; without it,
the hit would be silently dropped.

### 12.6 Split-horizon DNS caveat

In environments where workstations send DNS to an internal resolver
(BIND/Pi-hole/Windows DNS/AD DC/corporate DoH proxy) and the Zeek sensor
sees only resolver→upstream traffic, every `dns.log` record's `id.orig_h`
is the resolver's IP, not the workstation that triggered the lookup.
Attribution still lands on "the host that did the lookup Zeek observed,"
which is one hop short of the workstation but better than no attribution.
Zeek can't bridge this gap from the wire alone — the analyst needs the
resolver's own query log to find the originating workstation. The same
shadowing applies to `http.log` when the sensor sits behind an HTTP proxy.

### 12.7 Cross-annotation onto sibling findings

After the analyzer's results are merged into the store, the server walks
every newly-detected TI Hit (any of `TI Hit (IP)` / `TI Hit (Domain)` /
`TI Hit (Hash)` plus the legacy `Threat Intel Hit` for pre-v0.7.0
findings still in the DB; gated through `model.IsThreatIntelType`) and
appends a `TI Enrichment` system note to every other finding whose
`DstIP` or `SrcIP` matches the hit's IP. So an analyst opening (say) a
beacon finding for `10.0.0.5 → 1.2.3.4` automatically sees a
`FeodoTracker` annotation inline, instead of having to notice a separate
`TI Hit (IP)` row. `Suspicious URL` is excluded from the cross-annotation
trigger set — the corresponding `TI Hit (Domain)` for the same host
already carries the enrichment, and double-noting would clutter the
sibling findings.

The cross-note loop dedupes per `(dst, source)` so the per-source fan-out
doesn't write N copies of the same enrichment note onto each related
finding. The `IsNew` filter also prevents re-runs from piling on duplicate
notes for the same hit — once a fingerprint has been seen, `SetFindings`
carries it forward as `IsNew=false` and the cross-annotation loop skips
it.

### 12.8 TI Results tab

The detail dock's **TI Results** tab consolidates all threat-intel
evidence for whatever is currently in view:

- **Direct TI Hit finding.** When an analyst selects a `TI Hit (IP)`,
  `TI Hit (Domain)`, or `TI Hit (Hash)` row, the finding's own detail is
  synthesised into a TI Results entry (author = the finding type,
  text = the detail string). The cross-annotation notes from §12.7 appear
  alongside it for any sibling findings already annotated.
- **Host pivot.** Opening a host row in the Hosts tab renders the full
  contact set; the TI Results tab is populated with every TI Hit in that
  contact set and badged with the count.
- **Campaign pivot.** Opening a campaign row in the Campaigns tab renders
  the per-destination finding list; TI Results is populated with every TI
  Hit targeting that destination.

In all three modes, non-TI-Enrichment notes remain in the **Analyst
Notes** tab and TI cross-annotations route to **TI Results** — the
partition is `author === "TI Enrichment"` in the notes array.

### 12.9 Notification suppression

TI Hit notifications still fire for new hits (any flavor), but `Host Risk
Score` (the per-host roll-up emitted by Phase 4) is excluded from the bell
on purpose — that's an aggregate, not a discrete event, and the underlying
network detections that pushed the host's score over the line have
already generated their own notifications. See section 14 for the
roll-up's scoring algorithm.

### 12.10 Two-tier watch cadence

Statistical detectors (Beacon, HTTP analysis, DNS NXDOMAIN flood,
etc.) need the full temporal window of Zeek logs to spot patterns —
beaconing math operates on hours/days of `(src, dst, port)` interval
arrays. TI matching has no such requirement: each connection-to-bad-IP
is independently meaningful regardless of what came before it.

The watch loop exploits that asymmetry. On any UTC calendar day:

- **First tick → full pipeline.** All phases run, all detectors get a
  fresh refresh against the entire `/logs` tree.
- **Subsequent same-day ticks → incremental TI pass.** Calls
  `AnalyzeTIOnly` against the file subset whose mtime is newer than
  `LastAnalysisUnix - 5 min` (the 5-minute overlap absorbs files
  rotated right at the boundary). Statistical detectors don't run.

Two persisted timestamps in the settings table drive the decision:

- `LastFullAnalysisUnix` — set on every full-pipeline completion (watch
  tick, manual "Discard & re-analyze", or the manual analyze button).
  Compared against `time.Now().UTC().YearDay()` to gate full-vs-incremental.
- `LastAnalysisUnix` — set on every successful run of either kind.
  Used as the mtime cutoff for the next incremental tick's file filter.

Manual full-pipeline runs (the analyze button or "Discard &
re-analyze") flow through the same code path and reset both timestamps,
so the two-tier cycle restarts cleanly from a manual baseline.

**Rollup preservation across incrementals (v0.21.0).** `Store` exposes
two persistence entry points so the watch loop can be honest about
what's been re-evaluated. Full passes call `SetFindings` (the
"authoritative" path), which carries analyst state forward by
fingerprint AND purges historical roll-up findings — Correlated
Activity, Host Risk Score — whose fingerprints aren't in the fresh
emission set. Incremental TI-only passes call `SetFindingsIncremental`
(the partial-pipeline path), which carries state forward identically
but **does not** purge roll-ups. Without that split, every incremental
tick (5 between UTC-midnight full passes) would drop every CA / HRS
the prior full pass had emitted, since `correlateFindings` and
`aggregateRisk` don't run in incrementals — the absence in the new
emission set would be interpreted as "no longer valid" rather than
"not re-evaluated this pass."

Watch ticks emit a `done` SSE event with `incremental: true` for the
short-pass case so the UI can distinguish them from full-pipeline
completions. Incremental runs that find no modified files since the
last run skip silently with a status event ("Incremental tick: no new
logs since last run.") instead of producing a no-op `done` event.

**Detection latency.** TI hits surface within one tick interval (e.g.
hourly). Statistical detectors get a 24h refresh — a beacon that starts
between daily runs is detected on the next day's first tick. Real-time
beacon detection from a single hour of logs is mathematically
impossible, so this is the floor any honest design hits.

**Operator override — `WatchAlwaysFull`.** Settings → Operations → Watch Mode exposes
an **Always run full scan on every watch tick** checkbox that disables
the two-tier behavior entirely. When on, `triggerWatchAnalysis`
short-circuits the date-comparison check and routes every tick through
`launchAnalysisWithOptions` (full pipeline). Operators flip this on
during active hunts where the 24h gap on statistical detectors is too
slow; keep off for resource-conscious background monitoring where the
hourly TI freshness is enough between daily statistical refreshes. The
flag persists in the settings table as `watch_always_full`. The
`/api/watch` response reflects it: with the flag on, `next_run_kind`
always returns `"full"` and `next_full_run` always equals `next_run`,
so the sidebar drops the redundant "Next Full Scan:" follow-up line.

---

## 13. Zeek Notice Passthrough

**Where.** `internal/analysis/notice.go`.

Zeek already has its own notice framework (port scans, brute-force detection,
SSL anomalies). Archer ingests `notice.log`, dedupes per
`(src, dst, note_type)`, and turns each into a finding:

```
score = 92 if note_type contains "attack"|"scan"|"brute"|"sensitive"
score = 68 otherwise
```

This means Zeek's own detections are visible in the same UI as Archer's —
analysts don't have to swivel-chair between two log surfaces.

---

## 13a. Correlated Activity

**Where.** `internal/analysis/correlate.go`.

Per-record detectors are independent — Beacon fires on `conn.log`,
DNS Tunneling fires on `dns.log`, TI Hit (Hash) fires on `files.log`.
Each is a useful signal on its own, but the *combination* of multiple
detectors lighting up on the **same (SrcIP, DstIP) pair** is
qualitatively stronger evidence than any one of them: it's kill-chain
progression on a single host pair, not coincidence.

After Phase 3 (TI checks) and before Phase 4 (Host Risk Score), the
analyzer walks every finding and groups them by `(SrcIP, DstIP)`. When
a pair carries findings from `correlation_min_types` or more distinct
*eligible* detector types, the analyzer emits a `Correlated Activity`
finding and annotates the contributing findings with the IDs of their
siblings via `Finding.Correlations`.

**Eligibility.** The following types do not contribute toward the
threshold:

- `Host Risk Score` and `Correlated Activity` — both are roll-ups
  rather than per-record detections. Folding them in would
  double-count and risk recursive feedback the same way
  `aggregateRisk` would double-count itself if not type-filtered.
- `Zeek Notice` — passthrough of upstream Zeek policy hits; too noisy
  and too varied in shape to be a useful correlation signal in
  isolation.
- `Long Connection` — by itself a weak signal (legitimate VPNs,
  keepalives, long-lived SaaS sessions). Pairing it with one other
  type would inflate correlation counts on every busy host.

**Scoring.** Score = max(contributor scores) + 5 per distinct type
above the minimum, capped at 99. Severity from standard score bands
(`≥80 Critical | ≥60 High | ≥40 Medium | else Low`). Concrete
examples:

- Beacon(85) + DNS Tunneling(60) → 85 (Critical)
- Beacon(70) + DNS Tunneling(60) + Data Exfil(50) + Strobe(40)
  → 70 + 5×2 = 80 (Critical, two extra types above minimum of 2)
- HTTP Beacon(50) + Suspicious URL(45) → 50 (High)

**Historical context.** Like `aggregateRisk`, `correlateFindings`
unions this-run findings with the historical store snapshot via
`FindingsProvider` (NEW-67 pattern). A pair whose contributing
detections existed last run but didn't re-fire this run still
correlates as long as the historical findings are still in the store
— removes the "yesterday's DNS Tunneling + today's Beacon don't
correlate because we only see today's findings" gap.

**Sensor resolution timing (v0.20.2).** `correlateFindings` partitions
pairs on `(Sensor, SrcIP, DstIP)` so multi-sensor overlapping captures
don't conflate findings emitted by different Quiver collectors
observing the same flow. The Fingerprint used by `SetFindings` for
merge/dedup is `(Type, SrcIP, DstIP, DstPort, Sensor)`. Sensor is
included because sensor-partitioned aggregate detectors (DNS Beacon,
DNS Subdomain DGA, and all conn/HTTP beacon types) emit one finding per
sensor per pair; without Sensor in the key, two sensors observing the
same (src, apex) would collapse to a single DB row, discarding one
sensor's analyst notes on every re-analysis. The invariant that keeps
these keys consistent: every contributor's `Sensor` field must be
populated *before* it enters `correlateFindings`. The analyzer enforces
this in `Analyzer.add` — caller-set Sensor wins, then
`sensorOf(SourceFile)` for per-record detectors, then the
`defaultSensor` fallback set via `SetDefaultSensor` for aggregate
findings whose SourceFile is empty. Pre-fix the watch loop assigned
Sensor in a post-`Analyze` pass, so fresh aggregate contributors
entered correlate with `Sensor=""` while historical contributors carried
their persisted Sensor — two pair keys for the same (src, dst), two
Correlated Activity emissions with identical Fingerprint, and no
in-batch fingerprint dedup in `SetFindings` to collapse them. Any
future refactor that relocates Sensor assignment must keep it ahead of
the correlation phase.

**Stale-row handling.** `Store.SetFindings` purges historical
`Correlated Activity` (and `Host Risk Score`) rows whose fingerprints
aren't regenerated this run. Without that, a pair that dropped below
the threshold would leave an orphan roll-up pointing at contributors
that may have been archived or fallen out of scope. The roll-up has
an authoritative regeneration phase; absence-from-regeneration is
authoritative.

**ID translation across SetFindings (v0.15.1, NEW-71).** The analyzer
populates each contributor's `Correlations` slice with the per-run
`a.nextID++` IDs at emit time, before SetFindings has had a chance
to rewrite IDs via fingerprint match. SetFindings now builds a
fresh-ID → persisted-ID map during its existing rewrite loop and
translates every new finding's `Correlations` slice through it.
Preserved historical findings (not regenerated this run) keep their
slices unchanged — those references were already translated when
the prior SetFindings persisted them, and stay in terms of persisted
IDs. References that don't survive translation (would only happen if
correlate.go annotated a finding with an ID that doesn't appear in
the current run, which the implementation prevents) are dropped
defensively.

**Historical-correlation semantics (v0.15.1, NEW-75).** A
preserved-historical contributor that participated in a correlation
last run keeps its `Correlations` slice through SetFindings, but
correlate.go's annotation pass walks only this-run's `a.findings`
slice and doesn't touch historical findings. The result: a
contributor preserved across re-analyses (e.g. DNS Tunneling fires
once a week, Beacon fires daily) carries its slice as a record
of *past co-firing* rather than a guarantee of *current
co-firing*. This is honest for analyst use — the chip click still
resolves to a Correlated Activity row by (src, dst) triple, and if
the present-day correlation no longer holds the chip count is the
historical record. Analysts inspecting an old finding with a chip
should treat the slice as "this finding was correlated with these
others at some point in its history."

**Tuning.** `correlation_min_types` (default 2) controls the
threshold. Raise to 3 if multi-protocol SaaS (AWS SDK polling + DNS
to S3 + TLS to CloudFront) produces too many false-positive
correlations on benign destinations. Value < 2 is rejected at the
config API and short-circuited defensively in `correlateFindings`
itself (NEW-66 defense-in-depth pattern).

**UI surface.** The roll-up appears as its own `Correlated Activity`
row. Right-click it → **Show contributing activity** to filter the
Findings tab to that `(src, dst)` pair, so the roll-up and every
contributor land in one view. Each contributor also carries its
sibling IDs in the `correlations` field (exposed on `/api/findings`).

---

## 14. Composite Host Risk Score

**Where.** `internal/analysis/risk.go`.

After all per-finding analyzers have run, a final pass groups findings by
`SrcIP` and computes a composite score per host. Each detection type
contributes a weight:

| Detection type          | Weight |
|-------------------------|--------|
| Cobalt Strike URI       | 40     |
| Malicious JA3           | 40     |
| Malicious JA4           | 40     |
| C2 URI Pattern          | 38     |
| DNS Tunneling           | 35     |
| TI Hit (IP)             | 35     |
| TI Hit (Domain)         | 35     |
| TI Hit (Hash)           | 35     |
| Domain Fronting         | 32     |
| Beacon               | 30     |
| Port-Hopping Beacon  | 30     |
| DNS Beacon           | 30     |
| SSL No-SNI on C2 Port   | 30     |
| Suspicious URL          | 30     |
| HTTP Beacon          | 28     |
| Data Exfiltration       | 25     |
| Suspicious File Download| 25     |
| Protocol on Unexpected Port | 25 |
| DNS Subdomain DGA       | 22     |
| C2 Port                 | 22     |
| Lateral Movement        | 20     |
| Suspicious Certificate  | 20     |
| DNS NXDOMAIN Flood      | 18     |
| DoH Bypass              | 18     |
| SSL No-SNI              | 15     |
| Strobe                  | 15     |
| Suspicious UA           | 12     |
| Long Connection         | 10     |

(Each TI Hit flavor independently adds 35 — a host that triggered a
DNS-domain hit AND a file-hash hit gets +70. The legacy `Threat Intel
Hit` type from pre-v0.7.0 findings also weights 35 for backward
compatibility. Types not in this table contribute zero to HRS.)

For each host, the composite scales each type's weight by the highest-scoring
finding of that type and by the count of distinct destination IPs that type
fired on:

```
scoreScale(t)  = 0.5 + 0.5 × maxScore(t) / 100
multiMod(t)    = min( 1 + 0.5 · log₂(n_dsts(t)), 3.0 )
contribution(t) = round( weight(t) × scoreScale(t) × multiMod(t) )
composite       = dampenComposite( Σ contribution(t) )
```

`n_dsts(t)` is the number of distinct `DstIP` values for findings of type `t`
on this host (across both this run and the historical store union). For a
single destination, `multiMod = 1.0` and the behaviour is identical to the
pre-multiplicity formula. For two distinct destinations, `multiMod = 1.5`; for
four, `multiMod = 2.0`; the cap of 3.0 prevents runaway accumulation.

The rationale: a host beaconing to three distinct C2 servers is materially
worse than one beaconing to one, even if each individual finding scores the
same. Type dedup (taking only the max score) was deliberately kept to answer
"how many independent *kinds* of bad behavior" — the multiplicity modifier adds
"at how many distinct *targets*" without re-introducing per-finding counting.
The same DstIP appearing via both the fresh emission set and the historical
union counts once (set dedup).

When a type fires against more than one destination its entry in the detail
string is annotated: `TI Hit (IP)×3` means three distinct IPs triggered that
detector.

**Score dampening.** Rather than a hard clamp at 99, raw composites above 75
follow an asymptotic curve:

```
dampen(raw) = 75 + 24 × (1 − exp( −(raw − 75) / 50 ))   for raw > 75
dampen(raw) = raw                                          for raw ≤ 75
```

Concrete values: raw=100 → 84, raw=150 → 94, raw=200 → 97, raw=400 → 99.
This preserves rank-order at the high end — two heavily-saturated hosts can
still be compared — while preventing any host from pinning at 100 (reserved
for exact-match detectors like known JA3/JA4 hashes).

Severity buckets:

- ≥ 75 → Critical
- ≥ 50 → High
- ≥ 25 → Medium
- < 25 → Low

**Status filtering is deliberately absent from `aggregateRisk`.** Dismissed
findings still contribute to HRS. Dismiss is a lightweight reversible
view-state bucket ("hide from my default tabs"), not a "false-positive,
drop it" verdict. The underlying detection is still real evidence about
the host until it's expired by re-analysis or actively suppressed via
the IOC / allowlist / suppression surfaces. Putting load-bearing weight
on a one-click reversible action would be the wrong shape; analysts who
want a finding to stop influencing risk should use the allowlist or
suppression list instead. The contract is enforced by a code comment in
`aggregateRisk` and recorded under "Detection changes" in v0.18.0's
CHANGELOG entry. NEW-110.

---

## 15. Worked example you can use to explain a beacon

Imagine a workstation `10.0.5.42` connecting to `203.0.113.15` over TCP/443:

- 1287 connections over 22 hours.
- Inter-arrival intervals: median 60.0s, MAD 0.4s.
- `orig_bytes` per connection: median 412 bytes, MAD 6 bytes.
- Connections distributed evenly across 23 of the 24 dataset buckets.
- First and last timestamps span 96% of the dataset.

Step through the math:

- Bowley on intervals: ≈ 0, so `bowley_score ≈ 1.00`.
- MAD on intervals: `(60 − 0.4) / 60 = 0.993`, so `mad_score ≈ 0.99`.
- `ts_score = (1.00 + 0.99) / 2 = 0.995 ≈ 1.00`.
- Bytes — same shape, similar arithmetic → `ds_score ≈ 0.97`.
- 23 of 24 buckets populated, low CV → `hist_score ≈ 0.92`.
- Coverage 0.96, longest run probably ≥ 12 → `dur_score = 1.0`.

```
beacon_score = 100 × (0.25·1.00 + 0.25·0.97 + 0.25·0.92 + 0.25·1.00)
             = 100 × 0.9725
             = 97
```

Severity Critical (≥ 85). The detail line will read approximately:

```
Connections: 1287 | Mean interval: 60.3s | CV: 0.01 |
Score components: ts=1.00 ds=0.97 hist=0.92 dur=1.00 conf=1.00
```

That same host might also pick up a `C2 Port` finding (port 443 is not on
that list, so probably not), and would feed a Host Risk Score contribution of
approximately 30 from Beacon (weight 30 × (0.5 + 0.5×0.97) ≈ 30). Add a `Malicious JA3` or `Malicious JA4` hit with score 95 and the
composite jumps to approximately 30 + 39 = 69 — High severity (weight
40, score-scale 0.975, one destination).

---

## 16. Retention vs. detection window — tuning the analyzer's reach

Every statistical detector (Beacon, HTTP Beacon, DNS NXDOMAIN flood,
DNS tunneling diversity, off-hours transfer) operates only on the records
currently in `/logs`. Archived files under `/data/archive/` are out of scope
for the regular analyzer — the manual "Scan Archive for IOCs" admin button
only runs Phase 0 + Phase 3 (IOC matching), not the statistical phases.

That makes archive retention a **detection-coverage decision**, not just a
disk-usage one.

### 16.1 The math

For a `(src, dst, port)` triple beaconing at period `P`, the detector needs
at least `BeaconMinConnections` records inside the analysis window:

```
detectable iff:  retention_days × (1 day / P) ≥ BeaconMinConnections
                 P ≤ retention_days / BeaconMinConnections
```

With the default `BeaconMinConnections = 4`:

| Retention in /logs | Min detectable beacon period | Catches                                     |
|--------------------|------------------------------|---------------------------------------------|
| 5 days             | every 30h                    | Cobalt Strike, hourly C2, Empire / Sliver   |
| 14 days            | every ~3.5 days              | …plus slow daily APT cadence                |
| 30 days            | every ~7.5 days              | …plus most slow APT beacons                 |
| 60 days            | every 15 days                | …plus bi-weekly cadence                     |
| 90 days            | every ~22 days               | …reaching toward extreme patient adversaries |

The emit floor (score ≥ 40) is the primary quality gate at this threshold;
pairs with 4 connections but weak statistical structure will score below the
floor and be suppressed. Going slower than one connection per week requires
persistent per-triple state across runs (architecture change, not currently
implemented).

### 16.2 Score persistence vs. score evolution

Findings persist forever in the database via SetFindings's fingerprint
merge — every analyst note, ack, escalation, and status carries forward
across runs. But the *statistical score* on a finding is whatever the most
recent analyzer run that detected it produced. Once the original supporting
evidence ages out of `/logs`:

- The finding row stays (the historical detection is preserved)
- Re-analysis no longer emits a fresh finding for that triple (math fails
  the minimum threshold), so the score stays frozen at the original value
- An active beacon that's been running for 60 days won't show "60 days of
  evidence" in its score — it'll show whatever the analyzer computed when
  the original detection fired, even if subsequent runs would compute
  higher confidence on a longer sample

Path to live, evolving scores: persistent per-triple interval state across
runs. Major architecture change; out of scope for the current design.

### 16.3 Operational guidance

- **Active hunting + commodity malware focus** (Cobalt Strike, ransomware C2,
  hourly callbacks): 5–14 day retention. Hourly TI watch + daily full
  pipeline = fast loop, low storage cost. Misses daily/weekly APT cadence.
- **APT-aware threat hunting** (daily-cadence beacons matter): 30-day
  retention minimum. Roughly 6× the `/logs` footprint vs. 5-day; daily full
  run takes longer but two-tier watch keeps hourly TI fast regardless.
- **Maximum patient-adversary coverage** (weekly+ cadence): 60–90 day
  retention. Roughly 12–18× the disk vs. 5-day. At this retention the daily
  full-pipeline run is the dominant operational cost; schedule it for
  off-hours via the watch anchor time.

The tradeoff is purely between disk space, daily-tick wall-clock, and
detection floor. There is no algorithmic ceiling — a bigger window always
catches more.

**See also:** section 12.10 (two-tier watch cadence). Incremental TI ticks
process only mtime-filtered new files, so hourly TI freshness stays fast
regardless of how big `/logs` gets — only the once-daily full-pipeline tick
sees the full retention window.

---

## 17. What Archer is *not* doing

Worth stating explicitly so you don't oversell it:

- **No ML.** Every score above is a closed-form statistic. There is no model
  to retrain, no opaque classifier. The flip side is that Archer cannot learn
  novel patterns on its own — its detections only improve when you add new
  rules or new threat-intel feeds.
- **No payload inspection.** Archer reads Zeek's already-extracted metadata.
  It cannot decrypt TLS or look at HTTP body content. JA3, SNI, URI, and
  byte counts are all derived by Zeek, not Archer.
- **No identity correlation.** Source IPs are treated as the actor. NAT,
  shared workstations, and dynamic-IP environments will mix activity from
  multiple users into one Host Risk Score.
- **No cross-window beacon state.** Statistical detectors operate on the
  current `/logs` window only. Findings persist across runs (notes, status)
  but scores don't accumulate as more evidence arrives — see section 16 for
  the retention-vs-detection-window math and tuning guidance.

---

## 18. Threshold reference

All thresholds live in `internal/config/config.go` and can be overridden at
runtime. Defaults:

| Setting                  | Default | Used in                              |
|--------------------------|---------|--------------------------------------|
| BeaconMinConnections     | 4       | TCP beacon eligibility (min 4)        |
| HTTPBeaconMinRequests    | 8       | HTTP beacon eligibility (min 8)       |
| DNSBeaconMinQueries      | 20      | DNS beacon eligibility (min 20)       |
| LongConnMinHours         | 1.0     | Long Connection trigger               |
| StrobeMinConnections     | 100     | Strobe count floor (with rate gate)   |
| StrobeMinRatePerSec      | 0.5     | Strobe rate gate (conns/sec)          |
| ExfilMinBytesMB          | 5.0     | Exfiltration size floor               |
| ExfilRatioThreshold      | 10.0    | Out/in ratio                          |
| OffHoursStart / End      | 22 / 6  | Off-hours window (configured timezone) |
| OffHoursMinMB            | 1.0     | Off-Hours Transfer size floor         |
| DNSTunnelLabelLen        | 40      | DNS tunneling label length            |
| DNSTunnelEntropy         | 3.5     | DNS tunneling entropy bits            |
| DNSTunnelMinDepth        | 5       | DNS tunneling dot count               |
| DNSNXDomainThreshold     | 200     | NXDOMAIN flood trigger                |
| DNSUniqueSubdomainMin    | 50      | Subdomain diversity trigger           |

If you want to tune for a noisier or quieter environment, those are the dials.
The math is unchanged.
