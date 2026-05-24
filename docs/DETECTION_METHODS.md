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

- **Reservoir sampling.** Beacon analysis would otherwise need to remember every
  inter-arrival interval per (src, dst) pair. On a 3 GB capture that is a lot
  of memory. Archer keeps a bounded random sample of size *N* using
  Algorithm R (Vitter, 1985). Every observed value has an equal probability
  *N / total_seen* of being in the sample. Standard sample statistics
  (mean, median, variance, MAD) are unbiased estimators of the population
  values, so the regularity scores below are mathematically valid even though
  Archer never sees the full stream at once.

  **What this precludes.** Reservoir sampling shuffles the intervals into a
  random order to fit the cap, so by scoring time the slice has lost its
  temporal sequence. Order-independent statistics (Bowley, MAD, histogram
  counts, Shannon entropy on bucket counts) work fine on a reservoir;
  anything that needs the consecutive-interval relationship
  (autocorrelation, time-lag clustering) does not.
  **Frequency-domain analysis is the exception:** the spectral rescue path
  (v0.15.0) uses Lomb-Scargle rather than a binned FFT precisely because
  Lomb-Scargle is designed for unevenly-spaced (t_i, x_i) data with
  arbitrary ordering — the reservoir's preserved timestamp + value pairs
  are exactly the right input shape. See §2 for the math.
  If a future detector needs *consecutive-interval* information, it has
  to maintain a parallel bounded-window sample that preserves order
  alongside the existing reservoir — they're not derivable from each
  other.
- **Lazy state allocation.** Per-pair statistics are not allocated until a pair
  has been seen at least 3 times. High-cardinality, low-count pairs (one-off
  scans, NAT noise) never consume memory.

---

## 2. Beaconing — the headline detection

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

A pair is only scored if it has at least `BeaconMinConnections` connections
(default 10) and at least 3 intervals.

### 2.2 The four sub-scores

Each sub-score is in `[0, 1]`. The final beacon score is

```
beacon_score = 100 × (0.25·ts_score + 0.25·ds_score + 0.25·hist_score + 0.25·dur_score)
```

clamped to `[1, 100]`. Severity is `Critical` if score ≥ 80, else `High`.

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
reservoir-sampled connection timestamps. Lomb-Scargle (rather than
a binned FFT) handles unevenly-spaced data natively, sidestepping
bin-choice tuning. The Rayleigh power form gives the standard
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
Beaconing finding's Detail string gets a tag:

```
Connections: 200 | Mean interval: 60.4s | CV: 0.32 |
Score components: ts=0.62 ds=0.85 hist=0.71 dur=0.40 |
ts_layers: raw=0.31 mm=0.12 ent=0.08 |
Spectral rescued: score=0.62 (dominant period 60.3s, ...)
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

**CPU cost.** ~4 ms per pair on a 200-timestamp reservoir against
the 2000-point grid. Combined with the rescue-only gate, a hunt-
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

#### (c) hist_score — calendar-time uniformity

The dataset is sliced into 24 equal-width buckets between the dataset's
earliest and latest timestamps. For this pair, every connection lands in one
bucket. We then compute two scores and take the higher:

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

Did the beacon run across the whole capture, or was it active only for a brief
window? Two scores, take the max:

**Coverage.** `coverage = (last_ts − first_ts) / (dataset_max − dataset_min)`.
A beacon that's active end-to-end gets 1.0.

**Longest-consecutive-bucket run.** Walk the 24 buckets from start to end. The
longest run of consecutive non-empty buckets, divided by 12, is the
"consistency" score (clamped to 1.0). A run of 12 consecutive non-empty
buckets ≈ half the capture window of continuous activity.

`dur_score = max(coverage, consistency)`. Below 6 populated buckets total
(`minBars = 6`) the score is forced to 0 — there isn't enough activity to
meaningfully claim "persistence."

### 2.3 Detail line interpretation

A finding might read:

```
Connections: 1287 | Mean interval: 60.3s | CV: 0.04 |
Score components: ts=0.97 ds=0.95 hist=0.91 dur=1.00 |
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

- **Sub-score filtering.** The findings filter accepts inclusive
  `[min,max]` bounds on each of the four sub-axes (`ts_min`…`dur_max`;
  the Advanced bar and triage header label these **Timing** / **Data
  size** / **Histogram** / **Persistence** — the same `ts`/`ds`/`hist`/
  `dur` axes §2.2 describes, spelled out for the analyst).
  The composite score averages the axes, so a real implant profile —
  tight timing, short duration (a staging beacon) — sits below a score
  threshold despite textbook rhythm. The sub-score filter turns the
  score into a queryable signature space: `ts_min=0.8 & dur_max=0.3`
  pulls exactly the short-lived tight-cadence spikes the average
  buries. Any sub-score bound implicitly scopes results to beacon
  types (a structural-zero axis on a non-beacon can't satisfy a bare
  upper bound). See §2.2 for what each axis measures.
- **JA3 / JA4 cross-reference.** A conn-level Beaconing finding now
  carries the TLS client fingerprint of its seed connection (lifted
  from the same `ssl.log` index that resolves the SNI — Archer still
  does not compute JA3 itself; see §10.1). The detail view shows how
  many *other* beacons in the dataset share that JA3, and one click
  filters to them. Because an implant family reuses its TLS stack, a
  shared JA3 across pairs is implant-family attribution, not
  coincidence — the same logic §10.1 uses for the standalone
  Malicious JA3 detector, now joined to the beacon view.
- **HTTP-beacon URI footprint.** An HTTP Beaconing finding carries the
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
local traffic: mDNS pairs (`_tcp.local`, `_udp.local`) with
sub-30 s median intervals accumulate enough observations to produce
genuine periodogram peaks at 6–10 day periods (weekday/weekend
traffic rhythm), crossing FAP=12 after DC-correction. These produce
spectral-rescued findings at score 95+ that are operationally
benign. DC-correction cannot suppress them because the structure is
real. Analyst response: allowlist the pair, or treat mDNS findings
in the spectral-rescued set as noise unless TI hits, data-size
regularity, or high persistence score provide additional support.

### 2.5 DGA hostname augmentation

A beacon to `pool.ntp.org` is operational noise; the same timing
shape to `kx9j3qm2pflw.com` is high-confidence C2. After the
Beaconing, HTTP Beaconing, and DNS Beaconing detectors emit, a
post-Phase-2 sweep in `internal/analysis/dga.go` looks at each
finding's destination Hostname and decides whether the registrable
domain looks algorithmically generated.

**Where the Hostname comes from.** conn-level Beaconing gets it
from `sslUIDIndex` (TLS SNI). HTTP Beaconing gets it from the
`Host` header in `http.log`. DNS Beaconing gets it from the query
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

**Calibration.** The Settings → Beaconing pane has both
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
hooks `Store.SetFindings`: every time a Beaconing, HTTP Beaconing,
or DNS Beaconing finding lands, one row is written to `beacon_history`
keyed by `(Finding.BeaconHistoryKey(), today_UTC)` with the
composite score plus the four sub-axis components (ts, ds, hist,
dur). The PRIMARY KEY on `(fingerprint, day_utc)` plus
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
404) for non-Beaconing types so the SPA can call unconditionally on any
finding-detail open. See `docs/API.md` for the full shape.

**The chart.** SVG-rendered in the detail pane immediately below
the action buttons. Five lines:
- Composite **Score** (bold, severity color) on the 0–100 axis
- **ts / ds / hist / dur** (thinner, distinct colors) on the
  0–1 axis sharing the same plot

Reading the chart:
- A flat high score is a stable, persistent C2 channel.
- Climbing ts with stable ds = the beacon is becoming more
  regular over time (initial-jitter implant settling into a
  rhythm, or an operator-side scheduling cleanup).
- Climbing dur with flat ts/ds = the channel is staying alive
  longer each day; the implant's session-keepalive is
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

## 3. HTTP Beaconing

**Where.** `internal/analysis/http_analysis.go`.

Same four-axis scoring as TCP beaconing, but the grouping key is
`(src, dst, host, uri)` rather than just `(src, dst)`. The minimum connection
count is `HTTPBeaconMinRequests` (default 8). Otherwise the math is identical:
Bowley + MAD on intervals, Bowley + MAD on `orig_ip_bytes`, the same 24-bucket
histogram, and the same persistence test.

The DGA hostname augmentation (see §2.5) applies on the `host`
component of the (src, host, uri) key — HTTP Beaconing
findings with DGA-shaped Host headers get the same +15 score
and severity bump.

This catches implants that beacon over HTTP/HTTPS to a fixed URL — common in
Cobalt Strike, Sliver, Mythic, and most red-team frameworks.

---

## 4. Strobe

**What it is.** One source talks to one destination an *enormous* number of
times. Worm propagation, scan loops, and malformed clients all look like this.

**Formula.** For each `(src, dst)` pair count connections. If
`count ≥ StrobeMinConnections` (default 1000), emit:

```
score = clamp( 50 + 15·log10(count), 1, 88 )
```

Logarithmic scaling is used so 10 000 connections vs 100 000 still produces
distinguishable scores without saturating immediately.

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
`[OffHoursStart=22, OffHoursEnd=6]`, i.e., 22:00–06:00 UTC. Because the window
crosses midnight, the comparison logic handles both wrap-around and
non-wrap-around cases.

For each `(src, dst)` outside private space, sum `orig_bytes` that occurred
inside the off-hours window. If the total is at least `OffHoursMinMB`
(default 1 MB):

```
score = clamp( 45 + 12·log10(MB + 1), 1, 78 )
severity = Medium
```

---

## 8. Lateral Movement and C2 Port

These are pure pattern-match detections — no math, just categorical lookups.

**Lateral Movement.** Both `src` and `dst` are in RFC 1918 space and `dst_port`
is one of the lateral-movement ports: 445 (SMB), 3389 (RDP), 135 (WMI/RPC),
5985/5986 (WinRM), 22 (SSH). Score is fixed at 78, severity High. Deduped per
`src→dst:port` so a noisy AD environment doesn't drown the analyst.

**C2 Port.** `dst` is public and `dst_port` matches a known-bad port (8443
for many implants, 4444/5555 for Metasploit defaults, etc., as listed in the
`KnownC2Ports` table). Score 75, severity High.

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

   for each character `c` in the lowercased label. `H ≥ DNSTunnelEntropy`
   (default 3.5 bits) suggests the label is closer to random data than to
   English text.
3. **Deep nesting.** The query has `≥ DNSTunnelMinDepth` dots (default 5).
   Nested labels are how DNS tunneling tools fragment payloads.
4. **Exotic record type.** `qtype == "TXT"` or `qtype == "NULL"`. These are
   the canonical tunneling record types because they carry arbitrary text/bytes.

If any condition fires, deduplicate per `(src, apex)` and emit:

```
score = clamp( min(55 + 6·entropy, 88), 1, 88 )
severity = High
```

### 9.3 DNS tunneling — subdomain diversity

A second-pass aggregate. For each `(src, apex)` we collect the set of unique
subdomains. If `|set| ≥ DNSUniqueSubdomainMin` (default 50):

- Sample up to 200 subdomains, compute Shannon entropy of each, average.
- `score = clamp( min(55 + 6·avg_entropy, 90), 1, 90 )`
- Severity is High if `avg_entropy > 3.0`, else Medium.

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

### 9.6 DNS Beaconing — query-cadence on (sensor, src, apex)

The gap this closes: a regular-cadence, low-entropy, low-diversity DNS
heartbeat to a single FQDN — the Cobalt-Strike DNS-C2 shape — slips
*both* other DNS-aware paths and the conn-level beacon detector. DNS
Tunneling (§9.2/§9.3) needs long high-entropy labels or high subdomain
diversity; this has neither. Beaconing (§2) is keyed on `conn.log` IP
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
  histogram-regularity and §2.2(d) duration helpers, scored against
  the per-sensor DNS capture window (the min/max timestamps seen by
  that sensor's dns.log files).

`score = clamp(100·(ts·0.5 + div·0.25 + cov·0.25), 1, 100)`; Critical
≥ 80, else High. DNS Beaconing carries the same structured triage
fields as §2 (sample size, mean/median interval, jitter), the
`ts/hist/dur` sub-scores, and the beacon chart TSData payload (the
timing-scatter chart in the Beacon Chart dock tab is populated the same
as conn and HTTP beacons). `ds_score` is intentionally left zero (DNS
has no payload-size axis — the diversity axis is detector-internal and
surfaced in the Detail string, not overloaded onto `ds_score`).

**Two scoping rules keep it from double-counting:**

- **Diversity gate.** At or above `DNSUniqueSubdomainMin` the apex is
  exfil-shaped — DNS Tunneling owns it, and Correlated Activity links
  the two if the cadence is also regular. DNS Beaconing does not fire.
- **NXDOMAIN exclusion.** NXDOMAIN responses are dropped from the
  cadence accumulation entirely: a beacon to a sinkholed/dead C2 is
  the NXDOMAIN-flood detector's finding (§9.1), and resolver-retry
  behaviour on failed lookups contaminates inter-arrival timing.

**Benign suppression.** Before scoring, an apex matching the built-in
CDN/cloud suffix allowlist (shared with the DGA augmentation, §2.5) or
the operator's curated allowlist is skipped — a constant-cadence
resolver/telemetry/CDN apex would otherwise aggregate every query
under one key and read as periodic.

**Calibration.** `DNSBeaconMinQueries` (Settings → DNS → *DNS Beacon
Min Queries*, default 20) is the sample-size floor — the minimum
queries to a `(src, apex)` before scoring, analogous to
`BeaconMinConnections`. The timing/spectral math reuses the global
beacon knobs; there are no DNS-beacon-specific scoring knobs.

**What it misses.** A beacon resolving via DoH is invisible to
`dns.log` entirely (no query records to time) — a separate JA3/SNI
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
itself, so a sensor whose Zeek build lacks the JA3 script simply
produces no `ja3` and this detector cannot fire — a real blind spot
worth checking during sensor onboarding). The hash is looked up in
`KnownBadJA3` (a static, curated `map[hash]→framework-label` in
`heuristics.go` — Cobalt Strike default, Empire, Trickbot, etc.; not
feed-driven). An exact match emits **Malicious JA3**, score **95**,
severity **Critical**, deduped per `(src, dst, ja3)`; the label rides
in the Detail string and the type carries risk weight 40 — the highest
tier, because an exact known-C2-stack match is about as unambiguous as
network-only evidence gets.

**What it misses.** Exact-match only: a single changed cipher,
extension, or TLS-version bump in the implant's stack yields a new hash
the curated list won't have, so JA3 is strong against *unmodified*
tooling and weak against *recompiled/tuned* tooling. Legitimate
applications that share a TLS library can collide on one benign JA3, so
the list is deliberately conservative (curated, not heuristic — a
mis-added benign hash would false-positive fleet-wide). GREASE
(randomized extension/cipher values, RFC 8701) and uTLS/refraction-style
*randomized* fingerprints defeat static JA3 entirely — that evasion is
the motivation for **JA4**, the structured successor (GREASE-robust,
human-readable, separates the TLS/SNI/ALPN components). Archer is
JA3-only today: there is no JA3S (server-side) or JA4 ingestion, and no
inline cross-reference between a beacon and other beacons sharing its
JA3 — that linkage is the planned §2c enhancement in `TODO.md`, not a
shipped feature.

### 10.2 Weak TLS

Categorical: TLS 1.0, TLS 1.1, SSLv3. Score 48, severity Low.

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

### 12.8 Notification suppression

TI Hit notifications still fire for new hits (any flavor), but `Host Risk
Score` (the per-host roll-up emitted by Phase 4) is excluded from the bell
on purpose — that's an aggregate, not a discrete event, and the underlying
network detections that pushed the host's score over the line have
already generated their own notifications. See section 14 for the
roll-up's scoring algorithm.

### 12.9 Two-tier watch cadence

Statistical detectors (Beaconing, HTTP analysis, DNS NXDOMAIN flood,
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

**Operator override — `WatchAlwaysFull`.** Settings → Watch Mode exposes
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

Per-record detectors are independent — Beaconing fires on `conn.log`,
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

- Beaconing(85) + DNS Tunneling(60) → 85 (Critical)
- Beaconing(70) + DNS Tunneling(60) + Data Exfil(50) + Strobe(40)
  → 70 + 5×2 = 80 (Critical, two extra types above minimum of 2)
- HTTP Beaconing(50) + Suspicious URL(45) → 50 (High)

**Historical context.** Like `aggregateRisk`, `correlateFindings`
unions this-run findings with the historical store snapshot via
`FindingsProvider` (NEW-67 pattern). A pair whose contributing
detections existed last run but didn't re-fire this run still
correlates as long as the historical findings are still in the store
— removes the "yesterday's DNS Tunneling + today's Beaconing don't
correlate because we only see today's findings" gap.

**Sensor resolution timing (v0.20.2).** `correlateFindings` partitions
pairs on `(Sensor, SrcIP, DstIP)` so multi-sensor overlapping captures
don't conflate findings emitted by different Quiver collectors
observing the same flow. The Fingerprint used by `SetFindings` for
merge/dedup is `(Type, SrcIP, DstIP, DstPort, Sensor)`. Sensor is
included because sensor-partitioned aggregate detectors (DNS Beaconing,
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
once a week, Beaconing fires daily) carries its slice as a record
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

**UI surface.** Each contributor row in the Findings table shows a
`+N corr` chip next to its Type. Clicking the chip pivots to the
`Correlated Activity` row so analysts can read the full
multi-detector context from one place. If the roll-up row isn't in
the currently-loaded findings (pagination, active filter), the chip
falls back to selecting the originating finding — its Detail field
lists every contributing ID and the analyst can navigate from there.

---

## 14. Composite Host Risk Score

**Where.** `internal/analysis/risk.go`.

After all per-finding analyzers have run, a final pass groups findings by
`SrcIP` and computes a composite score per host. Each detection type
contributes a weight:

| Detection type      | Weight |
|---------------------|--------|
| Cobalt Strike URI   | 40     |
| Malicious JA3       | 40     |
| C2 URI Pattern      | 38     |
| TI Hit (IP)         | 35     |
| TI Hit (Domain)     | 35     |
| TI Hit (Hash)       | 35     |
| Domain Fronting     | 32     |
| Beaconing           | 30     |
| HTTP Beaconing      | 28     |
| Data Exfiltration   | 25     |
| Lateral Movement    | 20     |
| Strobe              | 15     |
| Long Connection     | 10     |

(Each TI Hit flavor independently adds 35 — a host that triggered a
DNS-domain hit AND a file-hash hit gets +70. The legacy `Threat Intel
Hit` type from pre-v0.7.0 findings also weights 35 for backward
compatibility.)

For each host, the composite is

```
composite = min( 99, Σ weight(t) for t in distinct_detection_types )
```

Severity buckets:

- ≥ 75 → Critical
- ≥ 50 → High
- ≥ 25 → Medium
- < 25 → Low

The clamp at 99 means the score saturates rather than ever hitting 100, so
"100" is reserved for exact pattern matches (e.g., a known JA3) rather than
emergent composite signals. Note that *distinct* types contribute — two
Beaconing findings against the same host count once, not twice. This is
deliberate: the host-risk view answers "how many independent kinds of bad
behavior is this host exhibiting," not "how loud is each one."

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

Severity Critical (≥ 80). The detail line will read approximately:

```
Connections: 1287 | Mean interval: 60.3s | CV: 0.01 |
Score components: ts=1.00 ds=0.97 hist=0.92 dur=1.00
```

That same host might also pick up a `C2 Port` finding (port 443 is not on
that list, so probably not), and would feed a Host Risk Score of at least 30
(Beaconing weight). Add a `Malicious JA3` hit on top and the composite jumps
to 70 — High severity.

---

## 16. Retention vs. detection window — tuning the analyzer's reach

Every statistical detector (Beaconing, HTTP Beaconing, DNS NXDOMAIN flood,
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

With the default `BeaconMinConnections = 10`:

| Retention in /logs | Min detectable beacon period | Catches                                     |
|--------------------|------------------------------|---------------------------------------------|
| 5 days             | every 12h                    | Cobalt Strike, hourly C2, Empire / Sliver   |
| 14 days            | every ~33h                   | …plus daily APT cadence                     |
| 30 days            | every 3 days                 | …plus most slow APT beacons                 |
| 60 days            | every 6 days                 | …plus weekly-ish cadence                    |
| 90 days            | every 9 days                 | …reaching toward extreme patient adversaries |

Going slower than that requires either dropping `BeaconMinConnections`
(false positives explode — legitimate periodic traffic starts matching) or
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

**See also:** section 12.9 (two-tier watch cadence). Incremental TI ticks
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
| BeaconMinConnections     | 10      | TCP beacon eligibility (min 4)        |
| HTTPBeaconMinRequests    | 8       | HTTP beacon eligibility (min 4)       |
| DNSBeaconMinQueries      | 20      | DNS beacon eligibility (min 4)        |
| LongConnMinHours         | 1.0     | Long Connection trigger               |
| StrobeMinConnections     | 1000    | Strobe trigger                        |
| ExfilMinBytesMB          | 5.0     | Exfiltration size floor               |
| ExfilRatioThreshold      | 10.0    | Out/in ratio                          |
| OffHoursStart / End      | 22 / 6  | Off-hours window (UTC)                |
| OffHoursMinMB            | 1.0     | Off-Hours Transfer size floor         |
| DNSTunnelLabelLen        | 40      | DNS tunneling label length            |
| DNSTunnelEntropy         | 3.5     | DNS tunneling entropy bits            |
| DNSTunnelMinDepth        | 5       | DNS tunneling dot count               |
| DNSNXDomainThreshold     | 200     | NXDOMAIN flood trigger                |
| DNSUniqueSubdomainMin    | 50      | Subdomain diversity trigger           |

If you want to tune for a noisier or quieter environment, those are the dials.
The math is unchanged.
