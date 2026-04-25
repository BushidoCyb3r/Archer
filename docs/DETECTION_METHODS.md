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

**Combined.** `ts_score = (bowley_score + mad_score) / 2`, rounded to 3
decimals. Both halves agreeing that the intervals are tightly clustered is what
we want.

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
Score components: ts=0.97 ds=0.95 hist=0.91 dur=1.00
```

- **CV** here is the coefficient of variation of the *intervals* themselves
  (not the bucket counts), included as an at-a-glance regularity number.
  `CV = stddev(intervals) / mean(intervals)`. Below ~0.1 is suspiciously
  regular; above ~1.0 is human-driven.
- The four sub-scores tell you which axis dominated.

### 2.4 What this catches and what it misses

Catches: fixed-interval implants (Cobalt Strike default 60s, Empire 5min,
custom RATs), long-running tunnels with constant-size keepalives.

Misses (intentionally, to limit false positives): jittered beacons with
intentionally randomized intervals — those degrade the timing score. The
bytes axis and histogram axis can still flag them, but the score will be
lower. This is a deliberate trade-off: Archer biases toward precision over
recall here.

---

## 3. HTTP Beaconing

**Where.** `internal/analysis/http_analysis.go`.

Same four-axis scoring as TCP beaconing, but the grouping key is
`(src, dst, host, uri)` rather than just `(src, dst)`. The minimum connection
count is `HTTPBeaconMinRequests` (default 8). Otherwise the math is identical:
Bowley + MAD on intervals, Bowley + MAD on `orig_ip_bytes`, the same 24-bucket
histogram, and the same persistence test.

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
score = clamp( min(55 + 6·entropy, 88), 1, 95 )
severity = High
```

### 9.3 DNS tunneling — subdomain diversity

A second-pass aggregate. For each `(src, apex)` we collect the set of unique
subdomains. If `|set| ≥ DNSUniqueSubdomainMin` (default 50):

- Sample up to 200 subdomains, compute Shannon entropy of each, average.
- `score = clamp( min(55 + 6·avg_entropy, 90), 1, 95 )`
- Severity is High if `avg_entropy > 3.0`, else Medium.

### 9.4 Suspicious TLD

Categorical match against a curated list of free / abused TLDs (`.tk`, `.ml`,
`.gq`, `.cf`, etc.). Score 52, severity Medium. Deduped per `(src, apex)`.

### 9.5 DoH Bypass

A connection on port 443 to an IP in `DoHIPs` (Cloudflare 1.1.1.1, Google
8.8.8.8, Quad9, NextDNS, etc.) is DNS-over-HTTPS, which evades on-prem DNS
logging. Score 62, severity Medium.

---

## 10. SSL/TLS Detections

**Where.** `internal/analysis/ssl.go`.

### 10.1 Malicious JA3

JA3 is a fingerprint of a TLS client's `ClientHello` — its supported cipher
suites, extensions, elliptic curves, and EC point formats hashed with MD5.
Implants tend to use a fixed TLS stack and therefore produce a stable JA3
hash. Archer maintains a list of known-bad JA3 hashes (Cobalt Strike default,
Empire, Trickbot, etc.). Match → score 95, severity Critical.

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

**Where.** `internal/analysis/ti.go`.

In Phase 0 of analysis, Archer pre-fetches Feodo Tracker (botnet C2 IPs) and
URLhaus (malware distribution IPs and hosts). During the conn pass, any
connection whose `dst` is in those feeds becomes a `Threat Intel Hit` finding.
Pure list match — no scoring math, just a high-confidence severity assigned by
the feed's own classification.

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
| Threat Intel Hit    | 35     |
| Domain Fronting     | 32     |
| Beaconing           | 30     |
| HTTP Beaconing      | 28     |
| Data Exfiltration   | 25     |
| Lateral Movement    | 20     |
| Strobe              | 15     |
| Long Connection     | 10     |

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

## 16. What Archer is *not* doing

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

---

## 17. Threshold reference

All thresholds live in `internal/config/config.go` and can be overridden at
runtime. Defaults:

| Setting                  | Default | Used in                              |
|--------------------------|---------|--------------------------------------|
| BeaconMinConnections     | 10      | TCP beacon eligibility                |
| HTTPBeaconMinRequests    | 8       | HTTP beacon eligibility               |
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
