# ANALYST_PLAYBOOK.md

How to hunt real-world C2 beacons with Archer. This is the
operational doc — what to click, what to read, what to ignore,
what to escalate, what to write in the note.

This doc is the counterpart to `DETECTION_METHODS.md` (the math
behind each finding type) and `OPERATIONS.md` (how the deployment
runs). When the question is *"the detector fired — now what?"*,
the answer is here.

It assumes you already know what Zeek is, what C2 is, and that
"beacon" means callback-on-a-schedule. It does not assume you
already know how attackers tune their beacons in 2026 — that's
covered below.

The current edition focuses on the **Beaconing** detection family
(Archer's headline detection — see CLAUDE.md). The same shape
applies to other detector families; per-family triage sections
for HTTP Beacon, Suspicious Certificate, DNS Tunneling, Data
Exfiltration, Off-Hours Transfer, and Long Connection will land
in this file as they're written.

---

## Table of contents

1. [The triage question](#the-triage-question)
2. [What a modern C2 beacon actually looks like](#what-a-modern-c2-beacon-actually-looks-like)
3. [The fast-path filter — 90% of findings resolve here](#the-fast-path-filter--90-of-findings-resolve-here)
4. [Sitting down with the findings table](#sitting-down-with-the-findings-table)
5. [Anatomy of a beacon finding](#anatomy-of-a-beacon-finding)
6. [Indicators that lean malicious](#indicators-that-lean-malicious)
7. [Indicators that lean benign](#indicators-that-lean-benign)
8. [The eight-question triage checklist](#the-eight-question-triage-checklist)
9. [Worked examples](#worked-examples)
10. [Pivoting from a beacon](#pivoting-from-a-beacon)
11. [Benign-pattern catalog and the suppress-vs-allowlist rule](#benign-pattern-catalog-and-the-suppress-vs-allowlist-rule)
12. [Note discipline](#note-discipline)
13. [Anti-patterns — things that look like good triage but aren't](#anti-patterns--things-that-look-like-good-triage-but-arent)
14. [Detection blind spots — what Archer cannot see](#detection-blind-spots--what-archer-cannot-see)
15. [When you're stuck](#when-youre-stuck)
16. [Daily / weekly / monthly rhythm](#daily--weekly--monthly-rhythm)
17. [Escalation criteria](#escalation-criteria)
18. [Glossary — Archer-specific terms](#glossary--archer-specific-terms)

---

## The triage question

Archer's beacon score is **"does this traffic look like a
beacon?"** It intentionally does not answer **"is this beacon
malicious?"** That second question is what you bring to the
table — context the detector doesn't have: which host this is,
where it sits on the network, what business function it serves,
what time it normally goes quiet.

The score tells you the *shape* of the traffic is beacon-like.
Your job is to decide whether the *destination* and *context* are.

**A high-scoring beacon to a known-good destination is benign.
A medium-scoring beacon to an unknown destination from a host
that has no business reaching the internet is the kind of
finding that ends careers (theirs, not yours).**

Triage well by remembering that score is one input, not the
answer.

---

## What a modern C2 beacon actually looks like

Forget the textbook example of "60-second intervals over port
8080." Real C2 in 2025-2026 is tuned to blend in. The five
properties to internalise:

1. **Sleep intervals are long.** Default sleep for the major
   commodity frameworks (Cobalt Strike, Sliver, Mythic, Havoc,
   Brute Ratel) is configurable; mature operators set it to 1-4
   hours, sometimes longer for the persistence stage. The
   "every 60 seconds" image is a training-stage default that
   mature operators never ship to a target. You'll still see
   defaults in commodity malware and in lazy red-team
   engagements — flag them — but don't expect them as the rule.

2. **Jitter is the new normal.** Sleep + jitter (±30-50%)
   randomises the interval enough to defeat naive
   "same-millisecond-every-time" detection. But the underlying
   *distribution* is still tight — coefficient of variation
   (CoV) stays low even with jitter. Human-driven traffic has
   much wider CoV. **This is the signal Archer's beacon
   detector measures.** Don't expect to see "exactly 60s, 60s,
   60s" — expect to see "3712s, 4127s, 3589s, 3998s" over a
   24-hour window with a tight CoV.

3. **HTTPS is the transport.** Anything other than HTTPS on
   443 is a tell in itself. Modern C2 rides HTTPS because TLS
   makes payload inspection moot and 443 outbound is allowed
   by every firewall on Earth. If you see a beacon-shaped flow
   on a non-standard port, the operator is either careless or
   it's commodity malware — both worth chasing.

4. **Destination looks legitimate.** Cloudflare, AWS, Azure,
   GitHub, Discord, Telegram, Slack webhooks, Notion, Dropbox.
   "Domain hiding" (the post-2018 successor to domain
   fronting) routes through CDN or serverless infrastructure
   whose certificates name a legitimate company. The IP is in
   a legitimate cloud range. Whois says nothing useful. **Do
   not dismiss a beacon because the destination "looks
   normal."** A clean reputation is what the operator paid
   for.

5. **Connection counts are low per beacon.** A 1-hour sleep
   over a 24-hour window produces ~24 connections. A 4-hour
   sleep produces ~6. Archer's default `BeaconMinConnections`
   is sized to catch this, but a quiet beacon on the edge of
   the window can produce a low-confidence finding the first
   day and a high-confidence one the second day as the sample
   grows. **Don't dismiss a borderline finding too early —
   give it another day.**

What you will *not* commonly see in 2026:

- Periodic beacons on weird ports (port 4444, port 6667, etc.)
  — that's commodity malware, not the threat actor you should
  fear.
- Plaintext HTTP C2 — extinct in serious tradecraft. If you
  see it, it's either commodity malware or pre-positioned
  scripts left behind by a previous incident.
- Single-IP destinations — most C2 rotates through a CDN or
  uses multiple destinations from the same operator. Same
  *source* fanning out to multiple beacon-shaped destinations
  is itself a finding shape; see "Pivoting from a beacon"
  below.

---

## The fast-path filter — 90% of findings resolve here

Before you do any deep analysis, run the destination through
the fast filter below. Most beacon findings on a healthy
network resolve in under thirty seconds this way.

| Destination shape | Almost always | Action |
|---|---|---|
| `pool.ntp.org`, `*.ntp.org`, port 123 | NTP | suppress destination |
| `time.windows.com`, `time.apple.com`, port 123 | OS time sync | suppress |
| `*.update.microsoft.com`, `*.windowsupdate.com` | WSUS / Windows Update | suppress |
| `*.apple.com`, `courier.push.apple.com`, port 5223 | APNs | suppress |
| `clients2.google.com`, `clients4.google.com` | Chrome update + safe-browsing | suppress |
| `*.slack.com`, `*.zoom.us`, `*.teams.microsoft.com`, port 443 | SaaS heartbeat | suppress |
| `mtalk.google.com`, `fcm.googleapis.com` | FCM push | suppress |
| `*.snmp-trap.<your domain>` | internal monitoring | suppress |
| `mdns.local`, multicast IPs (224.0.0.0/4) | service discovery | suppress |
| Your own DNS resolver (8.8.8.8, 1.1.1.1, internal) | DNS health | suppress destination |

"Suppress" means: add the destination to the allowlist with a
clear comment (`# WSUS — Windows Update`). The detector still
runs against those flows; it just doesn't surface them. Future
analysts will read your comment and understand why.

The fast filter is the difference between a triage queue you
can actually work and one you abandon at finding number forty.

---

## Sitting down with the findings table

Open Archer. You're on the Findings tab. Default sort is score
descending, severity-coloured rows.

**Step 1 — Scan severity, ignore score-as-priority.** Severity
buckets the scores into Critical / High / Medium / Low. Treat
severity as the priority signal; score is for tie-breaking
within a severity. A Critical at 87 and a Critical at 92 both
deserve immediate attention; a High at 89 doesn't beat a
Critical at 82 just because the number is bigger.

**Step 2 — Filter by Type.** The Type filter is your first
move. For beacon hunting specifically:

- `Beacon` — raw Zeek conn-derived beacons (any protocol).
- `HTTP Beacon` — same shape but HTTP-aware (correlates request
  cadence). Often *more* trustworthy because HTTP context
  (UA, method, URI shape) feeds into the score.
- `TI Hit (IP)` / `TI Hit (Domain)` / `TI Hit (Hash)` — TI feed
  matches. Often the bridge between a low-confidence beacon
  and "yes that's malicious."
- `Long Connection` — beacon-shaped behaviour where one
  connection just stays open instead of reconnecting.
  Modern C2 frameworks support this mode; it evades
  connection-count detection but trips long-conn detection.
- `Strobe` — many fast connections to one destination, the
  opposite shape from beacons. Some frameworks strobe during
  the initial handshake or staging phase before settling into
  beacon cadence.

**Step 3 — Open the first finding.** Click the row. The detail
pane shows:

- The score breakdown (Time-Stats / Data-Stats / Histogram /
  Duration sub-scores).
- The raw conn samples (pivot via the **Source Records** button
  in the detail-pane action footer).
- Cross-references (other findings touching the same IPs, TI
  cross-annotations).
- Notes and status history.

Two diagnostic charts open from the action footer:

- **Beacon Chart** — three views (Timeline / Interval
  histogram / Bytes) of the within-window cadence. Timeline
  supports click-drag brush-select to zoom into a slice;
  right-click or **Reset zoom** returns to auto-fit. PNG /
  JPEG export per view.
- **Score Evolution** (its own dock tab next to TI Results,
  keyboard `4`, gated on Beaconing / HTTP Beaconing) — 30-day
  trajectory of the composite score plus the four sub-axes,
  updated once per UTC day on the first full pass.

**Step 4 — Read the chart, not the score.** The cadence chart
is the most diagnostic thing in the UI. You're looking for:

- **Tight vertical spacing of dots** = low jitter = beacon.
- **Even spacing across the time axis** = sustained cadence,
  not bursty human activity.
- **Continuation past business hours** = not a user.
- **Dot count high enough to trust the math** = at least
  `BeaconMinConnections` (default 10). The chart shows this.

A score of 75 with a *visually clean* beacon pattern is more
trustworthy than a score of 88 with a chart that looks
clumpy. The detector is calibrated for noise floor; your eyes
are calibrated for adversary tradecraft. Use both.

**Step 5 — Decide one of five things:**

Archer's finding status enum has four values: `open` (default,
empty string), `acknowledged`, `escalated`, and `dismissed`
(v0.18.0). There is no distinct "false_positive" status —
confirmed-benign findings are still handled by acknowledging
with a clear note *plus* (when applicable) adding the
destination to the allowlist or a suppression so the same
finding doesn't recur. Dismissed is **not** the false-positive
button; it's a lightweight reversible view-state bucket that
says "hide this from my default tabs without committing to the
heavier Acknowledge semantic." Dismissed findings still
contribute to Host Risk Score — Dismiss is view-only, not a
risk-scoring verdict.

| Decision | When | What you do |
|---|---|---|
| **Escalate** | Beacon pattern + suspicious destination + can't explain it | Click Escalate, fill in the IPs and services for TI pivot, write a one-line note (date / what you saw / why escalating). Status becomes `escalated`. |
| **Acknowledge + suppress** | You've matched it to a known software pattern (see FP catalog below). Add the destination to the allowlist or a suppression so the finding stops recurring. | Status → `acknowledged`. Note records *what software / what pattern / why*. Then add the destination to the allowlist (or create a suppression). Future analyses won't surface this finding again, but the audit log preserves who added the curation entry and when. |
| **Acknowledge** | You've looked, decided it's not malicious, but don't want to add a permanent curation entry (because the destination is contextually fine *this time* but might warrant re-investigation if the pattern changes). | Status → `acknowledged`. Note records the rationale and the re-check condition. |
| **Dismiss** | You looked, this isn't worth keeping in your default view, but you don't want to commit to Acknowledge's "I've reviewed and judged this" semantic. Use cases: noise findings during a high-volume incident triage pass; a beacon you'll come back to next week; a bulk-cleanup of a campaign that's clearly known-low-value. | Status → `dismissed`. Hidden from every standard tab; visible in the dedicated Dismissed tab (Findings + Campaigns sub-tabs). Reversible — right-click → Un-dismiss. **Right-click a Campaigns row → "Dismiss campaign"** to bulk-dismiss every open finding in that campaign with a shared note. Doesn't affect HRS; use suppression / allowlist if you want a detection to stop influencing risk. |
| **Leave open** | You need to come back to it — wait another day for more data, ask a colleague, check a logfile | No status change. Add a note saying what you're waiting on. |

The status transitions land in the audit log (v0.14.0) so a
later reviewer can reconstruct the decision trail.

**Dismiss vs Acknowledge in one sentence:** Acknowledge says
"I've judged this finding and made a call"; Dismiss says "I
don't want to see this in my default view right now." Reach for
Dismiss when triaging volume; reach for Acknowledge + suppress
when triaging a benign pattern; reach for Escalate when the
beacon doesn't fit either bucket.

---

## Anatomy of a beacon finding

When you open the detail pane, every visible field tells you
something. Here's what to look at and why.

**Source IP.** Internal host. *This is the asset you care
about.* The finding is "this host is beaconing." Pivot to
Hosts tab to see its overall risk roll-up; high host-risk
score means this isn't the only suspicious thing this host
has been doing.

**Destination IP + Domain.** External callback. Domain comes
from DNS resolution observed in the same time window. **An
IP with no associated domain is suspicious in 2026** — modern
C2 uses domains because they're easier to rotate and they
hide CDN-fronted infrastructure. A no-domain destination
means either the malware uses a hardcoded IP (commodity,
older) or it uses DoH and Archer didn't see the
resolution.

**Connection count.** How many flows the detector saw to this
pair in the analysis window. Below `BeaconMinConnections`
(10 default) the finding doesn't fire; just above the
threshold means borderline confidence, deep above means
strong sample.

**Score breakdown (Time-Stats / Data-Stats / Histogram /
Duration).** Each is `[0, 1]`. Patterns to recognise:

- **Time-Stats high (>0.8)**, others mixed: classic
  short-sleep beacon with regular cadence. Time-Stats is the
  CoV signal.
- **Histogram high, Time-Stats mid**: cadence is detectable
  via inter-arrival distribution even when raw CoV is
  inflated by jitter. Modern tradecraft.
- **Duration high (>0.8)**: every connection lives roughly
  the same length of time. A regular cadence on duration is
  even rarer in legitimate software than a cadence on
  inter-arrival — it's a strong tell.
- **Data-Stats high**: byte counts per beacon are tightly
  clustered. A heartbeat with no command-and-response shows
  identical byte counts; a beacon delivering tasks shows two
  modes (heartbeat-sized and task-response-sized) which
  Data-Stats picks up via bimodality.

See DETECTION_METHODS.md §2.2 for the formulas; this
playbook tells you what the patterns *mean*.

**Cross-references.** If the same source IP shows up in other
findings (DNS tunneling, suspicious user-agent, TI hit), or
the same destination IP appears in another host's beacon —
the cross-reference panel lists them. **Two findings sharing
a source or destination are 10× more interesting than two
unrelated findings.** This is where the hunt usually breaks
open.

**Notes.** Previous analyst observations on this finding (if
it survived across analysis runs via fingerprint merge). Read
them. If someone's already acknowledged this exact pattern
last quarter and the note explains why, your job is over.

**Score evolution chart.** Beaconing / HTTP Beaconing findings
get a dedicated **Score Evolution** dock tab (next to TI
Results, keyboard `4`) showing up to 30 daily snapshots of
the composite score plus the four sub-axes (ts, ds, hist,
dur). Promoted to its own tab at v0.18.4 — previously a
sparkline inside the Detail pane. The chart updates once per
UTC day, on the first full pass — so it's a *trend* view, not
a real-time stream. The tab button only renders when the
selected finding's type is Beaconing or HTTP Beaconing.

Read it for trajectory rather than absolute value:

- **Flat high score** — stable, persistent channel. A
  long-running C2 implant looks like this; so does a
  long-running legitimate health probe. Use the other
  indicators to separate.
- **Climbing ts with stable ds** — the beacon is becoming
  more regular. An initial-jitter implant settling into its
  rhythm, or an operator-side cleanup of legitimate scheduled
  job timing.
- **Climbing dur with flat ts/ds** — the channel is staying
  alive longer each day; the implant's session keepalive is
  succeeding.
- **Sudden drop after weeks of activity** — the beacon went
  silent. Either remediation (good) or the implant rotated
  destinations (bad — cross-reference the Correlated Activity
  row for the same source).
- **Score moving up across days, no underlying detector
  change** — the DGA augmentation may have fired today on a
  destination that previously didn't trigger. Check the
  Detail line for the diagnostic tag.

The chart is the right view for "how is this beacon changing
over weeks." For intra-day timing detail (interval distribution,
byte distribution), use the Beacon Chart dialog instead.

**Correlation chip.** If this finding's `(src, dst)` pair is
also carrying findings from N+ other detector types, the row
shows a `+N corr` chip. Click it to pivot to the Correlated
Activity row, which lists every sibling finding. This is the
fastest way to spot kill-chain progression — a Beaconing
finding plus a DNS Tunneling finding plus a Suspicious File
Download on the same pair is a much higher-signal story than
any one of them alone.

---

## Indicators that lean malicious

The destination didn't fast-filter out. Now you start looking
for positive signals. Each of these on its own is
suspicious-not-conclusive; two or three together is escalate
territory.

### 1. The destination has no historical reputation

The IP isn't in any threat intel feed and has no business
presence:

- WHOIS shows a recently registered domain (under 30 days is
  a classic indicator — most legitimate services have years
  of history).
- Certificate is from Let's Encrypt or another free CA, issued
  in the past few days. Legitimate enterprises don't typically
  rotate daily.
- Reverse DNS resolves to nothing or to a hosting provider's
  generic template (`ec2-xx-xx.compute.amazonaws.com`).
- The destination has no public-facing web page or its page is
  empty / contains only a generic NGINX welcome.

A malware operator stands up infrastructure right before a
campaign. A legitimate service has been around long enough to
have a digital footprint.

### 2. The protocol/port combination is unusual

HTTPS is supposed to be on 443. When you see a high-scoring
beacon to TCP/8443, TCP/4443, TCP/9443, TCP/2087, TCP/2096 —
those are non-default HTTPS ports often used to bypass naive
proxy filtering. The traffic still presents as TLS but the
port is the tell.

Pay particular attention to:
- HTTPS on a non-443 port from a workstation (servers may
  legitimately speak on alt ports; user endpoints almost never
  should)
- Plain HTTP on non-80 ports
- Anything on the **C2-port watchlist** Archer already flags
  (`KnownC2Ports` in `internal/model/finding.go` — Metasploit
  4444, Cobalt Strike defaults, etc.)

### 3. The source host doesn't normally reach the internet

This is the single highest-value contextual signal Archer
cannot give you. A beacon from a domain controller, a SCADA
endpoint, a printer, an IoT device, or a server whose role is
internal-only is *extremely* high-signal. These hosts shouldn't
be initiating outbound traffic at all; if one is, ask why.

Conversely, a beacon from a developer's laptop to AWS or GCP
is much more likely to be a legitimate tool than a compromise
— but if the *destination* doesn't match any AWS region or
known service, raise your eyebrow.

### 4. The interval is suspiciously human

Malware authors are conscious of the timing-regularity
detection that tools like Archer use. Two patterns to watch:

- **Sub-minute beacons** (5-30 second intervals). Most
  legitimate services check in every few minutes or longer;
  sub-minute is C2-implant territory.
- **Beacons that match common implant defaults**. Cobalt
  Strike's default sleep is 60 seconds. Sliver's default is
  60 seconds with 30% jitter. Metasploit Meterpreter's
  reverse_https default poll is 5 seconds. When the detail
  line shows `mean ≈ 60s` and you haven't identified the
  destination as a known service, search the destination IP
  against Cobalt Strike team-server scan databases (Censys,
  Shodan).

### 5. The payload size is constant and small

The detail line shows `ds_mean ≈ 40 bytes, ds_cv = 0.0`.
That's a heartbeat with no payload — exactly what a C2
implant sends when it has no commands to retrieve. Compare:

- Legitimate beacon traffic usually has variable payload
  (status data, telemetry batches) — `ds_cv` in the 0.3-1.0
  range.
- Constant-tiny payload is the signature of "are you still
  there?" polling.

### 6. There's a coincident file download or HTTP POST

Look at the same `(src, dst)` pair in `http.log` or
`files.log` around the beacon window. A beacon that
occasionally pulls a file or POSTs a large body is "implant
fetched a task" — that's the shape of a C2 channel, not a
benign heartbeat.

Use the **Source Records** button on the finding (backed by
`GET /api/findings/{id}/raw`) to correlate quickly. The pivot
returns the actual log records for matching pairs in the same
time window.

### 7. The certificate is anomalous

For HTTPS beacons, pull the `x509` data for the destination:

- **Self-signed** (subject == issuer) is high-signal on any
  beacon destination that isn't an internal service.
- **Default subject strings** ("CN=localhost", "Internet
  Widgits") are bigger red flags — they mean the operator
  didn't even bother to customize.
- **Very short validity windows** (a few days) suggest
  disposable infrastructure.
- **Very long validity windows** (10+ years) on a destination
  that claims to be a real service suggest a self-issued CA
  the operator wants to keep using.

Archer's `Suspicious Certificate` detection fires on all of
these; the related cross-noting attaches to the beacon finding
if both fired in the same run.

### 8. The destination is in a threat intel feed

The simplest signal and the rarest. If the destination is in
your MISP, OTX, AbuseIPDB, ThreatFox, or other feed match,
Archer cross-annotates the beacon finding with a TI
Enrichment note. You should still verify (feeds have false
positives — the lowest-quality feeds list every cloud
provider's IP space). But the bar for escalate drops
considerably.

### 9. The destination hostname looks DGA-shaped

Archer's DGA augmentation already flagged this — the finding's
score is bumped +15 and severity is one step higher than the
baseline beacon math would have produced. The Detail line
carries the diagnostic tag:

```
DGA-suspect destination: kx9j3qm2pflw.com (SLD=kx9j3qm2pflw, entropy=3.58, bigram=-5.55)
```

When you see this tag, the destination's registrable domain has
both high character entropy (close to uniform — typical of
algorithmic generation) and bigram statistics that don't match
English. Built-in CDN allowlist already exempts cloudfront /
azure / akamai / fastly / etc., so the tag is *only* present on
destinations that survived that filter. Treat it as confirming
evidence on top of the timing-regularity case the beacon
detector already made — DGA on its own would be too noisy, but
DGA + timing = high-confidence C2 infrastructure.

False positives that survive the CDN allowlist:
- Hash-derived storage URLs from less-common providers (some
  S3-compatible hosts; smaller CDN networks).
- Email-tracking pixel hosts (one-off-domain-per-campaign style).
- Internal corporate test domains using generated names.

For these, add the specific hostname to the operator allowlist
(Settings → Allowlist). Don't bump the DGA thresholds globally —
the SLD-level entropy/bigram defaults are tuned to put English
words clearly above the floor.

---

## Indicators that lean benign

Inverse of the malicious list. None of these *prove* benign,
but each reduces the probability.

- **The destination is a major cloud provider's well-known
  service IP** (AWS S3 endpoints, GCP storage, Azure blob).
  The hosts are noisy for benign reasons (SDK polling, app
  telemetry, update checks).
- **The user-agent is browser-shaped** with a real version
  string matching the OS. C2 implants often have telltale UA
  strings or no UA at all.
- **The certificate is from a major CA** (DigiCert, Sectigo,
  GlobalSign) with a long validity history and a verified
  `Subject` matching the destination domain.
- **The beacon stops cleanly when the user logs off** (low
  score on `dur_score`'s end-of-capture check — see
  DETECTION_METHODS.md §2.2(d)). Malware persists; user-driven
  activity follows shifts.
- **The destination resolves via a well-known consumer DNS
  provider's domain hierarchy** matching the parent
  organization (telemetry.example.com when the org owns
  example.com).
- **There's a clear coincident user action** — a beacon that
  starts the moment a user opens Slack and stops when they
  quit it is Slack.
- **Multiple internal hosts beacon to the same destination on
  the same cadence**. Mass-distributed corporate software
  (security agent, EDR, MDM) talks home from every endpoint
  with similar timing. Malware would too, but malware
  typically infects unevenly; mass-uniformity points at an
  installed-on-image agent.

---

## The eight-question triage checklist

Run these in order. The first "yes" that pushes you past your
escalation threshold is the answer; you do not need to answer
all eight on every finding.

1. **Is the destination in the fast-path filter?** Stop,
   suppress, document.

2. **Is the destination in any threat intel feed?** Check the
   cross-notes on the finding. If yes, verify with a second
   source, then escalate.

3. **Does the source host belong to a "should never beacon"
   class?** DC, SCADA, IoT, printer, internal-only server,
   kiosk → escalate regardless of destination.

4. **Is the interval under 60 seconds?** Sub-minute is
   presumptively malicious until proven otherwise. Investigate
   the destination in depth.

5. **Is the destination's certificate / DNS / WHOIS reputation
   normal?** Anomalous cert, NXDOMAIN, or recently-registered
   domain → escalate or deep-investigate.

6. **Is the payload pattern heartbeat-shaped?** Tiny constant
   payload + perfect timing → escalate.

7. **Is there coincident HTTP POST or file download from the
   same pair?** Run the raw-log pivot. If yes, escalate.

8. **Does the beacon disappear when an obvious user action
   ends?** Probably benign (with note).

If you finish all eight and none triggered escalate but the
finding still feels off, write the note describing what feels
off and acknowledge the finding *without* adding it to the
allowlist or a suppression — a future analysis run will surface
the same destination again, and a future analyst seeing the same
destination next week with one more red flag attached has the
trail to pick up.

---

## Worked examples

### Example A — the textbook benign

**Finding**: Beaconing, score 78, src `10.4.1.50` → dst
`17.250.x.y:5223`, mean interval 32 seconds, `ds_cv 0.1`,
`dur_score 0.95`.

**Triage**:
- Destination IP resolves to `*.push.apple.com` — APNs.
- Source is a corporate-managed macOS laptop.
- Port 5223 is the canonical APNs port.
- Coincident `notice.log` rows show no anomaly.

**Action**: suppress destination CIDR (Apple publishes APNs
ranges). Note: "APNs push channel; verified `17.249.0.0/16` +
`17.250.0.0/16` ranges per Apple support article HT203609."

### Example B — the textbook malicious

**Finding**: Beaconing, score 81, src `10.4.1.7` → dst
`185.x.y.z:8443`, mean interval 60 seconds, `ds_cv 0.0`,
`dur_score 0.99`.

**Triage**:
- Destination IP has no rDNS.
- WHOIS shows the hosting provider; IP allocated to a
  customer two weeks ago.
- Port 8443 (non-default HTTPS).
- Certificate is self-signed, CN="Cobalt Strike", issued
  yesterday. (You won't get this lucky often, but Cobalt
  Strike teamserver defaults *are* this lazy in the wild.)
- Source `10.4.1.7` is a finance workstation per asset
  inventory.
- `ds_mean = 38 bytes` — heartbeat.
- Interval exactly 60 seconds (CS default sleep).

**Action**: escalate to IR immediately. Note: "Cobalt Strike
beacon to `185.x.y.z:8443`. Default sleep, self-signed
CN=Cobalt Strike, finance workstation. Isolating `10.4.1.7` —
see ticket #2026-0312."

### Example C — the realistic ambiguous

**Finding**: Beaconing, score 62, src `10.4.1.92` → dst
`52.x.y.z:443`, mean interval 5 minutes, `ds_cv 0.4`,
`dur_score 0.6`.

**Triage**:
- Destination resolves to `*.amazonaws.com`. WHOIS is AWS
  US-East-1.
- No TI feed match.
- Workstation in the developer subnet.
- Cert valid, signed by Amazon CA.
- Coincident HTTP traffic shows S3 GET requests.

**Action**: acknowledge with note. Note: "Developer
workstation beaconing to S3 bucket; matches the cadence of
the internal CI/CD tool poller. No anomalous payloads or
methods. Re-check if the dst IP changes pattern."

You acknowledge this rather than adding a permanent allowlist
entry. There's nothing wrong with the detection — the destination
is contextually fine *this time*, and if the cadence or
destination shifts you want to see it again. A persistent
allowlist for "this S3 bucket" would silence a real future
finding that happens to share the destination.

### Example D — the slow-burn

**Finding**: Beaconing, score 51, src `10.4.1.7` → dst
`91.x.y.z:443`, mean interval 24 hours, `ds_cv 0.3`,
`dur_score 0.4`.

**Triage**:
- Daily-cadence beacon (24h ± a few minutes).
- Destination IP has no rDNS, WHOIS is offshore hoster.
- No TI feed match.
- Finance workstation again.
- One coincident HTTP POST with 14 KB body per beacon.

The score is medium because Archer's interval math is
sensitive to exact daily timing — the variance is small as a
fraction of 24 hours but large in absolute seconds. The
destination is the tell.

**Action**: escalate. Slow-burn data exfil is a real pattern.
Note: "24h cadence to no-reputation IP from finance
workstation, daily 14KB POST. Treating as possible
low-and-slow exfil pending IR review."

---

## Pivoting from a beacon

A single beacon-shaped finding is the start of a hunt, not
the end. Standard pivots in Archer:

**Pivot 1: same source, other findings.** In the detail pane,
click the source IP. The findings table re-filters to "every
finding touching this source." If you see Beacon + DNS
Tunneling + Suspicious URI from the same host — that's the
intrusion chain, not a coincidence.

**Pivot 2: same destination, other sources.** Click the
destination IP. Findings table shows "every internal source
that's been to this destination." Multiple sources beaconing
to the same external IP/domain = malware spread across the
estate. This is the lateral-movement-via-shared-C2 signal.

**Pivot 3: TI cross-annotation.** If the destination has a TI
hit (IP, domain, or hash), the related findings get a
cross-annotation note pointing at the TI evidence. This
upgrades a medium-confidence beacon to "yes that's malicious
because feed X flagged this destination on date Y." Read the
TI hit's evidence — what feed, what type, when first seen —
to assess credibility.

**Pivot 4: raw log pivot.** Click **Source Records** on the
finding (action-footer button, or right-click → Source
Records). Shows the raw Zeek records (conn.log, http.log,
ssl.log, x509.log) the finding was built from. Inspect:

- The TLS SNI on each connection. Same SNI repeated = single
  destination behind a CDN. SNI varying within a beacon =
  CDN rotation by the operator.
- HTTP user-agent strings. Old-fashioned malware uses
  hardcoded UAs that look slightly off; modern malware
  copies a real browser's UA from a real user's traffic.
- Bytes-per-connection histogram. Heartbeats and
  task-responses cluster differently; if every flow has
  `bytes_in=72` and `bytes_out=128` that's a clean heartbeat.

**Pivot 5: host risk roll-up.** Hosts tab → click the
source. Shows every detection family that's contributed to
this host's risk score. A host with Beacon + Long Connection
+ Off-Hours Transfer + a TI hit isn't a noisy detector —
it's an incident.

---

## Benign-pattern catalog and the suppress-vs-allowlist rule

The cost of a missed FP is hours of analyst time. The cost
of a false-FP'd actual beacon is much higher. Be careful
with suppression.

The persistent FP sources in most environments — each with
the *confirming evidence* you need to verify before
suppressing:

**1. NTP / chrony.** UDP 123 outbound to pool.ntp.org IPs.
Tight cadence, low byte counts, low jitter. Confirm: dst
port 123, dst IP belongs to an NTP pool. Always allowlist
your NTP pool.

**2. OCSP / CRL fetches.** HTTPS to certificate-authority
infrastructure (DigiCert, Let's Encrypt, Sectigo) on a
roughly-regular cadence as certificates check revocation
status. Confirm: destination IP resolves to a CA's OCSP
responder; per-flow bytes are tiny. Almost always safe to
suppress.

**3. Software update checkers.** Microsoft Update, Adobe
update, browser auto-updates, antivirus signature pulls,
agent heartbeats (Datadog, Splunk Forwarder, CrowdStrike,
SentinelOne). These can be very beacon-shaped because
they're literally scheduled callbacks. Confirm: destination
is the vendor's official update infrastructure (Microsoft
IP space, Adobe-owned, etc.) AND the source host has that
software installed AND the pattern matches your fleet's
update schedule. **Do not suppress at the source level** —
that hides every beacon from that host, including real
ones. Suppress at the destination level:
`windowsupdate.com`, `clients2.google.com`, etc.

**4. EDR / agent heartbeats.** Your own EDR. Look at this
twice — if you don't recognise the destination as your EDR's
collection endpoint, find out *what* agent is talking to it
before suppressing. EDR vendors publish their IP ranges;
verify before adding to allowlist.

**5. M365 / Google Workspace background sync.** Outlook
calendar sync, OneDrive, Google Drive client. Periodic
HTTPS to office.com / outlook.com / drive.google.com.
Confirm: source is a workstation with the client
installed; destination is the official endpoint. Suppress
at destination level if it's the dominant pattern on every
endpoint.

**6. Mobile device push notifications (Apple, FCM).** If
mobile devices traverse your network, they'll periodically
hit push.apple.com / mtalk.google.com. Same shape, same
disposition as M365.

**7. Internal monitoring beacons.** Nagios, Zabbix,
Prometheus exporters scraping internal targets — these can
look like outbound beacons if the monitored host's
perspective is what's captured. Confirm with the team that
runs the monitoring stack; suppress at the source level
only if you're confident the source is a known monitoring
host.

**8. Container/orchestration health checks.** If Archer is
ingesting from a network where Kubernetes nodes are
visible, k8s liveness/readiness probes look like beacons.
Confirm via the k8s admin team; suppress the probe
destinations.

**Rules of thumb for suppression:**

- Suppress at the *destination*, not the *source*. A
  source-level suppression hides real beacons too. The only
  exception: a dedicated monitoring host whose role is
  beacon-shaped by design.
- Time-bound suppressions (`days` parameter) for anything
  you're not 100% sure about. Six months on a long-conn
  suppression for "this is JFrog's repo and it's noisy" is
  fine. Forever-suppressions get stale.
- Record the reason in the suppression detail. Future-you
  will want to know whether the rule still applies.

The audit log (v0.14.0) records every allowlist and IOC
edit with the diff. If a future analyst questions why a
suppression exists, the audit trail names the analyst, the
time, and the entries added — see OPERATIONS.md → Audit
log.

---

## Note discipline

The note is the artifact that survives the finding. A future
analyst (possibly you, possibly someone who's never seen this
network) reads it to understand what you concluded and why.
Notes are forever — they survive analysis re-runs
(fingerprint merge), they go in the audit log (v0.14.0),
they're what the next analyst reads when they hit a similar
finding. Write them like you're writing for a colleague six
months from now.

### The standard structure

```
Verdict: <benign / suspicious / malicious / escalated>

Destination context: <what it is, how you know>

Source context: <which host, what it does>

Key evidence: <the 2-3 facts that drove the verdict>

Action taken: <suppressed / acknowledged / escalated to IR ticket #>
```

### Per-status templates

**Acknowledge + suppress** (the "FP" pattern — confirmed-benign,
add curation to prevent recurrence):

```
ACK — <software/system identified>. <Confirming evidence>.
Suppressed dst <ip/domain> for <N> days.
```

Example:

```
ACK — Microsoft Defender cloud-delivered protection.
Confirmed via Defender event log on src; dst resolves to
wdcp.microsoft.com per cert SAN. Suppressed dst for 90d.
```

**Escalation:**

```
ESC — <what's anomalous>. <What I checked>.
Pivot: <related findings or assets>.
Handing off to IR ticket #<N>.
```

Example:

```
ESC — Beacon 4h cadence to chocolate-tank-42.workers.dev,
no associated business need on src wkstn-finance-12.
Pivot: same src has DNS Tunneling on the prior day, same
dst has TI hit from MISP feed (Cobalt Strike infra).
Handing off to IR ticket #2026-0312.
```

**Acknowledge:**

```
ACK — <verdict>. <Why it's not malicious>.
Re-check if <condition>.
```

Example:

```
ACK — Developer workstation beaconing to S3 bucket; matches
the cadence of the internal CI/CD tool poller. No anomalous
payloads or methods. Re-check if the dst IP changes pattern.
```

**Leave open / waiting for more data:**

```
WAIT — <hypothesis>. <What I need to confirm/disprove>.
Re-check <when>.
```

Example:

```
WAIT — possible beacon, 4h interval but only 6 samples so
far. Need another 24h of data for confidence. Recheck
tomorrow.
```

### A worked good-note example

```
Verdict: benign

Destination context: AWS S3 bucket us-east-1. PTR matches
s3-eu-west-1.amazonaws.com pattern. Cert is Amazon Trust
Services.

Source context: 10.4.1.92, dev workstation per asset
inventory. Owner is in the CI/CD oncall rotation.

Key evidence: HTTP method is GET on /artifacts/<sha>;
cadence matches our Jenkins poll interval (5 min);
content-type is application/octet-stream which is correct
for binary artifacts.

Action: acknowledged, no suppression — keep monitoring in
case the IP changes pattern.
```

The 90-second cost of writing the second note pays off the
moment the same destination reappears in three weeks and a
different analyst doesn't have to redo your work.

### Anti-templates — don't write

- "False positive" with no reason.
- "Looks ok" / "investigated" / "checked".
- Anything that wouldn't help someone else reconstruct your
  decision.
- The full content of the finding (the finding row already
  has that — your note adds *interpretation*).
- Sensitive operational specifics that don't belong in a
  log most analysts can read. The note text is preserved
  on the finding *and* recorded in the audit log as
  length-only (v0.14.0) — content sensitivity is your
  responsibility, not the log's.

---

## Anti-patterns — things that look like good triage but aren't

**"It's HTTPS to a CDN so it's fine."** Wrong. Modern C2
rides HTTPS to CDNs by design. The destination's legitimacy
is not a defence. The *behaviour* (regular cadence + low
jitter + matching the source's role) is what makes it a
beacon — not the destination's reputation.

**"It only triggered once, must be a false alarm."** Beacons
need a full analysis window to score reliably. A finding
that fires on day 1 with a borderline score may strengthen
on day 2 as the sample grows. Don't acknowledge-and-suppress a
borderline beacon on day 1 — leave it open with a note and
look again tomorrow.

**"The destination has a TI hit so I'll just suppress."**
Backwards. A TI hit *confirms* the malicious nature —
escalate the parent finding and let the suppression be of
the false positives, not the confirmed bad. Suppressing a
confirmed indicator hides the next host that beacons to it.

**"My EDR didn't fire so it's not real."** EDR detects
on-host artefacts; Archer detects on-network patterns.
Sophisticated C2 hides the on-host side (process injection,
sleep masks, etc.) but cannot hide the network cadence —
the beacon is the only durable signal. **Network detection
catching what EDR missed is the entire point of the tool.**
Treat an Archer-only detection as more interesting, not
less.

**"There's no payload visibility so I can't be sure."** You
don't need payload to call a beacon. Cadence + low jitter +
sustained over a 24-hour window is enough to escalate. Let
IR pull the host artefacts; your job at this layer is to
flag the network signal.

**"I'll acknowledge-and-suppress every borderline finding to
keep the queue clean."** This is how teams blind themselves.
A borderline finding is a hypothesis, not noise. Leave it
open with a note; acknowledge it only when you've matched it
to a known pattern, and only add an allowlist/suppression
entry when the pattern is durable enough to warrant silencing
the detector for future analyses.

---

## Detection blind spots — what Archer cannot see

Know your tool's edges. Compensating controls live elsewhere
(EDR, DNS firewall, egress proxy logs); not knowing the gap
is how analysts develop false confidence.

**Encrypted-payload C2.** Archer sees connection metadata
(IPs, ports, bytes, timing, TLS SNI when present, certificate
fingerprints) but not payload. A beacon's *cadence* is
visible; what it's actually exchanging isn't. This is fine
for hunt-purposes — cadence is enough to escalate.

**DoH (DNS over HTTPS).** If the host uses DoH (Firefox
default, Chrome optional, Windows 11 optional), DNS queries
ride inside HTTPS and Archer's DNS analyzers see nothing.
The conn analyzer still sees the host talking to the DoH
resolver. Look for the DoH-Bypass finding type
(DETECTION_METHODS.md §9.5) — it surfaces hosts using DoH
against policy. Then the network behavior of those hosts is
what you hunt on.

**Direct-IP C2 with no DNS.** Some commodity malware
connects directly to a hardcoded IP and never does DNS
resolution. Archer sees the conn flow but has no domain
context. The beacon detector still works; the destination
just lacks a domain field. Pivot via TI hits on the IP.

**Encrypted SNI / Encrypted Client Hello (ECH).** Newer TLS
versions can hide the SNI from passive inspection. If the
sensor's Zeek build doesn't decode the destination domain
from SNI, the finding will show IP-only. Modern Cloudflare
deployments use ECH by default — expect more IP-only
findings over the next 12-24 months.

**Sensor-side blind windows.** If the sensor is down or
mis-configured, traffic during that window isn't captured.
The Sensors modal shows last-seen-at; if a sensor has been
stale for a week, the hosts behind it had a week of unhunted
traffic. Cross-check sensor health when investigating
"unusually quiet" hosts.

**Internal-only traffic.** Archer detects east-west
beaconing if the sensor sees that traffic, but most
deployments tap at the egress boundary and east-west goes to
a different sensor (or nothing). Lateral-movement-via-
internal-C2 needs internal taps to catch.

---

## When you're stuck

Sometimes the eight-question checklist comes back ambiguous.
You're not sure. The destination has no clear reputation,
the source isn't obviously off, the timing is
suspicious-but-not-obvious. The honest answer is: more
context than Archer alone can give you.

Reach for:

- **Your asset inventory.** Who owns the source host? What's
  its role? Is it under change, recently re-imaged, recently
  joined to the domain?
- **Your EDR or endpoint telemetry**, if you have one. What
  process on the source host is making the connections?
  Archer doesn't see process names; the endpoint agent does.
- **Cross-host correlation.** Are multiple sources beaconing
  to the same destination? (Use the Campaigns view.) If 1
  source, more likely malware on that source; if many
  sources, more likely a corporate agent.
- **The destination's neighbors.** Often a malicious
  destination lives next to other malicious destinations on
  the same netblock. Pivot the destination IP through your
  TI sources.
- **Time correlation.** Did the beacon start at an unusual
  time? Just after a phishing wave? Right when a user
  clicked a bad link? Workshop the timeline with whoever
  owns the source host.

When in doubt, escalate. A finding that turns out to be
benign costs the team an hour. A finding that turns out to
be malicious and was missed costs much more.

---

## Daily / weekly / monthly rhythm

This isn't prescribed; teams differ. Common shapes that work:

**Daily (15-30 min per analyst on rotation):**

1. Open Findings tab, filter to Critical + High, status=open.
2. Triage top-of-queue: 5-10 findings using the eight-question
   checklist.
3. Glance at Sensors modal — anything stale? Note for ops if
   so.
4. Glance at Hosts tab — any host risk score jumping from
   yesterday? Click and look.

**Weekly (1-2 hours):**

1. Audit-log review (admin only): scan the week's
   admin actions. Anything unusual?
2. Suppression-list pruning: any time-bound suppressions
   expiring soon that need extending or letting lapse?
3. Feed staleness: Feeds modal, anything red? Check the
   feed config.
4. Open-status queue: anything that's been "open" for >7
   days without a note? Either close it or update the note
   with what you're still waiting on.

**Monthly:**

1. Review FP rate by detector type. If a particular detector
   is firing 90% FP, look at the threshold config (Settings
   tab). Don't lower it without a recorded reason — tuning
   below baseline is how teams develop blind spots.
2. Review TI feed effectiveness. Feeds modal shows
   indicators-matched-per-feed. A feed that hasn't
   contributed to any finding in 30 days might be noise.

---

## Escalation criteria

You should escalate to IR when you have any of:

1. **Beacon + suspicious destination + can't explain it** —
   the bread-and-butter case. Write up what you saw, hand
   off the source asset for host triage.
2. **Beacon + TI hit on destination** — confirmation. Skip
   straight to host triage.
3. **Multiple internal sources beaconing to same external
   destination** — lateral spread of an active intrusion. IR
   needs to see this immediately, not after your morning
   coffee.
4. **Host risk roll-up jumping suddenly** — a host that was
   quiet for weeks suddenly has Critical+High findings
   across multiple detector families. That's an active
   compromise in progress.
5. **Sensor goes dark coincident with anomalous activity**
   on hosts behind it — could be coincidence; could be an
   adversary blinding the tap. Treat the second
   interpretation as the default until ruled out.

You should *not* escalate for:

- Single low-confidence finding with no corroboration.
- TI hit on a known-benign endpoint your team uses
  legitimately (suppress instead).
- Beacon to a vendor's update infrastructure (FP it).
- Strobe to a load balancer that's expected to do health
  checks (acknowledge / suppress at destination).

When in doubt, *write the note and ask a colleague*. The
audit log preserves that you considered it; an unwritten "I
thought about it" doesn't.

---

## Glossary — Archer-specific terms

- **Beacon score.** 0-100. ≥80 = critical, ≥60 = high, ≥40 =
  medium, below that = low (see `sevFromScore` in
  `internal/analysis/types.go`). The same severity ladder
  applies to every detector that uses score-derived severity.
  See DETECTION_METHODS.md §2.2 for the beacon-score formula.
- **CoV (coefficient of variation).** Stddev / mean of
  inter-arrival times. Low CoV = regular beacon. Reported
  in the finding detail.
- **Fingerprint merge.** When the analyzer re-runs, findings
  whose identifying fields (type, src, dst, key signals)
  match an existing finding preserve the analyst's
  notes/status. Re-analysis won't destroy your work.
- **Host risk score.** Sum-of-finding-scores roll-up per
  host, surfaced on the Hosts tab. Composite signal — a
  noisy individual finding plus an unrelated noisy finding
  still produces a high roll-up. Investigate the underlying
  detections, not the roll-up score alone.
- **Off-hours.** Time window defined in Settings (default
  22:00-06:00 in the configured timezone, per
  `OffHoursStart` / `OffHoursEnd` in `config.Default()`).
  The detector scores larger outbound transfers in this
  window higher.
- **Suppression.** Per-target (IP / domain / regex / host)
  mute on the *finding generation* side. Time-bound.
  Stored separately from allowlist (which prevents source
  participation in any detection) and IOC list (which
  forces hits).
- **Watch.** The two-tier scheduled analysis cadence —
  first tick of UTC day runs a full pass, intermediate
  ticks run incremental TI-only.
- **TI cross-annotation.** When a TI feed match lands,
  other findings touching the same IP/domain get a pointer
  to the TI evidence. The little badge in the
  cross-references panel.

---

## Where this fits in the larger workflow

This is one of three analyst-facing references:

- **`DETECTION_METHODS.md`** — how the detectors work. Read
  once, re-read when you encounter a new detector type. The
  math behind each score.
- **`ANALYST_PLAYBOOK.md`** (this doc) — how to triage real
  findings. Read once, keep open during shifts.
- **`OPERATIONS.md`** — how the deployment runs. Read once;
  usually the engineer running Archer cares about this more
  than the analyst.

Future per-detector triage sections (HTTP Beacon, Suspicious
Certificate, DNS Tunneling, Data Exfiltration, Off-Hours
Transfer, Long Connection) will land in this file as they
get written. They'll follow the same shape — fast-path
filter, lean-malicious / lean-benign indicators, eight-
question checklist, worked examples — so analysts working a
specific finding type can find the relevant playbook by
section without scrolling through unrelated content.

If this doc gets something wrong, fix it. The right level
of abstraction is "what an analyst with two years of network
defence experience needs to know to be productive in Archer's
first week." If you find yourself explaining basic Zeek or
basic networking, cut it. If you find yourself missing a
real-world tradecraft pattern, add it.
