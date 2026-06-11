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

The current edition focuses on the **Beacon** detection family
(Archer's headline detection — see DETECTION_METHODS.md §2). The same shape
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
5. [Querying the findings table](#querying-the-findings-table)
6. [Anatomy of a beacon finding](#anatomy-of-a-beacon-finding)
7. [Indicators that lean malicious](#indicators-that-lean-malicious)
8. [Indicators that lean benign](#indicators-that-lean-benign)
9. [The eight-question triage checklist](#the-eight-question-triage-checklist)
10. [Worked examples](#worked-examples)
11. [Pivoting from a beacon](#pivoting-from-a-beacon)
12. [Beacon-depth tools — signature hunting, JA3 pivot, URI footprint, export](#beacon-depth-tools--signature-hunting-ja3-pivot-uri-footprint-export)
13. [Benign-pattern catalog and the suppress-vs-allowlist rule](#benign-pattern-catalog-and-the-suppress-vs-allowlist-rule)
14. [Note discipline](#note-discipline)
15. [Anti-patterns — things that look like good triage but aren't](#anti-patterns--things-that-look-like-good-triage-but-arent)
16. [Detection blind spots — what Archer cannot see](#detection-blind-spots--what-archer-cannot-see)
17. [When you're stuck](#when-youre-stuck)
18. [Daily / weekly / monthly rhythm](#daily--weekly--monthly-rhythm)
19. [Escalation criteria](#escalation-criteria)
20. [Glossary — Archer-specific terms](#glossary--archer-specific-terms)

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
| `*.local` (mDNS), multicast IPs (224.0.0.0/4), broadcast, IPv6 link-local | service discovery | auto-excluded — no action needed |
| Your own DNS resolver (8.8.8.8, 1.1.1.1, internal) | DNS health | suppress destination |

"Suppress" means: add the destination to the allowlist with a
clear comment (`# WSUS — Windows Update`). The detector still
runs against those flows; it just doesn't surface them. Future
analysts will read your comment and understand why.

The allowlist (and the IOC list) match a finding's source and
destination as **exact** values, **CIDR** ranges (`10.0.0.0/8`), or
**wildcards** — `*` matches any run of characters, `?` exactly one. So
the `*.`-prefixed patterns above work as written: `*.in-addr.arpa`
suppresses the reverse-DNS apexes the DNS detectors surface in the
destination column, `*.internal.corp` a domain family, `185.220.*` an IP
prefix (though CIDR is cleaner for ranges). Wildcards are matched
case-insensitively and anchored to the whole value.

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
- **Score Chart** (action bar button next to Beacon Chart, gated on
  Beacon / HTTP Beacon / DNS Beacon / Port-Hopping Beacon; grayed out until at
  least one daily history row exists) — 30-day trajectory of the
  composite score plus the four sub-axes, updated once per UTC day
  on the first full pass. Opens the evolution modal directly.

**Step 4 — Read the chart, not the score.** The cadence chart
is the most diagnostic thing in the UI. You're looking for:

- **Tight vertical spacing of dots** = low jitter = beacon.
- **Even spacing across the time axis** = sustained cadence,
  not bursty human activity.
- **Continuation past business hours** = not a user.
- **Dot count high enough to trust the math** = at least
  `BeaconMinConnections` (default 4). The chart shows this.

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

**Working without losing your place:** every action that mutates
the list — Acknowledge, Escalate, Dismiss, bulk-dismiss-campaign,
Add to Allowlist / Add to IOC List, Suppress, Allow this
Relationship — reloads in place. The acted rows drop out and the
rest shift up, but your tab, page, and scroll position hold (on
the Campaigns and Hosts tabs too). You can triage or curate
straight down a long list without being thrown back to the top
after each entry. Only a deliberate view change — running a new
query, toggling delta mode, changing page size — resets to the top.

---

## Querying the findings table

The query bar above the table is your primary filter. It's a
Lucene-style query language — type a query, press **Run** (or
Enter), and the table narrows to matching findings. The query is
evaluated server-side and ANDed on top of whatever view you're in
(Findings, Acknowledged, Campaigns, …), so it composes with the
tab rather than fighting it. Clear the bar to see everything in
the view again.

The **▾** caret at the left edge of the query field reopens the last
10 distinct queries you ran — pick one to drop it back in the box and
run it.
The list is per-browser, most-recent-first, and deduplicated; every
run path feeds it (Run, Enter, a Hunts/chip pick, a TLS or
contributing-activity pivot), so it's a quick way to step back to a
query you've moved on from without retyping it.

A bad query doesn't silently match everything or nothing — a red
toast drops in from the top of the page with the reason, and the
table keeps your last good results. It fires from every view —
Findings, Campaigns, Hosts — not just the findings list. You'll see
it for a malformed query (`score:[80 TO]`), an unknown field
(`dest:1.2.3.4` — it's `dst`), a finding type that doesn't exist
(`type:"Correlatd Activity"` — a typo never silently matches zero
rows), or a missing operator between terms (`type:Beacon
severity:critical` — put an `AND` between them). Read the toast
before trusting the result.

### The shape of a query

- **Field term:** `field:value` — `type:Beacon`, `dst:185.220.101.7`,
  `severity:critical`.
- **Bare term:** a word with no field is a case-insensitive
  substring match across type, src, dst, port, detail, timestamp,
  and severity — the same reach the old Search box had. A bare IP
  literal (`185.220.101.7`) matches the src **or** dst exactly.
- **Boolean logic:** `AND`, `OR`, `NOT`, and `()` grouping. An
  explicit operator is **required** between terms — `type:Beacon AND
  severity:critical`, not `type:Beacon severity:critical` (which is a
  parse error and toasts). Use `AND NOT` to exclude
  (`type:Beacon AND NOT sensor:sensor-a`).
- **Wildcards:** `*` (any run) and `?` (one character) on string
  fields — `dst:185.220.*`, `hostname:cdn?.example.com`,
  `detail:*jitter*`.
- **Comparisons:** `>=`, `<=`, `>`, `<`, `=` on numeric and date
  fields — `score:>=90`, `ts:>=2026-03-15`. `=` is an exact match
  (`conns:=1542`); a bare value with no operator means the same
  (`conns:1542` ≡ `conns:=1542`).
- **Number format:** numeric values are read as decimals, not just
  whole numbers — `meanint:<=9.5`, `jitter:<0.42` all parse. The
  catch is on exact `=`: a count field like `conns` only ever holds a
  whole number, so `conns:=1542.5` parses but can never match (there's
  no fractional connection count); use a whole number for `=` on
  `conns`. Decimals are exact-matchable on the true-float fields
  (`meanint` / `medint` / `jitter`).
- **Ranges:** `field:[lo TO hi]`, inclusive — `score:[80 TO 100]`,
  `ts:[2026-03-01 TO 2026-03-15]`.
- **Quoted phrases:** wrap values with spaces in quotes —
  `detail:"every 47s"`, `ts:>="2026-03-15 08:00:00"`.

### Fields you can query

| Field | Matches | Notes |
|---|---|---|
| `id` | Finding ID | Numeric — `id:1542` exact, plus comparisons and `[lo TO hi]` ranges. Reads the finding's stable ID directly (not the Detail text), so it works regardless of what the Detail string says. The ID is shown in the detail pane's identity block. |
| `type` | Finding type, e.g. `type:Beacon` | Exact (case-insensitive). Must name a real finding type — a misspelling (`type:Beaon`) is rejected with a toast, not silently empty. `type:beacons` matches the **whole** beacon family (Beacon / HTTP Beacon / DNS Beacon / Port-Hopping Beacon). |
| `severity` | `critical` / `high` / `medium` / `low` | Exact. |
| `score` | Composite score | Numeric — comparisons and ranges. |
| `src` / `dst` | Source / destination IP | Bare IP = exact; CIDR (`dst:185.220.101.0/24`) = containment; wildcard (`dst:185.220.*`) = prefix/substring; the keyword `rfc1918` (or `private`) matches the internal IP space (RFC1918 + IPv6 ULA + loopback + link-local — the same boundary `dir:` uses), and `public` (or `external`) is its strict inverse (a parseable, non-internal address). E.g. `src:rfc1918 AND dst:public` is the outbound shape. |
| `port` | Destination port | Comma-separated list allowed (`port:443,8443`); equality only. |
| `dir` | Traffic direction across the internal/external boundary | `dir:outbound` (internal→external — the usual beacon scope), `dir:inbound`, `dir:internal` (both RFC1918 — lateral; alias `dir:lateral`), `dir:external` (both public). Collapses hand-rolled `(src:10.0.0.0/8 OR src:172.16.0.0/12 OR src:192.168.0.0/16)` juggling into one term. An unknown direction is rejected with a toast. Alias: `direction`. |
| `hostname` | Resolved hostname / SNI | Substring or wildcard. |
| `uri` | HTTP Beacon request path | Substring or wildcard (`uri:/submit.php`, `uri:*pixel*`). Populated only for HTTP Beacon, so it's naturally scoped — hunt arbitrary paths the C2-URI detectors don't hardcode. |
| `service` | Zeek DPD protocol (the L7 Zeek fingerprinted for the flow) | Substring or wildcard, case-insensitive (`service:http`, `service:ssl`, `service:rdp`). Stamped on every conn-derived finding — Beacon, Lateral Movement, C2 Port, Strobe, Data Exfiltration, Off-Hours Transfer, Long Connection, Protocol on Unexpected Port, Admin Protocol Egress, and Database Protocol Egress — with the originating connection's service. Blank when Zeek's DPD didn't fingerprint the flow (and on a non-Security-Onion sensor that doesn't run the analyzer). Combine with `type:` to scope — e.g. `type:Beacon AND service:ssl`, or `type:"Protocol on Unexpected Port" AND service:http` for the protocol-mismatch hunt. The value matches Zeek's DPD string, which sometimes differs from the common name, so a few synonyms are aliased to Zeek's label: `vnc`→`rfb`, `tls`/`https`→`ssl`, `kerberos`→`krb`, `cifs`/`microsoft-ds`→`smb`. (WinRM has no alias — it rides HTTP as `service:http`, so query it by port: `port:5985,5986`.) See DETECTION_METHODS §8. |
| `detail` | The Detail string | Substring or wildcard — useful for `detail:"every 47s"` or `detail:*domain fronting*`. |
| `sensor` | Sensor name | Exact. |
| `file` | Source log file | Substring or wildcard. |
| `status` | `open` / `acknowledged` / `escalated` / `dismissed` | `status:open` = no status set yet. |
| `note` | Analyst note text | Substring or wildcard (`note:*pcap*`; `note:?*` = "has any note"). Alias: `analyst_note`. |
| `analyst` | Who set the finding's status | Substring, case-insensitive (`analyst:alice`). Pair with `status:escalated` to audit one analyst's escalations. |
| `ts` | Finding timestamp (event time) | Date (`ts:>=2026-03-15`) or datetime; interpreted in **your** timezone. A bare date is the whole day. |
| `detected` | When Archer **first detected** the finding | Same date/datetime grammar as `ts`, but keyed on first-seen time rather than the network event — the durable "new since my last shift" anchor (`detected:>=2026-06-01`). Decoupled from event time: an old beacon detected fresh still surfaces. Alias: `detected_at`. |
| `ja3` / `ja4` | TLS client fingerprint | Exact — the query-bar equivalent of the TLS Pivot button. |
| `ioc` | IOC-list match | `ioc:true` / `ioc:false`. |
| `spectral` | Spectral-rescued beacon | `spectral:true` surfaces beacons rescued by the periodogram. |
| `channel` | Per-channel beacon split | `channel:true` surfaces promoted per-channel beacons (a clean TLS channel split out of a noisier blended beacon to the same dst, §2.8 in DETECTION_METHODS); `channel:false` excludes them. Find a specific channel with `ja3:<hash>`. |
| `benign` | Fingerprint marked benign | `benign:true` matches findings whose JA3/JA4 client fingerprint you've marked benign on the TLS Fingerprints wall; `benign:false` excludes them. E.g. `type:Beacon AND benign:false` hides beacons over already-triaged fingerprints. The **Hide FP Benign** chip (next to Show Dismissed) applies `benign:false` to every view without typing it. |
| `attack` | MITRE ATT&CK technique | Matches the technique(s) the finding type maps to, by ID, tactic, or name (substring/wildcard, case-insensitive). `attack:T1071` matches the base technique **and** its sub-techniques (so it catches HTTP/DNS Beacons too); `attack:T1071.004` is exact; `attack:"command and control"` filters by tactic. The same map drives the detail-pane ATT&CK chips and the **ATT&CK** Coverage modal. TI hits, roll-ups, and Zeek notices carry no technique, so they match no `attack:` predicate. |
| `tscore` / `dscore` / `hist` / `dur` | Beacon sub-scores (Timing / Data size / Histogram / Persistence) | Numeric — comparisons and ranges. **Any** sub-score predicate implicitly scopes to the beacon family, so a bare `dur:<=0.3` won't drag in non-beacons whose sub-scores are a structural 0. |
| `conns` / `meanint` / `medint` / `jitter` | Beacon timing/volume metrics — observation count (`conns`, aka connections/requests), mean and median inter-arrival interval in **seconds**, and `jitter` (coefficient of variation = stddev/mean, the raw ratio — `0.42`, not `42%`) | Numeric — comparisons and ranges (`conns:<=10000`, `meanint:<=10`, `jitter:<0.5`, `conns:=1542`). `conns` is a whole-number count (use whole numbers for exact `=`); the interval/jitter fields are true floats so decimals match (`jitter:=0.42`). Beacon-scoped like the sub-scores: a structural 0 on every non-beacon, so a bare upper bound won't drag them in. Aliases: `connections`, `mean_interval`, `median_interval`. |
| `outratio` | Outbound/inbound payload-byte ratio over the pair's observation window | Numeric — comparisons and ranges. `outratio:>=2` is the whole-window analogue of the beacon chart's red **upload-heavy** Bytes-mirror buckets (sent > 2× received). Stamped on conn-derived `Beacon` / `Port-Hopping Beacon` / `Data Exfiltration` findings; everything else (including per-channel beacon sub-findings) carries no byte totals and matches no `outratio:` predicate. An all-upload pair (zero bytes received) matches every lower bound. |

The same fields are listed in the query bar's **+ more ▾** chip
menu — click a chip to drop the field into the bar.

### Prebuilt hunts (the Hunts ▾ chip)

Leftmost in the chip row, **Hunts ▾** is a menu of complete,
ready-to-run queries for the shapes worth looking at first. Unlike
the other chips (which upsert one token onto whatever you've already
typed), a hunt is an alternative *lens* — picking one **replaces** the
whole query box and runs immediately. Every query is a normal
expression, so once it's in the box you can tune it (raise a
threshold, AND on a subnet, drop a clause).

**Beacon varieties** — each isolates one variety by the axis that
distinguishes it (sub-scores are in `[0, 1]`):

| Hunt | Query | What it catches |
|------|-------|-----------------|
| Textbook check-in | `type:beacons AND tscore:>=0.8 AND dscore:>=0.8` | Regular clock **and** fixed payload — the classic heartbeat. |
| Tasking channel | `(type:"Beacon" OR type:"HTTP Beacon") AND tscore:>=0.8 AND dscore:<=0.3` | Steady cadence, *variable* payload — command/response or staged exfil. Scoped off DNS Beacon (its `dscore` is a structural 0). |
| Jitter-evading (spectral) | `type:beacons AND spectral:true AND dir:outbound` | Fixed schedule + bounded random jitter — the periodogram recovered a period the interval stats missed. Outbound-scoped to drop internal mDNS. |
| Clockwork (no jitter) | `type:beacons AND jitter:<0.05` | Interval CV under 5% — metronomic, default-config implant. |
| Scheduled / fixed-hour | `type:beacons AND tscore:>=0.7 AND hist:<=0.3` | Regular cadence concentrated in a narrow daily window (e.g. 02:00 nightly) — low circadian uniformity = scheduled stealth. |
| Low-and-slow | `type:beacons AND medint:>=1800` | Median sleep ≥ 30 min — evades rate/volume detection. |
| Persistent long-haul | `type:beacons AND dur:>=0.8` | Active end-to-end across the trailing persistence window. |
| DGA-backed | `type:beacons AND detail:"DGA-suspect"` | Destination domain scored algorithmically-generated. |
| Port-hopping | `type:beacons AND detail:"co-traffic to dst"` | Same `src→dst` seen across more than one destination port. |

**Threat signatures:**

| Hunt | Query |
|------|-------|
| Threat-intel matches | `ioc:true` |
| Known C2 signatures | `type:"Cobalt Strike URI" OR type:"C2 URI Pattern" OR type:"C2 Port" OR type:"Malicious JA3" OR type:"Malicious JA4" OR type:"Protocol on Unexpected Port"` |
| DNS covert channels | `type:"DNS Tunneling" OR type:"DNS Subdomain DGA" OR type:"DNS NXDOMAIN Flood" OR type:"DNS Beacon"` |
| Data exfiltration | `type:"Data Exfiltration" OR type:"Off-Hours Transfer"` |
| TLS evasion | `type:"DoH Bypass" OR type:"Domain Fronting" OR type:"SSL No-SNI on C2 Port" OR type:"SSL No-SNI"` |
| Lateral movement | `type:"Lateral Movement" OR (type:beacons AND dir:internal)` |
| Remote admin egress | `type:"Admin Protocol Egress"` (interactive SSH/RDP/VNC/Telnet to a public dst) |
| Database egress / exfil | `type:"Database Protocol Egress"` (cleartext MySQL/PostgreSQL/MongoDB/Redis to a public dst) |

The thresholds are starting points, not gospel — `tscore:>=0.8`,
`jitter:<0.05`, `medint:>=1800` and the rest are there to be tightened
or loosened against your own traffic once the hunt is in the box.

### Queries that earn their keep

- **The critical-beacon triage queue:**
  `type:beacons AND severity:critical` — every beacon-family
  finding at the top severity, the first thing to work each shift.
  Toggle **New only** alongside it to scope to findings first seen
  since your last login.
- **Outbound beacons only** (drop lateral and inbound noise):
  `type:beacons AND dir:outbound` — `dir` replaces the old
  `(src:10.0.0.0/8 OR src:172.16.0.0/12 OR src:192.168.0.0/16)`
  CIDR juggling with one term. Swap to `dir:internal` to hunt
  lateral movement.
- **Detected since your last shift** (independent of event time):
  `detected:>=2026-06-01 AND score:>=90` — `detected` keys on
  first-seen time, so an old beacon Archer only just surfaced still
  shows up (where `ts` would bury it in March).
- **HTTP-beacon path hunt:**
  `type:"HTTP Beacon" AND uri:*pixel*` — pivot on request paths the
  hardcoded C2-URI detectors don't cover.
- **Signature hunt — the staging-beacon shape** (tight timing,
  short duration, below a score floor):
  `tscore:>=0.9 AND dur:<=0.3` — sub-scores are in `[0, 1]`, so a
  high-timing floor is `0.9`, not `90` — see
  [Beacon-depth tools](#beacon-depth-tools--signature-hunting-ja3-pivot-uri-footprint-export)
  for why this finds implants the composite score buries.
- **One subnet, one window:**
  `dst:185.220.101.0/24 AND ts:>=2026-03-15` — scope to a known-bad
  range since an incident start time.
- **Find the implant family by fingerprint:**
  `ja4:t13d1516h2_8daaf6152771_b186095e22b6` — every finding on
  that JA4 (or use the TLS Pivot button, which builds this for you).
- **TI-confirmed, excluding a noisy benign cluster:**
  `ioc:true AND NOT dst:10.0.0.0/8` — external IOC hits only.
- **Free-text fallback:** when you don't remember the field,
  just type the value — `cobalt` or `185.220.101.7` — and the bare
  term does the substring/IP match.

Everything you filter to is what the per-tab **Export** honors, so
a query is also how you scope a hand-off export (see
[Beacon-depth tools → Export the beacons](#beacon-depth-tools--signature-hunting-ja3-pivot-uri-footprint-export)).

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

**Destination port + co-traffic.** The labeled port is the
*modal* one — the port carrying the most connections for this
src→dst pair. Archer aggregates a pair's connections across
ports, so when a host reaches the same destination on more
than one port the finding shows the dominant port and lists
the rest in the detail line's **co-traffic** segment:
`co-traffic to dst: 22×8 (14.1 KB, 2026-05-08 04:11→2026-05-31
09:02)` — port, connection count, byte volume, and first/last
seen. Co-traffic is your cue that the beacon shares a
destination with other activity — an HTTPS implant on a host
that also SSHes to the same box, say. A *regular* minority
port deserves a second look (it may be a second channel); an
irregular one is usually unrelated administrative traffic.

**Connection count.** How many flows the detector saw to this
pair in the analysis window. Below `BeaconMinConnections`
(4 default) the finding doesn't fire; just above the
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

**Why flagged.** Below the fields, the *Why flagged* block
states in plain English what this detection type means and
why it fired, then names the benign shapes that mimic it
(*Common false positives* — for a beacon, the usual suspects
are backup clients, update agents, and NTP heartbeats).
Expand *Scoring detail* when you want the exact formula. It's
a fast in-pane reminder so you don't have to leave the finding
to recall what you're looking at.

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

**Score evolution chart.** Beacon / HTTP Beacon / DNS Beacon /
Port-Hopping Beacon findings get a **Score Chart** button in the action bar (next to
Beacon Chart) showing up to 30 daily snapshots of the composite
score plus the four sub-axes (Timing, Data size, Histogram,
Persistence). The button is grayed out until at least one daily
history row exists for the finding — a finding first detected today
will have no history yet.
Click opens the evolution modal with PNG / JPEG export. The chart
updates once per UTC day, on the first full pass — so it's a
*trend* view, not a real-time stream.

Read it for trajectory rather than absolute value:

- **Flat high score** — stable, persistent channel. A
  long-running C2 implant looks like this; so does a
  long-running legitimate health probe. Use the other
  indicators to separate.
- **Climbing ts with stable ds** — the beacon is becoming
  more regular. An initial-jitter implant settling into its
  rhythm, or an operator-side cleanup of legitimate scheduled
  job timing.
- **Climbing Persistence with flat Timing/Data size** — the channel
  is staying alive longer each day; the implant's session keepalive
  is succeeding.
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

**Correlated Activity.** If this finding's `(src, dst)` pair is
also carrying findings from N+ other detector types, the analyzer
emits a separate **Correlated Activity** roll-up row for that pair.
Right-click it → **Show contributing activity** to filter the
Findings tab to that `(src, dst)` pair — every contributor *and*
the roll-up land in one view.
This is the fastest way to spot kill-chain progression — a
Beacon finding plus a DNS Tunneling finding plus a Suspicious File
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
  (`KnownC2Ports` in `internal/analysis/heuristics.go` — Metasploit
  4444, Cobalt Strike defaults, etc.)

Archer automates much of this with the **Protocol on Unexpected Port**
detector (DETECTION_METHODS §8): Zeek's DPD names the *actual* L7
protocol regardless of port, so `http` on 8443 or `ssl` on 4444 to an
external host is its own finding — you don't have to eyeball the
port column. Query `type:"Protocol on Unexpected Port" AND service:http`
(or `ssl`, `ssh`, …) to pull every recognized protocol caught egressing
where it shouldn't — `service:` now spans all conn-derived findings, so
`type:` scopes it to the mismatch detector. It's scoped to external
destinations and to protocols DPD recognizes — an encrypted tunnel Zeek
can't fingerprint carries no service and won't appear, so this is a
strong positive signal but not a guarantee of total coverage.

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

**Finding**: Beacon, score 78, src `10.4.1.50` → dst
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

**Finding**: Beacon, score 81, src `10.4.1.7` → dst
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

**Finding**: Beacon, score 62, src `10.4.1.92` → dst
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

**Finding**: Beacon, score 51, src `10.4.1.7` → dst
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

## Beacon-depth tools — signature hunting, JA3 pivot, URI footprint, export

These four tools (v0.27.0) change the unit of work from "triage the
high-score rows one by one" to a loop: **find the shape → find every
instance of it → confirm it's C2 → hand it off.** None of them changes
detection — they don't catch anything new. They make what's already
detected *huntable*. Use them in that order.

### 1. Sub-score signature hunting — find the shape

The score column is the **average** of four axes (see §5 / Anatomy).
The UI labels them **Timing**, **Data size**, **Histogram**, and
**Persistence**; the same four are the `ts` / `ds` / `hist` / `dur`
identifiers in the detection math (§2.2), exposed in the query bar as
the `tscore` / `dscore` / `hist` / `dur` fields. Averaging hides shapes. A staging beacon — dead-on
cadence, but it only checked in for ten minutes before the operator
moved on — has a high **Timing** and a low **Persistence**/**Histogram**,
so its *composite* lands at 55 and never crosses your score floor. It
is a textbook implant and the score buried it.

Query the sub-scores directly — `tscore` (Timing), `dscore` (Data
size), `hist` (Histogram), `dur` (Persistence) take comparisons and
inclusive `[lo TO hi]` ranges. Any one of them scopes the whole result
to beacons automatically (you can't accidentally pull non-beacons —
their axes are a structural zero). Stop sorting by score and hoping the
shape floats up; *state the shape* and pull it directly:

| You're hunting | Query |
|---|---|
| Short-lived tight-cadence check-ins (staging, hands-on-keyboard) | `tscore:>=0.80 AND dur:<=0.30` |
| Long-haul low-and-slow tunnel (keepalive) | `tscore:>=0.70 AND dur:>=0.80 AND hist:>=0.80` |
| Constant-size heartbeat regardless of timing jitter | `dscore:>=0.85 AND jitter:<0.3` |
| "Show me everything beacon-shaped, any score" | any single bound, e.g. `tscore:>=0.50` |

The same beacon scoping applies to the raw timing/volume metrics the
scorer recorded: `conns` (observation count), `meanint` / `medint`
(mean / median inter-arrival interval, seconds), and `jitter` (the
coefficient of variation, raw — `0.42`, not `42%`). Reach for them
when the *value*, not the score, is the hunt: `conns:<=10000` to drop
chatty high-volume noise, `meanint:>=3600` for hour-plus low-and-slow
check-ins, `jitter:<0.2` for metronome-tight cadence.

This is the entry point. Everything below pivots from a finding you
found here.

### 2. JA3 pivot — find every instance of the implant

Open a beacon that went over TLS. The detail pane now shows a **JA4**
(or **JA3**) line and `matched N other beacons in this dataset`, plus a
**TLS Pivot** button in the action footer. The fingerprint identifies
the TLS *client* — the malware's TLS stack, not the destination. An
implant family produces the *same* fingerprint from every host it runs
on, regardless of which C2 IP or domain each victim talks to.

So: one beacon you've assessed as malicious → **TLS Pivot** → the
findings table re-filters (via the `ja4:` field — or `ja3:` when no
JA4 is present — which you can see and edit in the query bar) to
*every* finding carrying that fingerprint. Three
internal hosts beaconing to three different destinations with the same
JA3 is not three findings — it's one implant on three machines and you
just scoped the whole intrusion. This is the lateral-spread signal
that the per-destination view can't show you.

Caveats: a shared *generic* JA3 (a common Go/Python HTTP client, a
stock curl) is weak on its own — corroborate with the destination
reputation and the rest of the beacon shape before calling spread.
JA4 shows only if the sensor's Zeek emits it (stock Zeek does not);
its absence means nothing.

**Reading the FP rarity row.** A conn-level beacon's Detail pane carries a
colour-coded **FP rarity** row, e.g. `rare — shared by 3 internal hosts · 43
conns, 1 dst(s)`. Unlike the "matched N other beacons" sibling count — which
only counts beacons Archer *already flagged* — this is computed over **every
TLS connection** in the capture, so it sees rarity (is this fingerprint a rare
implant stack or a ubiquitous browser?) and cross-host clustering even when the
sibling hosts scored too low to emit their own beacon finding. The row colour is
the concern level, read it like the severity colour: **red** (rare JA4 shared
across hosts — the implant-family shape, a rare TLS stack on multiple machines
all phoning a tight C2 set), **orange** (rare JA4, single host), **yellow** (rare
JA3 across hosts — JA3 collides on generic stacks, so corroborate), **green**
(rare JA3, single host), **white** (`common` — a browser/SDK reaching thousands
of dsts; means nothing). A `JA3 only` note means no JA4 was available and the
match rests on JA3 alone, which generic Go/Python/Rust stacks share — weight it
down. This row never changes the score (a corpus FP study showed no single
network signal, fingerprint rarity included, can safely auto-flag a beacon as C2
on a cloud-heavy network); it's there to rank where you look first.

### 3. URI footprint — confirm it's C2, not a chatty app

For an HTTP beacon the detail pane lists **Beacon paths on `<host>`** —
the request paths that same `(src,dst,host)` beaconed on, by request
count. This is the benign-vs-C2 discriminator that the single-URI view
hid:

- **One path, repeated** (`/api/v2/telemetry` every 5 min) → almost
  always a benign app. Telemetry, update checks, presence pings hit
  one stable endpoint.
- **A small fixed set** (`/poll` n=312, `/cmd` n=18, `/upload` n=4) →
  this is a C2 protocol. Frequent check-in, occasional tasking, rare
  exfil — the count ratio *is* the command-and-control rhythm. Read
  the paths: a poll/result/task split is implant structure, not a
  REST API a browser would touch.

If the footprint is one path, weight your assessment toward benign and
go look at reputation. If it's a structured handful, that's
corroborating evidence for malicious — and the path names are IOCs:
note them, they're the implant's control API.

### 4. Export the beacons — hand it off

Once you've worked a campaign, hand it off without dumping the whole
findings DB on the IR team. Set the **Type** filter to **Beacons (all
types)** and use **Export current tab**:

- **JSON** carries everything — the four sub-scores, jitter, sample
  size, JA3/JA4, and the `top_uris` footprint. This is the artifact
  for an IR/SOC handoff: every beacon with its full per-axis evidence
  and TLS fingerprint already attached, nothing else.
- **CSV** is the same beacon scope with the triage columns appended
  (`ts_score`…`sample_size`, `ja3`, `ja4`) for a spreadsheet triage
  pass. The footprint list is JSON-only — a path list doesn't fit a
  flat cell.

The export honours every filter you have set, so "export the beacons
matching `tscore:>=0.8 AND dur:<=0.3` with this fingerprint" is one
click — the hunt result, scoped, not the database.

### Worked loop

NXDOMAIN-quiet morning. You query `tscore:>=0.85 AND dur:<=0.35` —
eight findings the score-sorted view had below
the fold. One is a finance
workstation to a no-reputation IP on 443, jitter 4%, sample 280. You
**TLS Pivot**: the same fingerprint is on two more workstations to two
*different* IPs. Not three alerts — one implant, three hosts. You open
the HTTP beacon among them: footprint is `/news/feed` n=240, `/news/post`
n=9 — poll/result, not a news reader. You set Type → Beacons, keep the
fingerprint filter, **Export current tab → JSON**, attach it to the escalation.
Twenty minutes, campaign scoped and handed off — work the existing
detections, don't re-hunt them.

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

### Allowlist suggestions — closing the repeat-FP loop

If you find yourself acknowledging the same beacon every
analysis run — OS update checker, cloud sync, EDR heartbeat
— Archer will eventually surface it in the **Suggestions**
tab (Allowlist → Suggestions).

A pair appears there when two gates are both true:

1. It has fired across **14+ distinct UTC days** in the
   beacon evolution history — enough history that the
   pattern is unambiguously stable, not just a noisy week.
2. A current finding for that pair is **acknowledged** by
   an analyst.

Pairs already covered by a Relationship rule are excluded.

**To apply a suggestion:**

1. Open **Allowlist → Suggestions**.
2. Review the evidence trail: source → destination : port,
   finding type, how many days it has fired, date range,
   peak score, who acked it.
3. Type a justification in the text field — what software
   or service this is, why it is benign, enough context
   for a future analyst to verify the rule is still valid.
   The field is required; you cannot apply without it.
4. Click **Apply**. Archer creates a Relationship rule
   scoped to that exact `(src, dst, port, finding_type)`
   tuple. The justification is stored as the rule's note
   and is visible in the Relationships tab.

The suggestion disappears from the list once the rule
exists. If you later remove the rule, the pair will
re-appear in Suggestions on the next check (once it still
meets both gates).

**When not to apply:**

- The destination IP overlaps with ranges shared between
  a known vendor and unknown actors — suggestions are
  pair-scoped, but verify the destination is specifically
  the vendor's infrastructure before allowing.
- You're not sure why the analyst acked it. Check the
  notes on the finding first; an ack during a noisy
  incident triage pass is not the same as a deliberate
  verification.
- The beacon started recently and the 14-day gate was met
  by a fast-moving investigation window. Review the
  evolution chart before applying.

### Marking a TLS fingerprint benign

The **TLS Fingerprints** modal (left sidebar → Hunt → TLS Fingerprints)
is the third noise-reduction tool, scoped not to a destination
or a pair but to a **TLS client shape**. When a rare or
cross-host JA3/JA4 keeps re-surfacing on the wall and you've
confirmed it — a corporate EDR agent, a niche SDK, an internal
scanner — click **Mark benign** on its row. The fingerprint
drops off the wall into a collapsed **Benign** section, and any
finding carrying that JA3/JA4 is tagged with a muted `FP Benign`
chip in the table.

You don't have to go to the wall to do this. The JA3/JA4 rows in
a finding's **Detail** pane carry the same **Benign** / **Malicious**
buttons, so you can triage a fingerprint straight from a beacon you're
looking at — including a low-concern fingerprint the wall hides (a
common shape, or a single-host JA3). Same effect either way: Benign
allowlists it (the `FP Benign` chip then lands on every finding
carrying it, the CRITICAL beacon included), Malicious adds it to the
JA3/JA4 IOC list so it flags as `Malicious JA3/JA4` on the next
analysis.

This is a *hint, not a dismissal*: the findings still appear and
still score the same. Marking a fingerprint benign tells the next
analyst "this client shape was triaged" — it does not hide the
beacons it belongs to. Use a pair allowlist (tuple-scoped) or a
suppression (destination-scoped) when you actually want the rows
gone; use the fingerprint mark when the *shape* is what you've
cleared but you still want to see where it goes.

**Known-bad C2 fingerprints can't be marked** — Cobalt Strike,
Sliver, Brute Ratel and the rest stay on the wall with no button,
and the server rejects any attempt to allowlist them. A confirmed
C2 fingerprint is never something you mute. Unmark from the
**Benign** section to put a fingerprint back on the wall; nothing
re-analyzes, the row simply returns on the next open.

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
