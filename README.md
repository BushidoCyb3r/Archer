<p align="center">
  <img src="docs/archer-logo-dark-mode.png" alt="Archer — Silent Hunter" width="900">
</p>

# Archer — Network Threat Detection & Analyst Workbench

[![CI](https://github.com/BushidoCyb3r/Archer/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/BushidoCyb3r/Archer/actions/workflows/ci.yml)

Pre-1.0 — see [CHANGELOG.md](CHANGELOG.md) for the current release and the [Versioning](#versioning) section below for the stability contract.

Archer is a self-hosted, open-source network threat detection platform that processes Zeek log files to identify adversarial behaviors including C2 beaconing, data exfiltration, lateral movement, DNS tunneling, malicious TLS fingerprints, and more. It provides a browser-based analyst workbench for reviewing, annotating, and escalating findings — including live threat intelligence enrichment via VirusTotal, CrowdSec, AlienVault OTX, AbuseIPDB, GreyNoise, and Censys.

---

## Table of Contents

- [Features](#features)
- [Detection Coverage](#detection-coverage)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installing Prerequisites](#installing-prerequisites)
- [Quick Start](#quick-start)
- [Try It Locally (Demo)](#try-it-locally-demo)
- [Air-Gapped Installation](#air-gapped-installation)
- [Log File Layout](#log-file-layout)
- [Configuration](#configuration)
- [Threat Intelligence](#threat-intelligence)
- [Quiver Sensors](#quiver-sensors)
- [User Roles](#user-roles)
- [Web Interface](#web-interface)
- [API Reference](#api-reference)
- [Versioning](#versioning)
- [Resetting to Factory State](#resetting-to-factory-state)
- [Running Without Docker](#running-without-docker)
- [Contributors](#contributors)
- [License](#license)

---

## Features

- **Multi-log analysis** — ingests conn, DNS, HTTP, SSL, X.509, files, and notice logs in TSV or JSON/NDJSON format, including gzip-compressed files
- **Spectral beacon rescue** — Lomb-Scargle periodogram over reservoir-sampled timestamps catches bounded-jitter C2 beacons (fixed cadence + random jitter around it) that defeat statistical interval-distribution scoring. DC-corrected `rayleighPower` eliminates finite-window leakage artifacts; a lower-bound plausibility gate (`ivMedian/5`) suppresses burst-structure noise while allowing burst-connect beacons whose true period exceeds `ivMedian`. Gated to only run when the statistical path scored weak, ~4 ms/pair overhead. Calibration knobs in Settings; tuning guide at [docs/SPECTRAL_TUNING.md](docs/SPECTRAL_TUNING.md). Operator validation: `bash corpus-spotcheck.sh`.
- **DGA hostname augmentation** — Beacon / HTTP Beacon scores get a +15 / one-step severity bump when the destination's registrable domain looks algorithmically generated (high Shannon entropy + low English-bigram log-likelihood). Built-in CDN allowlist + operator allowlist suppress legitimate algorithmic hostnames.
- **Cross-detector correlation** — same `(src, dst)` pair carrying findings from ≥N distinct detector types becomes a Correlated Activity roll-up; right-clicking the roll-up row → **Show contributing activity** filters the Findings tab to that `(src, dst)` pair so every contributor plus the roll-up land in one view (each contributor also carries its sibling IDs in the `correlations` API field). Catches kill-chain progression (Beacon + DNS Tunneling, Suspicious File + TI Hit, etc.).
- **Cross-host C2 staging (`Multi-Stage Beacon`)** — binds two or more internal hosts that beacon to the same *rare* external destination with staggered onsets — the "operator lands on A, moves laterally to B, B calls the same C2" pattern that single-pair beacon detection can't see. High-precision gate (rare dst ≤ 6 unique sources, ≥ 2 hosts, onsets clustered within 48h); **HIGH** for a staged cluster, **CRITICAL** when corroborated by a lateral hop between participants, a TI hit on the destination, or a Malicious JA3/JA4 on it. Anchored on patient zero, binds the contributing beacons via the `correlations` field. Complements the Campaigns view (broad fan-in lens) with a narrow conviction; gate with `corpus-spotcheck.sh` Check 8. Detail in [docs/DETECTION_METHODS.md §2.9](docs/DETECTION_METHODS.md).
- **30-day beacon score evolution chart** — **Score Chart** button in the action footer opens a modal showing the composite score + four sub-axes (Timing, Data size, Histogram, Persistence) over the last 30 UTC days, written by `SetFindings` on the first full pass of each day for `Beacon`, `HTTP Beacon`, and `DNS Beacon` finding types. Surfaces whether a beacon is escalating, stable, or decaying. Button is grayed out until at least one daily row exists.
- **Beacon-depth hunting tools** — the composite score averages four axes, so a real implant shape (tight timing, short duration — a staging beacon) can sit below a score floor. The query bar exposes each sub-axis as a numeric field — `tscore` (Timing) / `dscore` (Data size) / `hist` (Histogram) / `dur` (Persistence) — taking comparisons and inclusive `[lo TO hi]` ranges (sub-scores are in `[0, 1]`, e.g. `dur:<=0.3 AND tscore:>=0.9`), turning the score into a queryable signature space; any sub-score predicate implicitly scopes to beacons. A conn-level beacon carries the **JA3/JA4** of its seed connection (lifted from the same `ssl.log` index that resolves the SNI) with a one-click **TLS Pivot** to every beacon sharing the fingerprint (JA4 preferred when the sensor runs the Zeek JA4+ plugin; falls back to JA3) — per-pair detection becomes implant-family attribution. Each conn-level beacon also carries a colour-coded **TLS-fingerprint rarity + cross-host-cluster** row in the detail pane, computed over *all* TLS in the capture (not just emitted beacons) — e.g. `rare — shared by 3 internal hosts · 43 conns, 1 dst(s)`, coloured by concern (red = rare JA4 shared across hosts, through to white = common browser/SDK shape) — so a rare fingerprint shared across several internal hosts to one destination stands out even on a low-scored finding, and the signal survives cloud-hosting because the fingerprint is the malware's, not the host's (enrichment only — never changes score or severity). HTTP beacons carry a **URI footprint** (the request-path set the `(src,dst,host)` group beaconed on, aggregated pre-dedup) — one stable path reads benign, a small fixed set reads C2. **Type → Beacons** scopes the findings view (and the existing export flow) to the whole beacon family. Analyst-facing only — no detection-semantics change. Walkthrough: [docs/ANALYST_PLAYBOOK.md](docs/ANALYST_PLAYBOOK.md).
- **Per-channel beacon scoring** — a conn-level beacon keys on `(sensor, src, dst)`, excluding both port and TLS fingerprint, so two channels to one destination that differ only by JA3 — a chatty CDN/telemetry client and a periodic C2, both on 443 — aggregate into one beacon whose blended score the noisy channel drags down. After the SNI/JA3 index is built, Archer partitions each beacon's connections by JA3 and re-runs the **identical** four-axis + spectral scoring on each channel; any channel that independently clears the emit floor **and** scores strictly higher than the blend is surfaced as its own `Beacon` finding (carrying a `Channel` discriminator and the channel's JA3). It's a **non-destructive overlay** — the blend is always kept, so no detection is lost to fragmentation; a lone dominant channel ≈ the blend and isn't promoted (no duplicate); and Host Risk Score reflects the higher of blend and channels via its max-per-type rule, so a clean CRITICAL C2 hidden inside a merely-MEDIUM blend raises host risk instead of being averaged away. Detection-semantics change (new finding population); gate with `corpus-spotcheck.sh` Check 6. Detail in [docs/DETECTION_METHODS.md §2.8](docs/DETECTION_METHODS.md).
- **TLS Fingerprints inventory** — the top-down counterpart to per-finding TLS Pivot. A **TLS Fingerprints** button (left sidebar, under **Hunt**) opens a modal listing every high-signal JA3/JA4 client fingerprint in the capture, ranked by concern: known-bad C2 matches (always critical) plus rare / cross-host shapes (concern ≥ medium), with common browser/SDK shapes filtered out so it stays a hunt list, not a TLS census. Each row shows the fingerprint, a count-free **Concern** judgment, the prevalence (Hosts / Dest / Conns) and how many findings carry it; clicking a row pivots the Findings tab to all of them. A search box at the top filters both the wall and the Benign list by hash, type, or concern (in-memory, so it's instant). Because it's computed over the same all-`ssl.log` prevalence snapshot as the detail-pane FP-rarity badge — not the emitted-findings set — it surfaces a rare fingerprint that tripped no detector at all (`finding_count: 0`). Backed by `/api/fingerprints`. Heuristic rows carry a **Mark benign** action: a triaged fingerprint (corporate EDR agent, a niche SDK, an internal scanner) drops off the wall into a collapsed **Benign** section (reversible with one click), and findings carrying it are tagged with an `FP Benign` chip rather than dismissed. A **Hide FP Benign** toggle in the query-chip row (next to Show Dismissed) takes that one step further when wanted: it composes `benign:false` into every view so already-triaged-fingerprint findings drop out of sight — a reversible per-browser filter, not a status; the findings still exist, score, and feed Host Risk. Known-bad C2 matches are non-markable — the button is withheld and the server rejects the request — so a confirmed C2 fingerprint can't be muted. Heuristic rows also carry a **Mark malicious** action: it adds the fingerprint to the JA3/JA4 IOC list (`/api/ioc-fingerprint`), so it emits a Malicious JA3/JA4 finding on the next analysis and shows as known-bad on the wall thereafter. Backed by `/api/fingerprint-allowlist`.
- **MITRE ATT&CK mapping** — every finding type maps to the ATT&CK technique(s) it most precisely evidences (a curated table dominated by Command and Control, with a few Exfiltration / Lateral Movement entries). A finding's detail pane shows its technique(s) as chips linking to attack.mitre.org (Beacon → `T1071`, DNS Beacon → `T1071.004`, Domain Fronting → `T1090.004`); the `attack:` query field filters by technique ID, tactic, or name (`attack:T1071` matches the base and its sub-techniques, `attack:"command and control"`, `attack:DNS`); and an **ATT&CK Coverage** button (left sidebar, under **Hunt**) opens a Coverage modal — techniques the current findings evidence, grouped by tactic with counts, clicking one sets the query to just `attack:<id>` and pivots to the Findings tab. Finding types with no precise technique (TI-feed hits, roll-ups like Host Risk Score / Correlated Activity, raw Zeek notices) are intentionally unmapped and listed separately so coverage gaps are explicit. Backed by `/api/attack-coverage`.
- **Bounded memory detection** — beacon analyzers use streaming aggregates and reservoir sampling so peak memory is a function of unique pair count, not total record count; Docker entrypoint auto-derives `GOMEMLIMIT` from the container's cgroup so the Go runtime applies back-pressure before OOM
- **Persistent findings** — findings survive restarts, rebuilds, and re-analyses; analyst annotations (status, notes, assignee) are carried over by fingerprint match; findings are preserved even when the logs that produced them are later archived, and are only removed when an admin explicitly prunes them
- **Delta detection** — the "New only" filter shows findings first detected since you last logged in, so analysts can focus on what's new to them — not just the most recent run
- **Findings trend chart** — a collapsible full-width panel between the query bar and the findings table charts per-day finding counts over the whole log period, with two lenses on the same axis: **Families** (one line per detection family — Beaconing, Threat Intel, Exfil, DNS, Lateral, TLS/Cert, Other) and **Severity** (one line per tier, coloured by the severity tokens). It follows the active query/tab/filters exactly (same server-side filter surface as the table), so zooming a hunt shows that hunt's shape over time. Legend chips toggle lines, hovering reads exact per-day counts, and dragging the canvas zooms an x range — **Apply as filter** then writes the zoomed window into the query box as a `ts:[from TO to]` token and runs it. Hand-drawn theme-aware canvas, no chart library — works air-gapped like everything else
- **Raw-log pivot** — clicking a finding opens a Source Records dialog that scans the original Zeek logs (plus the archive) for matching records and renders the full standard schema with resizable, horizontally-scrollable columns; one-click **Export CSV** flattens every loaded record (with a leading `_log_type` column) for offline analysis
- **In-app campaign graph** — right-click any campaign and pick **View campaign in Graph** to render a force-directed network graph of the involved hosts and destination, severity-coloured and sized by finding volume; clicking a node jumps the findings table to that IP
- **Query language** — the query bar is the primary findings filter: Lucene-style field terms (`id:`, `type:`, `severity:`, `src:`/`dst:` IP, CIDR, or a space keyword — `rfc1918`/`private` (internal) or `public`/`external`, `dir:` traffic direction, `port:`, `sensor:`, `hostname:`, `uri:`, `service:`, `detail:`, `note:`, `analyst:`, `status:`, `ja3:`/`ja4:`, `file:`, `attack:` (MITRE ATT&CK technique / tactic)), boolean `AND` / `OR` / `NOT` with `()` grouping (an operator is required between terms — `type:Beacon AND severity:high`, not `type:Beacon severity:high`), leading/trailing wildcards (`dst:185.220.*`), numeric comparisons and ranges (`score:>=90`, `score:[80 TO 100]`), date windows on event time (`ts:>=2026-03-15`) and first-detected time (`detected:>=2026-06-01`), the booleans `ioc:` / `spectral:` / `channel:` / `benign:`, the beacon sub-scores `tscore:` / `dscore:` / `hist:` / `dur:`, the beacon timing/volume metrics `conns:` / `meanint:` / `medint:` / `jitter:`, and the outbound/inbound byte ratio `outratio:` (conn-derived beacons and Data Exfiltration). A bare word is a case-insensitive substring match (a bare IP matches src or dst). Evaluated server-side and ANDed on top of the active view; a bad query — malformed syntax, an unknown field (`dest:` for `dst:`), a misspelled finding type (`type:Beaon`), or a missing operator between terms — drops a red toast in from the top of the page with the reason rather than silently matching everything or nothing. A **Hunts ▾** chip ships prebuilt expressions for the shapes worth looking at first — nine beacon-variety lenses (textbook check-in, tasking channel, jitter-evading/spectral, clockwork, scheduled/fixed-hour, low-and-slow, persistent, DGA-backed, port-hopping) and six threat-signature sweeps — each replacing the box with a complete, editable query. Full reference in [docs/ANALYST_PLAYBOOK.md](docs/ANALYST_PLAYBOOK.md#querying-the-findings-table).
- **Virtualized findings table** — the table renders only what's on screen, so result sets of any size stay smooth without truncation
- **Per-tab exports** — every tab has its own CSV and JSON export. Findings/Acknowledged/Escalated/IOC Hits export only the visible subset (server-side, honoring all active filters). Campaigns and Hosts export their aggregations directly. A separate "All" export grabs every finding in the database. Right-click any single campaign row to export just that one campaign — useful for loading into a graphical viewer for stakeholder presentations.
- **Log archive & retention** — admin-configurable: files older than N days automatically move from `/logs` to `/data/archive` after each watch analysis; findings are preserved by default (or optionally pruned past the same cutoff)
- **Dataset fingerprint skip** — watch-mode re-analyses short-circuit when the set of files + their sizes + mtimes is unchanged from the last successful run; recurring runs over a static dataset return in milliseconds (matters more once you tighten the cadence dropdown to hourly)
- **Preflight memory warning** — before each run Archer compares the total log size against `GOMEMLIMIT` and surfaces a status-bar warning when the run is projected to approach or exceed the budget
- **Live threat intelligence** — manual escalation queries VirusTotal, CrowdSec CTI, AlienVault OTX, AbuseIPDB, GreyNoise (Community API works without a key), and Censys; results are consolidated into a single TI Enrichment note per escalation (per-IP grouping with hit/clean indicators), with live SSE toasts as each lookup completes
- **SIEM forwarding** — when a SIEM is configured (Settings → SIEM forwarding), escalating a finding also forwards a compact record of it as **bare CEF over UDP** (port 9003 by default), so a separate analyst can triage and pivot in the SIEM. Carries the 5-tuple, score, detector, detail line, destination domain, MITRE ATT&CK technique, IOC/TI source, event time, and a deep-link back to the finding; heavier evidence stays in Archer. Best-effort and additive — escalation behaves exactly as before when no SIEM is set. Validated against Security Onion (reuses its CEF Elastic Fleet integration); setup: [docs/SECURITY_ONION.md](docs/SECURITY_ONION.md).
- **Archive IOC scan** — admin-triggered retroactive scan over `/data/archive` against the current IOC list and TI feeds (Feodo / URLhaus / Suspicious URL); skips the heavy beacon/exfil/lateral phases so a 100+ GB archive scans in minutes. New IOC matches surface as findings exactly like a regular run; existing analyst state is preserved by fingerprint merge.
- **Cell-aware right-click menu** — click-anchor arrow at one of the menu's four corners (↖↗↙↘) points back at the click point regardless of which way the menu had to flip to fit the viewport; column-aware items (Pivot / Lookup / Add to Allowlist / Add to IOC) adapt to whichever IP cell was clicked so there's no Src-vs-Dst picker; state-aware disabling (Acknowledge greys for already-acked findings, "Add to IOC" greys when the IP's already on the list); tab-aware (Acknowledge / Escalate / Suppress hidden on Campaigns and Hosts tabs since those operate on synthesised aggregate rows, not findings; **Add to Allowlist / Add to IOC stay available on the Campaigns tab** — they act on the right-clicked destination IP, not a finding's status, so a campaign's dst is a valid list target; Hosts is excluded since its rows are internal RFC1918 IPs where allowlisting/IOC-listing is a footgun); role-gated (write actions hidden for viewers); 8 external-lookup destinations (VT, AbuseIPDB, Shodan, CrowdSec, Censys, GreyNoise, URLscan.io, OTX); **Show contributing activity** on Correlated Activity rows filters the Findings tab on the CA's `(src, dst)` pair so the analyst sees the roll-up, every contributor, and any newer activity on the same pair in one view; **Pivot** on any aggregate row (Campaigns / Hosts / Dismissed-Campaigns) routes to the Findings tab and filters on the right-clicked IP — an in-place filter is a no-op on a roll-up panel, so Pivot's intent there is "show me every finding for this IP" (Lookup stays hidden on Hosts since its rows are always internal RFC1918 addresses).
- **Tabbed detail dock** — Shared across all tabs (Findings, Acknowledged, Escalated, IOC, Campaigns, Hosts) — the bottom detail pane is a Detail / Notes / TI Results tab strip with persistent action footer (Ack / Esc / Dismiss / Beacon Chart / Score Chart / PCAP / Source Records / TLS Pivot / Suppress) that stays visible when the dock is collapsed. Notes partition on author so analyst notes stay in Notes and machine-emitted TI Enrichment notes route to TI Results — tab badges show counts. 1/2/3 keyboard shortcuts flip tabs when focus isn't in an input. **↑ / ↓ arrow keys** step through findings in the current sort order when a row is selected — the table scrolls to keep the selection centred and the detail pane updates; suppressed when focus is inside a text input. The dock collapses to a header strip via the chevron; the collapse preference persists. **Drag-to-resize** on the top edge sets a height between 120px and 80% of the viewport, persisted across reloads. The active panel scrolls only when its content overflows; otherwise the dock fits its content. For `Beacon` / `HTTP Beacon` / `DNS Beacon` findings the Detail tab leads with a **structured triage header** — jitter %, "every 47s ± 3s", median interval, sample size, and the per-axis sub-score breakdown — so the confidence signal is readable in the first five seconds without parsing the raw Detail string. When a conn-level beacon went over TLS the header carries its **JA4** (preferred) or **JA3** with a "matched N other beacons" sibling count (the **TLS Pivot** footer button filters to them); HTTP beacons show the **Beacon paths on `<host>`** footprint (the request-path set the group beaconed on, count-descending).
- **Dismiss as a reversible bucket** — fourth status alongside Open, Acknowledged, Escalated. Hides the finding from every standard view (Findings, Acknowledged, Escalated, IOC, Campaigns, Hosts) without committing to the heavier Acknowledge semantic. A dedicated Dismissed top-level tab with Findings + Campaigns sub-tabs shows what's been dismissed; sub-tabs sit directly below the main tab strip so the hierarchy reads top-down. **Bulk-dismiss on Campaigns rows** — right-click a campaign aggregate to dismiss every open finding in that campaign with a shared note. Hosts is intentionally exempt — bulk-dismissing a source IP's findings would erase the host's risk story.
- **Allowlist-aware bell** — adding an IP to the allowlist (or applying a suppression) dismisses any active bell notification whose src/dst is now hidden, in lockstep with the matcher update. New notifications skip the bell entirely when src/dst is allowlisted or suppressed — the bell only rings for findings whose row will actually appear in the table.
- **Score Chart button** — **Score Chart** in the action footer opens the 30-day beacon score evolution modal for `Beacon` / `HTTP Beacon` / `DNS Beacon` findings. Button is grayed out until at least one daily history row exists for the finding. Modal renders composite score + four sub-axes (Timing, Data size, Histogram, Persistence) as SVG with a legend embedded in the chart. PNG / JPEG export includes the legend. Pure client-side serialization (SVG → canvas → toDataURL); no extra round trip.
- **Findings export (TXT)** — Export TXT button on the tab strip produces a self-contained plain-text file from whatever is in the detail dock: a finding's metadata header, Detail body, TI Results, and analyst notes when a single finding is selected; a composite summary with full contact set and TI Results when a host or campaign pivot is open. Filename is `archer-finding-{id}.txt` for individual findings, `archer-host-{ip}-{ts}.txt` / `archer-campaign-{label}-{ts}.txt` for pivots.
- **Admin DB backup** — Settings → Admin → Backup → Download DB backup streams a consistent `VACUUM INTO` snapshot of the live SQLite database with a timestamped filename. The snapshot covers findings, notes, audit log, sensor enrollments, allowlist / IOC / suppressions, and users. Audit-logged as `db_backup`. For scripted rotation use `./backup.sh` (drives the same endpoint, writes timestamped snapshots, optional retention + rsync off-box); `./restore.sh <snapshot.db>` swaps a snapshot back in with the container stopped.
- **Automatic free TI feeds** — Feodo Tracker C2 IPs and URLhaus malware hosts are fetched and cross-referenced during every analysis run without requiring API keys
- **Internal MISP / OpenCTI support** — per-feed `Allow internal address` opt-out lets operators point Archer at an internal MISP at e.g. `https://10.0.0.17/` without falling foul of the SSRF guard. Per-feed scope; other feeds keep the guard. Both the config-time check and the fetch-time redirect guard honor the flag for the same feed. Audit-logged on every toggle.
- **Feed aging visibility** — the Feeds dialog shows a per-feed `X% aged` line under the aging-days knob: the share of the pre-prune population the last full refresh removed (hover for absolute counts). Makes the per-feed `indicator_aging_days` window calibratable — too tight discards still-live upstream indicators every cycle; never pruning means it's looser than upstream churn.
- **Role-based access control** — admin, analyst, and viewer roles with per-endpoint enforcement
- **Analyst workbench** — acknowledge, escalate, suppress, add notes, and copy tcpdump/Suricata filter strings directly from the UI
- **Watch mode** — admin-configurable scheduled analysis. Cadence dropdown (Daily / Every 12h / Every 6h / Every 4h / Hourly) lets you tighten the loop to match Quiver's hourly shipping rather than waiting for a once-a-day window. Anchor time + IANA timezone persist independently of the enable/disable toggle. **Two-tier execution:** the first watch tick of each UTC day runs the full analysis pipeline (statistical detectors need the long temporal window for beaconing, HTTP analysis, etc.); subsequent same-day ticks run an incremental TI/IOC pass over only the log files modified since the last run — typically seconds instead of the full-window minutes-to-hours. The archive worker runs after both full and incremental ticks when archive is enabled — not only after the daily full pass.
- **Disk-usage telemetry** — `/api/disk-usage` walks `/logs` per-sensor, totals `/data/archive`, and reports free space on each volume (5-minute server-side cache). Surfaces in Settings → Operations → Log Archive (full per-sensor breakdown) and the Sensors modal (Size column). Low-disk banner appears at the top of the page when any tracked volume drops below 10% free.
- **Detector health** — `/api/detector-activity` counts new findings per type over the last 7 days vs the prior 7 (keyed on `detected_at`). A detector that was firing and went silent this week is flagged — the earliest sign a sensor stopped shipping a log type or a Zeek policy fell out, before the gap surfaces as findings an analyst would have to notice were missing. Surfaces in Settings → Operations → Detector Health (dropped detectors highlighted and sorted first).
- **Quiver sensors** — optional companion agent that ships Zeek logs from any Linux sensor host into Archer over rsync-on-ssh. Enrollment is one curl one-liner per sensor (TLS-pinned), pubkey-pinned per-sensor authorized_keys, hourly randomized push window, live Sensors modal showing health/missed-slot status, single-step disenroll + log-tree purge. Auto-installs prerequisites on Debian/Ubuntu/RHEL/Oracle/Rocky/Alma/SLES/Alpine. See [docs/QUIVER.md](docs/QUIVER.md) for the full operator guide.
- **Campaign & host views** — left-click any Campaigns row to open a **campaign pivot** in the detail dock: a `Campaign [SEVERITY score N] dst:port` banner with a table of every finding for that destination (score, type, src IP, timestamp), sorted score-desc. Left-click any Hosts row to open a **host pivot**: the Host Risk Score banner followed by a **Contact set** table of every network finding for that host (score, type, dst:port, timestamp). Clicking a contact row in either pivot renders the full finding detail in the same dock — beacon sub-scores, charts, notes. Right-click any row for the standard export/pivot/lookup menu.
- **Resource-aware deployment** — `start.sh` automatically allocates 80% of host CPU and 70% of host RAM to the container; RAM is held to a tighter cap so burst spikes have absorption headroom before they could OOM-kill the container. The entrypoint then wires the Go runtime memory limit to 90% of whatever budget it gets

---

## Detection Coverage

Archer runs five parallel analysis phases across all supported log types.

### Network Connections (`conn.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **Beacon** | Statistically regular connections to an external host — multi-dimensional scoring using inter-arrival time regularity (Bowley skewness + MAD), data size consistency, circadian histogram (hour-of-day coverage across 24 clock-hour buckets), and temporal persistence across a bounded trailing window (most recent 7 days, so the score doesn't erode as log retention grows). When a beacon blends multiple TLS channels (distinct JA3s to one dst), a sharper hidden channel is additionally surfaced as its own `Beacon` carrying a `Channel` discriminator — see **Per-channel beacon scoring** above and DETECTION_METHODS §2.8 | CRITICAL / HIGH |
| **Port-Hopping Beacon** | A `Beacon` (above) that spreads across many destination ports with no dominant one — the "rotate the callback port to dodge a port rule" evasion. The beacon key excludes the port, so these are already caught as one beacon; this is a downstream relabel when the pair spans ≥ 5 destination ports and no single port carries ≥ 50% of its connections. Identical scoring, sub-scores, beacon history, host-risk weight, and beacon-family UI (Beacon Chart, Score Chart, triage header) as the `Beacon` it was — it just names the shape. | CRITICAL / HIGH |
| **Strobe** | High-rate connections to a single destination — indicative of port scanning or automated tooling. Both a count floor (default: ≥ 100) and a rate gate (default: ≥ 0.5 conn/s) must be met. Rate-gating ensures that a slow C2 beacon observed over a long capture window is not misclassified as a Strobe. | HIGH |
| **Data Exfiltration** | Large outbound transfer (default: ≥ 5 MB) with a high outbound/inbound ratio (default: ≥ 10:1) | HIGH |
| **Lateral Movement** | Internal-to-internal traffic on administrative ports: SMB (445), RDP (3389), WMI (135), WinRM (5985/5986), SSH (22), Telnet (23), VNC (5900) | HIGH |
| **Protocol on Unexpected Port** | Zeek's dynamic protocol detection (DPD) identified an app-layer protocol (`http`, `ssl`, `ssh`, `dns`, `smtp`, `ftp`) egressing to an external host on a port outside that protocol's expected set — `http` on 8443, `ssl` on 4444. Catches port-control evasion a port-only view misses; the DPD service is stamped on the finding and queryable as `service:`. External destinations only; recognized protocols only (an empty DPD service never fires). Score 70, bumped to 75 on a known C2 port. See DETECTION_METHODS §8 | HIGH |
| **C2 Port** | Connection to an external host on a known C2 / RAT default port (the curated `KnownC2Ports` set: Metasploit 4444/4445, Radmin 4899, IRC/C2 6666–6669, Tor 9001/9030, Back Orifice 31337, SOCKS/HTTP proxy 1080/3128/8008/8888). Port-only — unlike Protocol on Unexpected Port it needs no DPD service. External destinations only. Score 75. See DETECTION_METHODS §8 | HIGH |
| **Off-Hours Transfer** | External data transfer outside configured business hours (default: 22:00–06:00 in the configured `timezone`, UTC when unset) exceeding the configured threshold | MEDIUM |
| **Long Connection** | TCP/UDP session duration exceeding the configured minimum (default: 1 hour) — indicative of reverse shells and VPN tunnels | MEDIUM / HIGH / CRITICAL |

### DNS (`dns.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **DNS Tunneling** | High-entropy, long DNS labels (default: > 40 chars, entropy > 3.5) with deep nesting (default: > 5 levels) — detects iodine, DNScat2, dns2tcp | HIGH |
| **DNS Subdomain DGA** | A high count of unique subdomains under one apex per source (default: ≥ 50) — the exfil/DGA fan-out shape, distinct from the entropy-keyed Tunneling and the low-diversity DNS Beacon cadence. Score scales with average subdomain entropy; HIGH once that average exceeds 3.0, MEDIUM otherwise | MEDIUM / HIGH |
| **DNS NXDOMAIN Flood** | High rate of non-existent domain responses (default: ≥ 200) — indicative of DGA-based malware | HIGH |
| **DNS Beacon** | Regular-cadence query timing on a `(source, apex)` key — the Cobalt-Strike DNS-C2 heartbeat that slips both DNS Tunneling (labels too short/low-entropy, diversity too low) and conn-level Beacon (IP-pair keyed, no `conn.log`). Reuses the conn-level timing + Lomb-Scargle spectral pipeline; scored timing 0.5 / inverse-subdomain-diversity 0.25 / window-coverage 0.25. Diversity gate defers high-diversity apexes to DNS Tunneling; NXDOMAIN-dominated streams defer to NXDOMAIN Flood; built-in CDN + operator allowlist suppress benign apexes. Min queries default 20. | CRITICAL / HIGH |
| **Suspicious TLD** | Queries to free or commonly abused TLDs: `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.top`, `.xyz`, `.pw`, `.cc`, `.to`, and others | MEDIUM |
| **DoH Bypass** | DNS-over-HTTPS queries to known public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9, etc.) on port 443 — malware evading DNS logging and response policy zones | MEDIUM |

### HTTP (`http.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **HTTP Beacon** | Same multi-dimensional beacon scoring applied to HTTP request patterns per (source, host, URI) triple — catches C2 over CDN infrastructure where multiple IPs share one domain | CRITICAL / HIGH |
| **Cobalt Strike URI** | Checksum8 algorithm match: URI byte sum modulo 256 equals 92 (x86 stager) or 93 (x64 stager) | CRITICAL |
| **C2 URI Pattern** | Regex match against default framework URI patterns: Cobalt Strike (`/submit.php`, `/ca`, `/dpixel`, `/pixel.gif`, `/ptj`, `/j.ad`, `/updates.rss`), Empire (`/news.php`, `/admin/get.php`, `/login/process.php`), Metasploit (8-character alphanumeric stager paths) | CRITICAL |
| **Domain Fronting** | SSL SNI does not match HTTP Host header — CDN abuse used to hide C2 destination | CRITICAL |
| **Suspicious UA** | Scripting and automation user agents: python-requests, curl, wget, go-http-client, PowerShell, libwww-perl | LOW |
| **Suspicious File Download** | Executable MIME types (`application/x-dosexec`, `application/x-elf`, etc.) or executable extensions (`.exe`, `.dll`, `.ps1`, `.vbs`, `.bat`, `.hta`, `.scr`, `.sh`, `.elf`, `.msi`) | HIGH |

### TLS / SSL (`ssl.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **Malicious JA3** | TLS ClientHello fingerprint (MD5 hash) matches known C2 frameworks: Cobalt Strike (multiple profiles), Metasploit, Sliver, Brute Ratel — or an operator-supplied hash from the JA3/JA4 IOC list. Requires sensor Zeek JA3 script (stock). | CRITICAL |
| **Malicious JA4** | TLS ClientHello fingerprint (JA4 structured format) matches known C2 malware: Cobalt Strike v4.9.1 (wininet/winhttp, SNI/no-SNI variants), IcedID loader. Source: FoxIO public JA4+ database. Requires sensor running Zeek JA4+ plugin. | CRITICAL |
| **SSL No-SNI on C2 Port** | Established TLS connection with no SNI on known C2 ports (4444, 4899, 6666–6669, 8008, 8888, 9001, 9030, 31337) | HIGH |
| **SSL No-SNI** | Established TLS connection with no SNI on standard ports — supporting indicator | LOW |

### X.509 Certificates (`x509.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **Suspicious Certificate** | Self-signed certificates (subject equals issuer), generic or default subject strings, or anomalous validity windows (< 48 hours or > 10 years) | MEDIUM |

### Zeek Notices (`notice.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **Zeek Notice** | Detections from Zeek policy scripts: `Sensitive_Signature`, `Scan`, `Attack`, `Brute_Force` | CRITICAL / HIGH |

### Threat Intelligence

| Detection Type | Description | Severity |
|---|---|---|
| **TI Hit (IP)** | Source or destination IP matched against Feodo Tracker C2 IPs, URLhaus malware-distribution IPs, OTX / AbuseIPDB lookups, or any configured MISP/OpenCTI feed's IP/CIDR indicators during analysis; or confirmed malicious by a TI service during analyst escalation | CRITICAL (built-in feeds) / HIGH (MISP/OpenCTI feeds) |
| **TI Hit (Domain)** | DNS query name or HTTP host matched against URLhaus malware-distribution domains or any configured MISP/OpenCTI feed's domain indicators | CRITICAL (URLhaus) / HIGH (MISP/OpenCTI feeds) |
| **TI Hit (Hash)** | `files.log` md5 / sha1 / sha256 matched against any configured MISP/OpenCTI feed's hash indicators. Only fires when Zeek's hashing analyzers are loaded *and* the file traverses an unencrypted protocol Zeek can reassemble (HTTP, SMB, FTP, SMTP, IRC) — see [docs/FEEDS.md](docs/FEEDS.md) for the full coverage map | HIGH |
| **Suspicious URL** | HTTP destination host matched against URLhaus malware distribution hosts or any configured MISP/OpenCTI feed's domain indicators | CRITICAL (URLhaus) / HIGH (MISP/OpenCTI feeds) |

For MISP/OpenCTI integration — adding a feed, configuration options, the per-feed TLS-verify bypass, indicator types that match (and ones that don't), aging behavior, and troubleshooting — see **[docs/FEEDS.md](docs/FEEDS.md)**. Feeds are admin-curated through the Feeds topbar dialog; findings carry per-feed provenance via the `SourceFile: feed:<name>` field.

For the analyst-side workflow — how to actually hunt with these findings, what modern C2 tradecraft looks like in 2026, the eight-question triage checklist, worked examples (textbook benign, textbook malicious, realistic ambiguous, slow-burn exfil), false-positive patterns, escalation criteria, and detection blind spots — see **[docs/ANALYST_PLAYBOOK.md](docs/ANALYST_PLAYBOOK.md)**. Complements [docs/DETECTION_METHODS.md](docs/DETECTION_METHODS.md) (the math) with operational flow (the hunt).

### Composite Scoring

| Detection Type | Description | Severity |
|---|---|---|
| **Host Risk Score** | Weighted composite score (0–100) aggregated across all findings for a given source IP. Selected weights: Cobalt Strike URI / Malicious JA3 / Malicious JA4 +40, C2 URI Pattern +38, DNS Tunneling / TI Hit (IP/Domain/Hash) +35 each, Domain Fronting +32, Beacon / Port-Hopping Beacon / DNS Beacon / SSL No-SNI on C2 Port / Suspicious URL +30, HTTP Beacon +28, Data Exfiltration / Suspicious File Download / Protocol on Unexpected Port +25, DNS Subdomain DGA / C2 Port +22, Lateral Movement / Suspicious Certificate +20, DNS NXDOMAIN Flood / DoH Bypass +18, Strobe / SSL No-SNI +15, Suspicious UA +12, Long Connection +10. Full table in `docs/DETECTION_METHODS.md §14`. Surfaced in the **Hosts** tab (not the Findings tab — that tab is reserved for discrete network events). Click any host row to open the underlying score breakdown. | CRITICAL / HIGH / MEDIUM / LOW |
| **Correlated Activity** | Same-pair multi-detector roll-up: any `(src, dst)` pair carrying findings from N+ distinct detector types becomes a Correlated Activity row; right-click it → **Show contributing activity** to filter the Findings tab to that `(src, dst)` pair (all contributors + the roll-up row in one view). Score = max(contributor scores) + 5 per extra distinct type above N (capped 99). Excludes roll-ups (HRS recursion, self-feedback), Zeek Notice, and Long Connection from the contributor set. Surfaces kill-chain progression a single detector wouldn't catch alone. | CRITICAL / HIGH / MEDIUM |
| **Multi-Stage Beacon** | Cross-host C2-staging roll-up: ≥ 2 internal hosts beaconing to the **same rare external destination** (≤ 6 distinct sources) with staggered onsets (≤ 48h apart) — the lateral-spread-with-shared-C2 pattern single-pair beacon detection can't see. HIGH when staged; CRITICAL when corroborated by a lateral hop, a TI hit on the destination, or a Malicious JA3/JA4 on it. A roll-up type (purge-when-stale, excluded from Host Risk Score weighting). Complements the broad Campaigns view with a narrow, high-conviction signal. See DETECTION_METHODS and `internal/analysis/stage.go` | CRITICAL / HIGH |

---

## Architecture

```
archer/
├── entrypoint.sh               # sshd host-key bootstrap, /home/quiver/.ssh perms, GOMEMLIMIT, exec archer
├── sshd_config                 # Sensor-facing sshd — pubkey-only, AllowUsers quiver
├── start.sh                    # Resource-sizes the container (80% CPU / 70% RAM), derives version, runs compose
├── reset.sh                    # Operator-confirmed wipe of archer-data / archer-sshd / archer-quiver volumes
├── backup.sh                   # Auth'd VACUUM INTO snapshot via the admin endpoint; optional retention + rsync off-box
├── restore.sh                  # Confirmed swap of a snapshot into archer-data (container down; TLS + other volumes untouched)
├── demo.sh                     # One-command local demo — builds, seeds sample logs, analyzes, serves until Ctrl-C (see Try It Locally)
├── demo/logs/                  # Sample Zeek captures (37 scenarios in a date tree) the demo analyzes
├── cmd/archer/main.go          # Entry point — flags, signal handler, TLS bootstrap, HTTP listener
├── internal/
│   ├── analysis/               # Detection engines
│   │   ├── analyzer.go         # Pipeline orchestration (5 phases, memory-bounded worker pool, pause/cancel)
│   │   ├── conn.go             # Beacon, strobe, exfil, lateral, long-conn (streaming + reservoir)
│   │   ├── dns.go              # Tunneling, NXDOMAIN floods, suspicious TLDs, DoH bypass
│   │   ├── http_analysis.go    # HTTP beaconing, Cobalt Strike, domain fronting, suspicious downloads
│   │   ├── ssl.go              # JA3/JA4, no-SNI, weak TLS; populates sslUIDIndex consumed by HTTP
│   │   ├── x509.go             # Certificate anomalies
│   │   ├── files.go            # Suspicious file downloads + MIME-mismatch
│   │   ├── notice.go           # Zeek notices passthrough with score
│   │   ├── ti.go               # Two-phase TI scan — Phase A dst-only sets per file, Phase B targeted collection
│   │   ├── correlate.go        # Cross-detector correlation roll-up — Correlated Activity (v0.15.0)
│   │   ├── stage.go            # Multi-Stage Beacon — cross-host C2 staging, ≥2 hosts → one rare dst (v0.63.0)
│   │   ├── spectral.go         # Lomb-Scargle periodogram beacon rescue (v0.15.0); see docs/SPECTRAL_TUNING.md
│   │   ├── dga.go              # DGA hostname augmentation (Shannon entropy + English-bigram log-likelihood)
│   │   ├── feedprovider.go     # Indicator-cache snapshot consumed by phase 0 prefetch
│   │   ├── heuristics.go       # Detection-knowledge tables — KnownC2Ports, KnownBadJA3, KnownBadJA4, SuspiciousTLDs, DoHIPs, etc.
│   │   ├── risk.go             # Host Risk Score composite (Phase 4) — unions historical findings
│   │   ├── stats.go            # Math helpers (Bowley skew, MAD, coefficient-of-variation)
│   │   └── types.go            # Internal pipeline types (sslEntry, httpEntry, ProgressEvent)
│   ├── config/config.go        # Tunable thresholds + watch + archive settings with defaults
│   ├── feeds/                  # MISP / OpenCTI subsystem
│   │   ├── types.go            # Feed, Indicator, Adapter interface
│   │   ├── misp.go             # MISP attribute restSearch client + normalizer
│   │   ├── opencti.go          # OpenCTI indicator search client + normalizer
│   │   ├── validate.go         # Indicator-shape validation at the ingest boundary (NEW-28 SSRF/XSS gate)
│   │   ├── sourced.go          # Per-feed typed indicator snapshot consumed by the analyzer hot path
│   │   └── worker.go           # Per-feed scheduler scaffolding (currently dormant — watch tick drives refresh)
│   ├── match/match.go          # Compiled exact + CIDR matcher reused by allowlist, IOC list, feed union
│   ├── model/                  # Finding, Severity, Status, Notification, Note, User, Role types
│   ├── parser/zeeklog.go       # Zeek log reader — TSV + JSON/NDJSON, gzipped or not
│   ├── query/                  # Findings query language — Lucene-style parser + matcher (the q= filter)
│   │   ├── query.go            # Lexer, parser, AST, Parse() / Match()
│   │   ├── term.go             # Leaf predicates — field aliases, known fields, per-field evaluation
│   │   └── match.go            # Field match primitives — IP/CIDR, wildcard glob, numeric, timestamp
│   ├── version/version.go      # Build identifier — Version / Commit / BuildTime via -ldflags -X
│   ├── server/
│   │   ├── server.go           # Route registration + role middleware (any / write / admin)
│   │   ├── auth.go             # Session management, login timing pad
│   │   ├── middleware.go       # requireRole(...)
│   │   ├── handlers_api.go     # Findings list/detail/raw, exports, escalation, analyze kickoff
│   │   ├── handlers_ui.go      # Index template renderer (no-store)
│   │   ├── handlers_sse.go     # /events SSE stream handler
│   │   ├── handlers_quiver.go  # /quiver/install.sh, /api/quiver/enroll, /api/quiver/checkin
│   │   ├── handlers_sensors.go # Sensors-modal endpoints (enroll, disenroll, purge, tokens, schedule)
│   │   ├── handlers_service_tokens.go # /api/service-tokens CRUD; tokenOrSession() accepts X-Archer-Token or session
│   │   ├── handlers_feeds.go   # Feeds CRUD + /api/feeds/{id}/refresh (10-min cap, detached context)
│   │   ├── handlers_audit_log.go # GET /api/audit-log (cursor-paginated)
│   │   ├── handlers_backup.go  # /api/admin/backup — VACUUM INTO snapshot stream
│   │   ├── handlers_beacon_history.go # /api/findings/{id}/history → SVG evolution chart data
│   │   ├── handlers_attack.go  # /api/attack-coverage — MITRE ATT&CK coverage over current findings
│   │   ├── detector_activity.go # /api/detector-activity — per-type new-detection counts (capture-regression signal)
│   │   ├── fingerprints.go     # /api/fingerprints — ranked TLS-fingerprint inventory (the TLS wall)
│   │   ├── fingerprint_allowlist.go # /api/fingerprint-allowlist — mark a JA3/JA4 benign
│   │   ├── ioc_fingerprints.go # /api/ioc?kind=fp + /api/ioc-fingerprint — operator JA3/JA4 IOC list
│   │   ├── findings_filter.go  # Shared query-param filter for list + exports; runs the Lucene q= query (internal/query)
│   │   ├── findings_raw.go     # Raw-log pivot — finds source records for a finding
│   │   ├── exports_xlsx.go     # XLSX export path
│   │   ├── archive.go          # Aged-log archive worker + finding prune
│   │   ├── disk_usage.go       # /api/disk-usage with 5-minute server-side cache
│   │   ├── watch.go            # Watch scheduler — two-tier cadence, dataset fingerprint skip
│   │   ├── watch_heartbeat.go  # watch.heartbeat SSE tick (60s) for the top-bar dot
│   │   ├── sensor_heartbeat.go # Sensor staleness scan, /api/sensors/health, stale + rsync-dead alarms
│   │   ├── feed_health.go      # Feed reliability alarm — ≥3 consecutive failures or 24h staleness
│   │   ├── ti_crossnote.go     # TI cross-annotation — pointer-notes onto sibling findings
│   │   ├── audit.go            # Audit emission helpers; audit_log writes
│   │   ├── audit_actions.go    # Canonical audit-action vocabulary
│   │   ├── tls.go              # Auto-gen self-signed cert (ECDSA P-256; Ed25519 auto-upgrade for pre-v0.14.6)
│   │   ├── authorized_keys.go  # Per-sensor authorized_keys rewrite with rrsync command-forcing
│   │   ├── rate_limit.go       # IPv6 /64-aware token-bucket limiter on login + register
│   │   ├── quiver_protocol.go  # Quiver protocol version negotiation
│   │   ├── quiver_hmac.go      # Quiver enrollment HMAC
│   │   ├── json_decode.go      # Strict-JSON decoder helpers (unknown-field rejection)
│   │   ├── sse_broker.go       # Pub/sub broker — Publish(SSEEvent) fans out to subscribers
│   │   └── quiver_assets/      # Embedded sensor scripts (install.sh, quiver.sh, quiver-uninstall.sh)
│   └── store/
│       ├── store.go            # Findings (fingerprint-merge), allowlist, IOC, suppressions, config, watch state
│       ├── sensors.go          # sensors, enrollment_tokens, unauthorized_attempts
│       ├── service_tokens.go   # service_tokens table — create/list/delete, X-Archer-Token verification
│       ├── feeds.go            # feeds, feed_indicators, consecutive_failures
│       ├── audit_log.go        # audit_log table with structured before/after JSON
│       ├── beacon_history.go   # beacon_history table (UPSERT) for the 30-day evolution chart
│       ├── userstore.go        # User accounts, sessions
│       ├── migrate.go          # Forward-only migration runner; tracks schema_migrations
│       └── migrations/         # NNNN_*.sql migrations (0001 → 0036)
└── web/
    ├── templates/
    │   ├── index.html          # Single-page application shell
    │   ├── login.html          # Standalone sign-in page
    │   └── register.html       # Standalone first-user / new-user registration page
    └── static/
        ├── css/themes.css      # Per-skin design tokens (:root[data-theme])
        ├── css/archer.css      # Component styles (consume the tokens)
        └── js/
            ├── app.js          # Main application state machine
            ├── sse.js          # SSE client with auto-reconnect
            ├── notifications.js # Bell UI + SSE-driven updates
            ├── detail.js       # Finding detail pane renderer (Detail / Notes / TI Results tabs)
            ├── table.js        # Findings table — virtual scrolling, sort
            ├── chart.js        # Beacon inter-arrival time chart
            ├── trend.js        # Findings-over-time chart (family / severity lenses)
            ├── beacon_evolution.js # 30-day SVG evolution chart + PNG/JPEG export modal
            ├── campaigns.js    # Campaign aggregation view
            ├── sensors.js      # Sensors modal — enrolled, tokens, unauthorized, health
            ├── feeds.js        # Feeds modal — MISP/OpenCTI feed config + status
            ├── rowmenu.js      # Shared kebab (⋮) popover for Feeds + Sensors row actions (v0.19.0)
            ├── audit_log.js    # Audit log table
            ├── attack.js       # ATT&CK Coverage modal (techniques grouped by tactic)
            ├── fingerprints.js # TLS Fingerprints wall — JA3/JA4 inventory + mark-benign
            ├── graph.js        # In-app campaign graph (Cytoscape wrapper)
            ├── cytoscape.min.js # Vendored Cytoscape.js (MIT, lazy-loaded)
            ├── dialog.js       # DlgManager — drag-by-header for every <dialog>
            └── resize.js       # Detail-dock drag-to-resize
```

All state is persisted in a single SQLite database at `/data/archer.db`. There are no external service dependencies at runtime beyond optional TI API keys.

---

## Requirements

- **Docker** and **Docker Compose** (recommended deployment method)
- OR **Go 1.25+** for building and running from source without Docker

---

## Installing Prerequisites

### Docker and Docker Compose

Docker is required for the recommended deployment path. Docker Compose is included with Docker Desktop on Mac and Windows, and is installed as a plugin on Linux.

#### Ubuntu / Kali Linux

```bash
# Add Docker's official GPG key
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to apt sources
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update

# Install Docker Engine and Compose plugin
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
sudo systemctl enable --now docker
```

> **Kali Linux note:** Kali is Ubuntu/Debian-based. If `UBUNTU_CODENAME` is not set in `/etc/os-release`, the sources entry will fall back to `VERSION_CODENAME`. If the repository step fails, replace the `Suites:` value manually with the current Ubuntu LTS codename (e.g. `noble`).

#### Debian

```bash
# Add Docker's official GPG key
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to apt sources
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: $(. /etc/os-release && echo "$VERSION_CODENAME")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update

# Install Docker Engine and Compose plugin
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
sudo systemctl enable --now docker
```

#### Fedora

```bash
# Add the Docker repository
sudo dnf config-manager addrepo --from-repofile https://download.docker.com/linux/fedora/docker-ce.repo

# Install Docker Engine and Compose plugin
sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
sudo systemctl enable --now docker
```

> **Fedora note:** When prompted during installation, verify the GPG key fingerprint matches `060A 61C5 1B55 8A7F 742B 77AA C52F EB6B 621E 9F35` before accepting.

#### RHEL / Rocky Linux

```bash
# Remove any conflicting older packages
sudo dnf remove docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine podman runc

# Install the dnf plugin manager
sudo dnf -y install dnf-plugins-core

# Add the Docker repository
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo

# Install Docker Engine and Compose plugin
sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
sudo systemctl enable --now docker

# Verify
sudo docker run hello-world
```

> **Rocky Linux / AlmaLinux note:** These are RHEL-compatible rebuilds, so the RHEL repository above is the correct one to use. If `dnf config-manager` is not found, install it with `sudo dnf -y install dnf-plugins-core` first. When prompted during installation, accept the Docker GPG key only after verifying the fingerprint matches `060A 61C5 1B55 8A7F 742B 77AA C52F EB6B 621E 9F35`.

#### macOS

Docker Desktop for Mac includes Docker Engine, Docker Compose, and a GUI dashboard.

1. Download Docker Desktop from the official Docker website: `https://www.docker.com/products/docker-desktop/`
   - Choose **Mac with Apple Silicon** (M1/M2/M3/M4) or **Mac with Intel Chip** depending on your hardware
2. Open the downloaded `.dmg` file and drag **Docker** to your Applications folder
3. Launch **Docker** from Applications
4. Accept the terms of service and wait for Docker to finish starting — the whale icon in the menu bar will stop animating when ready

Verify from a terminal:

```bash
docker --version
docker compose version
```

> **Note:** On macOS, `start.sh` calls `sudo docker compose`. Docker Desktop on Mac does not require `sudo` for most operations, but the script will still work — macOS will simply ask for your password if needed.

#### Windows

Docker Desktop for Windows includes Docker Engine and Docker Compose.

**System requirements:**
- Windows 10 64-bit (version 22H2 or later) or Windows 11
- WSL 2 (Windows Subsystem for Linux 2) — required and installed automatically by Docker Desktop

**Installation steps:**

1. Download Docker Desktop from the official Docker website: `https://www.docker.com/products/docker-desktop/`
   - Choose **Docker Desktop for Windows**
2. Run the installer (`Docker Desktop Installer.exe`)
3. When prompted, ensure **Use WSL 2 instead of Hyper-V** is checked (recommended)
4. Follow the installer prompts and restart your computer when asked
5. After restart, launch **Docker Desktop** from the Start menu and wait for it to finish initializing

**Enable WSL 2 (if not already enabled):**

Open PowerShell as Administrator and run:

```powershell
wsl --install
wsl --set-default-version 2
```

Restart your computer after this step.

**Running Archer on Windows:**

Archer's shell scripts (`start.sh`, `reset.sh`) are written for Bash. On Windows, run them from inside a **WSL 2 terminal** (Ubuntu or Debian recommended):

```bash
# Inside a WSL 2 terminal
cd /mnt/c/path/to/Archer
sudo ./start.sh
```

Alternatively, run Docker Compose commands directly from PowerShell or Command Prompt:

```powershell
docker compose up -d --build
```

Verify from PowerShell or Command Prompt:

```powershell
docker --version
docker compose version
```

---

#### Verify Docker on Linux

```bash
docker --version
docker compose version
```

You should see output similar to:

```
Docker version 26.1.0, build 6e0c0c5
Docker Compose version v2.27.0
```

#### Optional: run Docker without sudo (Linux only)

By default, Docker on Linux requires `sudo`. To allow your user to run Docker commands without it:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

Log out and back in for the group change to take full effect. Note that `start.sh` still uses `sudo docker compose` explicitly for compatibility — this step is optional.

---

### Go (only needed if running without Docker)

Go is only required if you want to build and run Archer directly on the host without Docker.

#### Linux (all distributions)

```bash
# Download the latest Go release (check https://go.dev/dl/ for the current version)
curl -LO https://go.dev/dl/go1.25.0.linux-amd64.tar.gz

# Remove any previous Go installation and extract the new one
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz

# Add Go to your PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile
```

For ARM64 systems (e.g. Raspberry Pi, Apple Silicon in a Linux VM), replace `amd64` with `arm64` in the download URL.

#### macOS

The easiest method on macOS is Homebrew:

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Go
brew install go
```

Alternatively, download the `.pkg` installer directly from `https://go.dev/dl/` and run it — Go will be installed to `/usr/local/go` and added to your PATH automatically.

#### Windows

1. Download the Windows installer (`.msi`) from `https://go.dev/dl/`
   - Choose the `windows-amd64` package
2. Run the installer and follow the prompts — Go is installed to `C:\Program Files\Go` and added to your PATH automatically
3. Open a new Command Prompt or PowerShell window for the PATH change to take effect

To build Archer on Windows, use the **Developer PowerShell** or a WSL 2 terminal:

```powershell
go build -o archer.exe ./cmd/archer
```

#### Verify the installation

```bash
go version
```

Expected output:

```
go version go1.25.0 linux/amd64
```

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/BushidoCyb3r/Archer.git
cd Archer
```

### 2. Place your Zeek logs

Archer expects logs in the `logs/` directory **inside the cloned repository folder on the host machine**. Docker bind-mounts this directory into the container at `/logs` — any files you place there are immediately visible to Archer without a rebuild or restart.

```
/home/user/Archer/          ← cloned repo on the host
└── logs/                   ← place your Zeek logs here
    ├── campaign-apt29/
    │   ├── conn.log
    │   ├── dns.log
    │   ├── http.log
    │   └── ssl.log
    └── campaign-lateral-2026/
        ├── conn.log.gz
        └── dns.log.gz
```

Each subdirectory under `logs/` is treated as a distinct **sensor** (or, for hand-imported datasets, the directory name is the sensor label) and is shown as such throughout the UI. Files can be uncompressed (`.log`) or gzip-compressed (`.log.gz`, `.gz`). Quiver-enrolled sensors automatically populate `logs/<sensor-name>/YYYY-MM-DD/...` via rsync — see [Quiver Sensors](#quiver-sensors).

### 3. Start Archer

One command. No configuration required.

```bash
sudo ./start.sh up
```

`start.sh` measures the host (and the Docker daemon's view, in case it's smaller), allocates 80% of available CPU and 70% of available RAM to the container, builds the image, and starts Archer. Drop the tool on a 16 GB laptop and it scales down; drop it on a 256 GB analysis box and it scales up. No env vars to set, no memory values to guess. The summary at the end prints the host's actual reachable IP (from the default-route source address) so the URL is paste-ready for analysts on the same LAN.

```
Host resources:   16 CPUs  |  32768 MB RAM
Archer limits:    12.8 CPUs  |  22937m RAM  (CPU 80% / RAM 70%)

Archer is running at https://192.0.2.10:8443
```

Two ports are exposed:

| Host port | Container port | Purpose |
|---|---|---|
| 8443 | 8443 | UI + API + Quiver sensor checkin / install.sh — every role (admin, analyst, viewer, sensor) over TLS |
| 2222 | 22 | Quiver sensor rsync-over-ssh (mapped off port 22 so a host-side sshd isn't disturbed) |

Port 2222 only matters if you're using Quiver to ship logs from sensors. If you're hand-importing logs into `./logs`, ignore it.

**On the cert warning:** the default cert is self-signed (auto-generated on first start, valid 10 years). The first time you load `https://<host>:8443/` your browser shows a "Not Secure" warning. Click through it once and your browser remembers the trust. For a production hunt-team deployment, drop a CA-signed cert from your internal PKI into `/data/tls/server.{crt,key}` and restart — sensors re-pin on next enrollment, browsers validate cleanly. See [OPERATIONS.md → TLS certificate rotation](docs/OPERATIONS.md#tls-certificate-rotation) for the swap-in procedure.

**Everyday operations** — same script:

```bash
sudo ./start.sh up        # build + start (or rebuild after code changes)
sudo ./start.sh down      # stop
sudo ./start.sh restart   # restart without rebuild
sudo ./start.sh logs      # tail container logs
sudo ./start.sh status    # show running state + live memory/CPU usage
```

<details>
<summary>Advanced: running without start.sh</summary>

If you're managing your own Docker environment (CI, orchestrated hosts, existing `.env` workflow), you can bypass `start.sh` and run compose directly. The container sizes itself based on whatever `ARCHER_MEMORY` / `ARCHER_CPUS` you supply; Archer's entrypoint always derives `GOMEMLIMIT` from the cgroup memory cap at runtime, so the Go runtime is correctly budgeted regardless of how you start it.

```bash
# Accept the conservative 4 GB default (fine for demo datasets, too small for large deployments):
sudo docker compose up -d

# Or set your own limits:
ARCHER_MEMORY=32g ARCHER_CPUS=8 sudo docker compose up -d
```

Note: bare `docker compose up -d` gives the container only 4 GB of RAM regardless of host size — the default in `docker-compose.yml` is a safety floor, not a host-aware size. On a big VM, either use `./start.sh up` or set `ARCHER_MEMORY` explicitly.

</details>

### 4. Register your admin account

Navigate to `https://localhost:8443/`. Accept the self-signed cert warning the first time (or swap in your CA-signed cert before this step — see [OPERATIONS.md → TLS certificate rotation](docs/OPERATIONS.md#tls-certificate-rotation)). The first user to register automatically receives the **admin** role.

### 5. Analyze

1. Drop Zeek logs into `logs/<name>/<date>/` on the host (or let
   Quiver sensors rsync them in automatically). The sidebar **Logs**
   tree shows what's been picked up.
2. Click **Analyze** to run the full detection pipeline.
3. Findings appear in real time as the pipeline progresses.

For analyst-laptop bundles or third-party hand-offs without a live
sensor: drop the bundle into `logs/<handoff-name>/<date>/` on the
host (mount, `docker cp`, or SCP via the Quiver SSH dropbox at
port 2222). Same `Analyze` button picks them up.

---

## Try It Locally (Demo)

To see a populated workbench without Docker, a sensor, or a real
capture, run the demo. It needs only Go (see [Running Without
Docker](#running-without-docker) for the toolchain) and a checkout
of this repo:

```sh
./demo.sh
```

From the repo root this builds the binary, seeds a throwaway data
directory from the sample Zeek logs in `demo/logs/`, registers a
demo admin, runs one analysis pass, and serves the workbench at
`https://localhost:18443` — a non-privileged port, so the demo
never collides with a real deployment on 8443. It stays up until
you press Ctrl-C, then wipes the temporary directory on exit.
Nothing it does touches a production instance.

```
URL:       https://localhost:18443
Email:     demo@archer.local
Password:  archerdemo
```

The sample corpus is 37 curated single-scenario captures covering
every from-logs detector family (beaconing variants, DNS tunneling,
HTTP C2, JA3/JA4, x509 anomalies, exfil, lateral movement, and
more) — a full pass surfaces ~60 findings, enough to exercise the
query bar, the Views, and the beacon-depth tools. Override the port
or credentials with `ARCHER_DEMO_PORT`, `ARCHER_DEMO_EMAIL`, and
`ARCHER_DEMO_PASSWORD`. See `demo/README.md` for the scenario list.

---

## Air-Gapped Installation

Archer's runtime has no hard internet dependencies — once installed, the analyzer reads logs from disk, the analyst UI is local, sensors push over LAN, and findings are stored in SQLite on the host. The only outbound traffic at runtime is **threat-intel feed prefetching** (FeodoTracker, URLhaus) and **manual escalation lookups** (OTX / AbuseIPDB / VirusTotal / CrowdSec / GreyNoise / Censys); both fail gracefully when offline, and every other detector — Beacon, Cobalt Strike URI, JA3/JA4, Lateral Movement, Suspicious URL via local IOC list, etc. — works fine without network.

**The catch is the build.** A fresh `git clone` + `docker compose build` reaches out to three places: Docker Hub for the `golang:1.25.10-alpine` and `alpine:3.20` base images, the Alpine package mirror for `apk add` (rsync, openssh-server, tini, ca-certificates, tzdata, rrsync), and the Go module proxy for ~11 module dependencies in `go.sum`. None of those resolve in an air-gapped environment without preparation.

The cleanest pattern is to **build on a connected box, ship the resulting Docker image as a tarball, load it on the air-gapped target.** The image is the artifact; you stop trying to rebuild on the isolated side.

### Build + ship workflow

On a connected box with Docker installed:

```bash
git clone <archer-repo-url>
cd Archer
docker compose build               # populates archer:latest in local Docker
docker save archer:latest -o archer-image.tar   # ~80 MB
```

Copy `archer-image.tar` plus the `Archer/` source tree (for `docker-compose.yml`, `start.sh`, `reset.sh`, the Quiver scripts, etc.) to the air-gapped host via whatever sneakernet you use — USB, scp from a connected jump host, signed transfer, etc.

On the air-gapped host (Docker installed, no internet):

```bash
docker load -i archer-image.tar    # loads archer:latest from the tarball
cd Archer
./start.sh up                      # uses the loaded image, no build, no pulls
```

`start.sh` handles the resource sizing as described in [Quick Start](#quick-start) and brings up the stack against the loaded image. No outbound HTTP fires. The container starts, sshd binds 2222, the HTTPS listener binds 8443, and you're operational.

### What still works offline

| Capability | Works air-gapped? | Notes |
|---|---|---|
| Log ingest from `/logs` | ✓ | Sensors push over LAN, or admin drops files manually |
| All statistical detectors (Beacon, HTTP, DNS, SSL, etc.) | ✓ | Closed-form math, no external calls |
| IOC list matching | ✓ | Admin maintains the list locally via Settings → IOC List |
| Allowlist + suppressions | ✓ | Local |
| Findings, notes, escalations, exports | ✓ | All local SQLite + browser |
| Quiver sensor enrollment | ✓ | TLS handshake is internal LAN traffic, pinned-pubkey |
| Quiver sensor install on RHEL/Debian/etc. | ⚠ | Sensor's `install.sh` uses the local distro package manager (`apt`/`dnf`/etc.) to install rsync/openssh-client/cron — those need to resolve from the sensor's own internal package mirror or be pre-installed |
| FeodoTracker + URLhaus feed prefetch | ✗ | Outbound HTTPS to `feodotracker.abuse.ch` and `urlhaus.abuse.ch`. Fails silently per analysis run; no findings from these feeds. |
| Escalation lookups (OTX/AbuseIPDB/VT/etc.) | ✗ | Outbound HTTPS per service. Manual escalation surfaces "request failed" results in the consolidated TI Enrichment note instead of hits. |

### Bringing TI feeds into an air-gapped install

If you want TI matching to work air-gapped, the practical path is to **mirror the two free feeds locally** (FeodoTracker IP blocklist and URLhaus active-URL CSV are plain text + CSV downloads), serve them from an internal HTTP endpoint, and either patch `internal/analysis/ti.go`'s `fetchFeodo` / `fetchURLhaus` URLs to point at the mirror — OR populate the local IOC list from the same files via a periodic internal job and rely on IOC-list matching (which works air-gapped) as the substitute for live feed lookups.

The escalation services (OTX, AbuseIPDB, VirusTotal, CrowdSec, GreyNoise, Censys) all require their own API endpoints; there's no "mirror" pattern for these short of running an internal API gateway with cached responses. For most air-gapped deployments these stay disabled.

### When you actually need to rebuild on the air-gapped side

If your operational model requires building from source on the isolated host (e.g. you're patching analyzer code in the field), the path is heavier:

1. Pre-pull both base images on a connected box, save as tarballs, sneakernet over: `docker pull golang:1.25.10-alpine && docker pull alpine:3.20 && docker save golang:1.25.10-alpine alpine:3.20 -o base-images.tar`
2. Vendor Go modules into the repo before transit: `cd Archer && go mod vendor` — this drops all module sources into `./vendor/` so the build doesn't need the Go module proxy. You'll also need to add `-mod=vendor` to the `go build` line in the Dockerfile.
3. Solve the `apk add` problem — Alpine doesn't ship a self-contained "all-packages" snapshot. The realistic options are: (a) host an internal Alpine package mirror, (b) bake the needed packages into a custom base image built on the connected side and shipped as a tarball alongside the source, or (c) skip the Alpine package step and embed the binaries directly into a `FROM scratch` image.

Most teams find option 1 (build connected, ship the tarball) is dramatically less work than option 2-3 (rebuild on the air-gapped side). Use the rebuild path only when you have a specific reason to need source-on-target.

---

## Log File Layout

Archer reads Zeek-format logs. Files may be uncompressed (`.log`) or gzip-compressed (`.log.gz`, `.gz`). Both TSV (tab-separated with `#fields` header) and JSON/NDJSON formats are supported.

The directory immediately under the configured logs root is used as the **sensor name** displayed throughout the UI. Deeper nesting is allowed but only the first level is used as the label:

```
/logs/<sensor-name>/[subdirs/]<file>.log
```

Supported log filenames: `conn`, `dns`, `http`, `ssl`, `x509`, `files`, `notice` (with or without `.log` suffix, with or without `.gz`).

---

## Configuration

All thresholds are configurable at runtime through the **Settings** dialog (admin only). Changes are persisted in SQLite and survive restarts.

### Analysis Thresholds

| Parameter | Default | Description |
|---|---|---|
| `beacon_min_connections` | `4` | Minimum connection count before beacon scoring is applied |
| `http_beacon_min_requests` | `8` | Minimum HTTP request count before HTTP beacon scoring is applied |
| `long_conn_min_hours` | `1.0` | Minimum session duration (hours) for a long connection alert |
| `strobe_min_connections` | `100` | Count floor — minimum connections to a single destination before the rate gate is evaluated |
| `strobe_min_rate_per_sec` | `0.5` | Rate gate — minimum average connection rate (conn/s) for a pair to be classified as Strobe. A pair must meet both `strobe_min_connections` and this rate. A 60-second C2 beacon over 30 days generates ~43,200 connections at 0.017/s and is not affected. |
| `exfil_min_bytes_mb` | `5.0` | Minimum outbound transfer (MB) required for an exfiltration alert |
| `exfil_ratio_threshold` | `10.0` | Minimum outbound/inbound byte ratio for an exfiltration alert |
| `off_hours_start` | `22` | Start of off-business hours (hour-of-day in the configured `timezone`, UTC when unset) |
| `off_hours_end` | `6` | End of off-business hours (hour-of-day in the configured `timezone`, UTC when unset) |
| `off_hours_min_mb` | `1.0` | Minimum transfer (MB) outside business hours to trigger an alert |
| `dns_tunnel_label_len` | `40` | DNS label character length threshold for tunneling detection |
| `dns_tunnel_entropy` | `3.5` | Shannon entropy threshold for DNS label content |
| `dns_tunnel_min_depth` | `5` | Minimum subdomain nesting depth for tunneling detection |
| `dns_nxdomain_threshold` | `200` | NXDOMAIN response count threshold for DGA detection |
| `dns_unique_subdomain_min` | `50` | Unique subdomain count threshold per apex domain |
| `dns_beacon_min_queries` | `20` | Minimum non-NXDOMAIN queries to a `(src, apex)` before the DNS Beacon cadence detector scores it (sample-size floor, analogous to the conn/HTTP beacon minimums) |

### Deployment

**`start.sh` commands:**

```bash
sudo ./start.sh           # Build and start (default)
sudo ./start.sh up        # Build and start
sudo ./start.sh down      # Stop and remove containers
sudo ./start.sh restart   # Restart without rebuilding
sudo ./start.sh logs      # Tail container logs
sudo ./start.sh status    # Show container status and live resource usage
```

**Docker environment variables:**

| Variable | Default | Description |
|---|---|---|
| `TZ` | `UTC` | Container timezone |
| `GOMAXPROCS` | `0` | CPU cores available to the Go runtime (`0` = all) |
| `ARCHER_CPUS` | `9999` (none) or `start.sh` output | CPU limit enforced by Docker |
| `ARCHER_MEMORY` | `4g` or `start.sh` output | Memory limit enforced by Docker (cgroup cap) |
| `GOMEMLIMIT` | auto | Go soft memory budget — set by `entrypoint.sh` at startup to 90% of the cgroup memory cap. Passing an explicit value overrides the auto-derivation. |

---

## Threat Intelligence

### Free Feeds (No API Key Required)

These feeds are fetched automatically at the start of every analysis run:

| Feed | Coverage |
|---|---|
| **Feodo Tracker** | Active C2 server IPs for Emotet, TrickBot, QakBot, Dridex, and other banking malware |
| **URLhaus** | Active malware distribution URLs and hosting domains |

### Escalation Lookup Services

Configure credentials in the **Settings** dialog. **GreyNoise** is the only service that runs without any configuration — its Community API works unauthenticated (rate-limited to ~50 requests/hour). Adding a free GreyNoise key raises the limit. Every other service in this table is gated on a configured key.

| Service | Auth | Lookup Type | What is Checked |
|---|---|---|---|
| **VirusTotal** | API key | IP addresses and domains | Malicious engine detection count from `last_analysis_stats` |
| **CrowdSec CTI** | API key | IP addresses only | Overall reputation score from the smoke feed |
| **AlienVault OTX** | API key | IP addresses and domains | Threat pulse count and reputation score |
| **AbuseIPDB** | API key | IP addresses only | Abuse confidence score (0–100%) and total report count (last 90 days) |
| **GreyNoise** | optional Community key | IP addresses only | Classification (benign/malicious/unknown), `noise:true` (background internet scanner — likely not targeted), `riot:true` (known benign service like Google/AWS) |
| **Censys** | API ID + API Secret (Basic auth) | IP addresses only | Number of services + sample ports (HTTPS, SSH, …), country, last-observed timestamp. Informational only — Censys doesn't return a malicious verdict. |

The Settings UI presents Censys as a single combined `id:secret` field — the ID half is plaintext (it's an identifier, not a credential by itself), the secret half is masked.

### Escalation Workflow

When an analyst escalates a finding, Archer opens a dialog to:

1. Select which artifact to look up — **Dst IP**, **Src IP**, or both
2. Select which TI services to query (only services with configured credentials are shown; GreyNoise is always shown because it works unauthenticated)

Lookups run in the background. For each service queried:
- A real-time **toast notification** is pushed to the browser as each lookup completes
- A final summary toast indicates total hit count when all lookups complete
- Once every lookup has settled, a **single consolidated TI Enrichment note** is written to the finding — grouped per IP, with each result prefixed `⚠` (hit) or `✓` (clean):

  ```
  TI Enrichment Results — 2 IP(s), 1 hit(s)

  [1.2.3.4]
    ⚠ [VirusTotal] 5 engines flagged 1.2.3.4 as malicious
    ✓ [GreyNoise] 1.2.3.4 background internet scanner (Censys Scanner) — likely not targeted
    ✓ [CrowdSec] 1.2.3.4 - no threats found
    ✓ [Censys] 1.2.3.4 - 4 services [443/HTTPS, 22/SSH, 80/HTTP] (location: US, last seen 2026-05-01)

  [5.6.7.8]
    ✓ [VirusTotal] 5.6.7.8 - no malicious detections
  ```

Results are classified as `[HIT]` (threat confirmed) or `[CLEAN]` (no threats found) and stored permanently regardless of outcome. The full thread can be exported as a self-contained `.txt` file via **Export TXT** at the top of the Notes section — useful for incident reports and stakeholder handoffs.

**Cross-annotation onto sibling findings.** When a TI lookup returns substantive information about an IP — a hit (Feodo / URLhaus / OTX / VirusTotal / AbuseIPDB / CrowdSec / GreyNoise classification) or a substantive non-hit (GreyNoise labelling the IP as `riot:true` Google/AWS/CiscoOpenDNS infrastructure, Censys returning a service list) — Archer also appends a per-IP `TI Enrichment` note to every other finding that mentions that IP. An analyst opening a beacon finding will see "GreyNoise: known benign service Google DNS" inline instead of having to notice a separate `TI Hit (IP)` row. "No record found", "lookup failed", and "request failed" lines are kept on the originating finding only — they have no signal worth surfacing on related findings. The same applies to automatic TI hits emitted during the analyzer's TI phase: every newly-detected `TI Hit (IP)` / `TI Hit (Domain)` / `TI Hit (Hash)` cross-notes the IP across all other findings that mention it, gated on `IsNew` so re-runs don't duplicate notes. (`Suspicious URL` is excluded from cross-annotation — the matching `TI Hit (Domain)` for the same host already carries the enrichment.)

### Archive IOC Scan

Admins can retroactively re-scan archived logs against the current IOC list and TI feeds. Settings → Operations → Log Archive → **Scan Archive for IOCs**. The scan walks `/data/archive`, runs only the IOC + Feodo + URLhaus + Suspicious-URL phases (skipping beacon/exfil/lateral/etc.), and produces standard findings via the same fingerprint-merge that regular runs use. Useful when a freshly added threat-intel feed should be checked against historical data that's already aged out of `/logs/`.

---

## Quiver Sensors

Quiver is the optional sensor-side companion that ships Zeek logs from any Linux host into Archer. Each enrolled sensor pushes hourly via rsync-on-ssh; Archer treats every sensor as its own per-sensor log tree at `/logs/<sensor-name>/`, so analyzers, campaigns, and the host risk model keep per-sensor scope automatically.

**Quick enrollment.** As an Archer admin, open the **Sensors** modal in the header → **+ Enroll new sensor** → **Generate token**. Copy the curl one-liner; on the sensor (as root):

```sh
sudo curl -fsSL -k --pinnedpubkey "sha256//<fingerprint>" \
    https://<archer-host>:8443/quiver/install.sh | sudo bash -s -- <TOKEN>
```

The script auto-installs missing dependencies (rsync, openssh-client, cronie/cron, sudo, util-linux), creates a `quiver` system user, generates an ed25519 keypair, registers with Archer, drops `/etc/cron.d/quiver`, and runs a full first-sync. The Archer dialog flips from "Waiting…" to "✓ Enrolled as `<name>`" the moment the server records the enrollment.

**Supported distros.** Debian, Ubuntu, Kali, RHEL/Oracle/Rocky/Alma 7+, Fedora, openSUSE/SLES, and Alpine. SELinux contexts are restored on RHEL-family hosts so cron can exec the daily script under enforcing mode.

**Cadence.** Sensors push every hour at a server-assigned random minute-of-hour. Each push ships only the last 24 hours of completed `.gz` files (rsync mtime-skips already-shipped files).

**Initial backfill window.** During `install.sh`, the operator is prompted for how many days of historical Zeek logs the sensor should ship on its first push — Enter for all available history (legacy default), or a positive integer N to ship only the last N days. The choice is persisted to `/etc/quiver/config` as `INITIAL_BACKFILL_DAYS=` and is honored only by the FIRST_SYNC=1 invocation; recurring cron pushes always use the 24h window. For non-interactive deployments, set `INITIAL_BACKFILL_DAYS=N` in the environment before piping the install script and the prompt is skipped. Useful when a sensor has months of local Zeek history but the operator only wants the recent slice ingested into Archer.

**Sensors modal.** Three tables visible to all authenticated users; admin-only writes:

- **Enrolled Sensors** — name, host, status, slot, last seen (UTC `YYYY-MM-DD HH:MM`; full ISO + `UTC` in the hover title), Health (`✓ on time` / `pending` / `⚠ missed` / `never`), and a per-row kebab (⋮) menu with admin actions (Reassign slot, Disenroll, or Purge after disenroll).
- **Pending Tokens** — outstanding tokens awaiting use or revocation. Used tokens are filtered out automatically (they show up as Enrolled Sensors). Kebab on fresh tokens offers **Show enrollment command** (replays the curl one-liner with the same blue pulse-dot → green ✓ confirmation flow as the fresh-generate path) and **Revoke**; expired tokens only offer Revoke.
- **Unauthorized Attempts** — checkins from sensor names Archer doesn't recognize, with source IP, attempt count, and first/last-seen timestamps. Auto-prunes after 30 days unless pinned. Kebab offers **Enroll this sensor** (pre-fills the override name) or **Dismiss attempt**.

**Architecture summary.** Two separate channels: HTTPS on port 8443 with TLS-pinned curl for enrollment + daily checkins (pull-control), and rsync-over-ssh on host port 2222 with per-sensor `authorized_keys` lines pinning each session to `command="rrsync -wo /logs/<name>/"` (push). Disenrollment works without a sensor-side daemon — the next hourly checkin returns `{"status":"disenrolled"}` and the script self-cleans.

**Persistence.** Sensor rows, tokens, unauthorized attempts, the SSL fingerprint, sshd host keys, and the per-sensor `authorized_keys` lines all live in named volumes (`archer-data`, `archer-sshd`, `archer-quiver`) and the host bind `./logs/`. `./start.sh up` rebuilds the image but never loses sensor state.

For the full operator guide — architecture diagrams, sensor-side artifact layout, distro-specific notes, troubleshooting, and the sensor-facing endpoint reference — see **[docs/QUIVER.md](docs/QUIVER.md)**.

---

## User Roles

The first user to register automatically becomes an **admin** and is signed in immediately. Subsequent registrations create a **pending** account with the **viewer** role; the new user cannot sign in until an administrator approves them from the **Users** dialog. Approved viewers can be promoted to **analyst** or **admin** by an admin via the same dialog.

Every user can change their own password from the account menu (click your name in the top bar → **Change password**); the current password is re-verified and all other live sessions for that account are invalidated. Admins can reset any other user's password from the per-row **Reset PW** action in the **Users** dialog — the target's sessions are dropped so they sign in again on the new credential.

| Capability | Admin | Analyst | Viewer |
|---|:---:|:---:|:---:|
| View findings, campaigns, hosts | ✓ | ✓ | ✓ |
| View watch mode status | ✓ | ✓ | ✓ |
| Acknowledge / escalate findings | ✓ | ✓ | — |
| Add analyst notes | ✓ | ✓ | — |
| Run TI escalation lookups | ✓ | ✓ | — |
| Start / pause / stop analysis | ✓ | ✓ | — |
| Scan and clear log files | ✓ | ✓ | — |
| Edit allowlist and IOC list | ✓ | ✓ | — |
| Manage suppressions | ✓ | ✓ | — |
| Manage relationship allowlist (pair rules) | ✓ | ✓ | — |
| Update analysis thresholds | ✓ | — | — |
| Manage API keys | ✓ | — | — |
| Configure watch mode (anchor time / timezone / cadence) | ✓ | — | — |
| Scan archive for IOCs | ✓ | — | — |
| View disk-usage telemetry | ✓ | ✓ | ✓ |
| View Sensors modal (read-only tables) | ✓ | ✓ | — |
| Enroll / disenroll / purge sensors | ✓ | — | — |
| Generate / revoke enrollment tokens | ✓ | — | — |
| Reassign sensor push slot | ✓ | — | — |
| Dismiss unauthorized-attempt rows | ✓ | — | — |
| Set sensor-facing host override | ✓ | — | — |
| Create / delete users | ✓ | — | — |
| Promote / demote user roles | ✓ | — | — |
| Change own password | ✓ | ✓ | ✓ |
| Reset another user's password | ✓ | — | — |

Sessions are stored in SQLite with a 24-hour expiry, httpOnly cookies, and `SameSite=Strict` enforcement.

---

## Web Interface

### Sidebar

| Section | Controls |
|---|---|
| **Logs** | Shows the configured log directory and a read-only preview tree of `<sensor>/<date>/` directories under `/logs`. Click a sensor to expand its dates with file counts and total size. The tree refreshes automatically when an analyze pass finishes, so newly-arrived (rsync'd or hand-dropped) logs appear without a page reload. |
| **Analysis** | **Analyze** starts the detection pipeline against everything currently under `/logs`. Disabled when the tree is empty. A progress bar and step indicator update in real time via SSE. **Pause** and **Stop** are available during a run. The analyzer checks for cancellation at phase boundaries (not in tight loops), so there can be a noticeable delay between clicking **Stop** and the run actually winding down — the button visibly switches to "Stopping…" and the status line shows *"Cancellation requested — waiting for analyzer to wind down…"* until the run exits. Manual analyze runs the full pipeline and preserves analyst state (notes / acks / escalations) via fingerprint merge — useful during active hunts when you want a fresh detection pass without losing your annotations. |
| **Threat Intel** | Displays a count of TI hits found in the last analysis. |
| **Watch Mode** | The sidebar is read-only for every role: it shows whether watch mode is enabled or disabled and a compact status — the configured cadence and run time (e.g. *"Daily at 02:00"*, *"Hourly at :15"*) and the timezone with its abbreviation (e.g. *"America/New_York (EDT)"*). The configured schedule shows even while watch is disabled, so an analyst or viewer can see what's set up. **Admins** additionally see a **Watch Mode** button (styled like the other sidebar action buttons) that opens the settings modal; analysts and viewers don't get the button — matching the server, which enforces admin on the watch write. Inside the modal an admin picks a **Cadence** first (Daily / Every 12h / Every 6h / Every 4h / Hourly); the time control beneath it adapts: a full HH:MM picker labeled `Run at` for Daily, `First run at` for the multi-hour cadences, and a minute-of-hour numeric input under Hourly (the server only uses the minute portion there). A live schedule preview in the modal shows when the next tick lands and whether it is a full pipeline or an incremental TI/IOC pass. Cadence, time, and timezone auto-save on change and persist independently of the **Enable** / **Disable** toggle. |
| **Allowlist** | Edit the list of IPs and domains to exclude from all findings. One entry per line. Findings matching an allowlisted IP are hidden across all tabs immediately after saving. |
| **IOC List** | Tabbed editor. **IPs & Domains** — known-bad IPs/CIDRs/domains; findings with a matching src/dst IP are tagged and appear in the IOC Hits tab (read-time annotation). **JA3 / JA4** — TLS client fingerprints that flag as **Malicious JA3 / JA4** on the next analysis, exactly like the built-in C2 tables; the always-active built-in fingerprints are listed in the tab as undeletable lines (editing them is a no-op, they return on save). Add fingerprints by pasting into the tab or via **Mark malicious** on the TLS Fingerprints wall. |
| **Suppressions** | View all active suppressions with their target, context, and expiry time. Individual suppressions can be removed here; expired suppressions are pruned automatically. |
| **Relationships** (allowlist tab) | Tuple-scoped finding filter for known-good `src → dst : port` relationships (e.g. a host beaconing to the corp DNS). Either side can be a single IP or a **CIDR range** — `10.0.0.0/24 → 10.0.0.53 : 53` allowlists the whole LAN's resolver relationship in one rule (both sides ranged works too, IPv4 and IPv6). Created from a finding's right-click menu → **Allow this Relationship** (pre-filled with the finding's exact IPs — widen either side to a CIDR before saving; scope defaults to that finding's type so DNS Tunneling on the same pair still surfaces). A pure view filter — matching findings are hidden from the table and bell, never deleted; removing a rule brings them straight back with no re-analysis. Managed from the **Allowlist** modal's **Relationships** tab (the standalone sidebar dialog was removed in v0.25.0). |
| **Suggestions** (allowlist tab) | Beacon pairs that Archer has identified as repeat false positives: the pair must have an acknowledged finding *and* have re-fired across 14+ distinct UTC days in the beacon evolution history. Each candidate shows the evidence trail (day count, date range, peak score, who acked it). Applying requires a typed justification, which is stored as the rule's note in the Relationships tab. A way to close the "I keep acking the same beacon" loop without manual rule creation. |

### Finding Tabs

The first four tabs (Findings / Acknowledged / Escalated / IOC Hits) all view the same network-event finding set with different status filters. The last two (Campaigns / Hosts) are aggregations built client-side from the same data. Per-host roll-up findings (`Host Risk Score`) are excluded from the four findings tabs and from the bell — they live in the Hosts tab where the score actually means something to the analyst.

| Tab | Contents |
|---|---|
| **Findings** | All open (unacknowledged, non-escalated) network-event findings |
| **Acknowledged** | Network-event findings marked as reviewed |
| **Escalated** | Network-event findings sent to threat intelligence or escalated for response |
| **IOC Hits** | Network-event findings where src or dst IP matches the IOC list, plus all `TI Hit (IP)` / `TI Hit (Domain)` / `TI Hit (Hash)` / `Suspicious URL` findings |
| **Campaigns** | Destinations contacted by two or more distinct internal source IPs — potential shared C2 infrastructure. **Left-click** any row to open the campaign pivot in the shared detail dock: banner reads `Campaign [SEVERITY score N] dst:port`; the contact table lists every finding for that destination by score. Right-click for export / graph / allowlist / IOC actions. |
| **Hosts** | Per-host composite risk scores aggregated across all finding types, plus a sortable **Beacons** column — the count of `Beacon` / `HTTP Beacon` findings for that host, so a staging host accounting for many of the active beacons stands out instead of being buried in a flat list. Click any row to open the **host-pivot view**: the Host Risk Score summary at the top, followed by a **Contact set** table listing every network finding for that host (score, type, destination, timestamp) sorted by score — click any contact row to drill into that finding's full detail. Right-click for the standard pivots. |

### Findings Table

Columns: **Score**, **Severity**, **Type**, **Source** (IP + port), **Destination**, **Port**, **Time (UTC)**, **Status**, **Sensor**, **Detail**. All columns are sortable. Findings timestamps are always rendered in UTC for consistency across analysts in different time zones.

**Query bar** (always visible): a single query-language input is the primary filter — Lucene-style field terms (`id:`, `type:`, `severity:`, `src:`/`dst:` IP, CIDR, or a space keyword — `rfc1918`/`private` (internal) or `public`/`external`, `dir:`, `port:`, `sensor:`, `hostname:`, `uri:`, `service:`, `detail:`, `note:`, `analyst:`, `status:`, `ja3:`/`ja4:`, `file:`, `attack:`, `score:`, `ts:`, `detected:`, the booleans `ioc:`/`spectral:`/`channel:`/`benign:`, the beacon sub-scores `tscore:`/`dscore:`/`hist:`/`dur:`, the beacon timing/volume metrics `conns:`/`meanint:`/`medint:`/`jitter:`, and the outbound/inbound byte ratio `outratio:`), `AND`/`OR`/`NOT` with `()` grouping (an operator is required between terms), wildcards, numeric comparisons and `[lo TO hi]` ranges, and date windows. A **▾** caret at the field's left edge reopens any of the last 10 distinct queries you ran (per-browser, most-recent-first, deduplicated; fed by every run path). Shortcut chips (Severity, Type, Score, Time, **+ more**) upsert the matching token into the query text, composed with `AND`. A **Hunts ▾** chip (leftmost) holds prebuilt, ready-to-run queries — nine beacon-variety lenses (textbook check-in, tasking channel, jitter-evading/spectral, clockwork, scheduled/fixed-hour, low-and-slow, persistent, DGA-backed, port-hopping) and six threat-signature sweeps (TI matches, known C2, DNS covert channels, exfil, TLS evasion, lateral movement); picking one replaces the box with the full expression and runs it. A bare word is a case-insensitive substring match. Evaluated server-side and ANDed on top of the active view; full grammar in [docs/ANALYST_PLAYBOOK.md](docs/ANALYST_PLAYBOOK.md#querying-the-findings-table).

**Exports**: every tab has its own CSV and JSON download.

- **⬇ Export current tab ▾** in the filter bar dispatches based on the active tab — Findings/Ack/Esc/IOC do a server-side export honoring all active filters plus the tab's status filter; Campaigns and Hosts emit their client-side aggregations directly. CSV or JSON for any tab.
- **⬇ Export all ▾** in the filter bar exports every finding in the database, ignoring filters and tab. CSV or JSON.
- **Single campaign export** — right-click any row in the Campaigns tab and pick **Export campaign ▸** to get a hub-and-spoke graph (one node per source IP plus a destination hub) ready for graph viewers. Submenu offers four formats:
  - **CSV** — edge list with `Source`, `Target`, `Port`, `MaxScore`, `FindingTypes` columns; works with [Cytoscape Web](https://js.cytoscape.org/) and any spreadsheet
  - **Graphology JSON** — [Graphology serialization](https://graphology.github.io/serialization.html) format (`{attributes, nodes, edges}`)
  - **GEXF** — Gephi's native XML format, the most reliable choice for [Gephi Lite](https://gephi.org/gephi-lite/) and desktop Gephi
  - **GraphML** — XML format consumed by Cytoscape Desktop, yEd, and most desktop graph tools (note: Cytoscape Web does not accept GraphML — use the CSV export for it)
- **In-app graph view** — right-click any campaign row and pick **View campaign in Graph** to open the network inline. Uses an embedded Cytoscape.js renderer (lazy-loaded on first open) with severity-coloured nodes/edges, node sizes that scale with finding count, force-directed `cose` layout, fit-to-view and re-layout controls. Clicking a node jumps the findings table to a finding involving that IP — the graph doubles as a navigation surface.

Filter-bar dropdowns produce server-streamed downloads for findings tabs and client-side Blob downloads for Campaigns/Hosts; right-click campaign exports are always client-side.

**Delta mode**: **New Only** / **Show All** toggle to focus on findings that appeared in the most recent analysis.

### Right-Click Menu (any findings tab)

The context menu reshapes itself based on what was right-clicked, the user's role, and the finding's current state:

- **Click-anchor arrow** at one of the menu's four corners (↖↗↙↘) — JS measures the menu after reveal and clamps it inside the viewport with an 8px margin, then places the arrow at the corner closest to the click point so the menu always has a visual reference back to where you right-clicked.
- **Column-aware section** — if the right-click landed on a Source or Destination cell, the menu offers `Pivot to <ip>`, `Add <ip> to Allowlist`, `Add <ip> to IOC List`, and `Lookup <ip> ↗ ▸`. The same right-click on any other cell hides the column-aware items entirely and shows only row-level actions, since there's no clear single target.
- **External lookups** (8 destinations, all open in a new tab): VirusTotal, AbuseIPDB, Shodan, CrowdSec, Censys, GreyNoise, URLscan.io, AlienVault OTX. Censys and GreyNoise free tiers require an account; URLscan and OTX direct-link reads work without one.
- **Row-level actions**: Copy PCAP Filter, Copy Row, Source Records, Beacon Chart (visible for `Beacon` and `HTTP Beacon` finding types), Acknowledge, Escalate, Suppress ▸ (1d/7d/14d/30d).
- **State-aware disabling**: greyed and click-blocked when an action no longer applies — `Acknowledge` for already-acknowledged findings, `Escalate` for already-escalated ones, `Add to Allowlist`/`IOC` when the resolved IP is already on the respective list. Tooltips explain the reason on hover.
- **Role-gated**: write actions (Ack, Escalate, Suppress, Add to Allowlist/IOC) are hidden entirely for viewer-role users so the menu never offers a click that would dead-end at a 403.
- **Tab-gated**: Acknowledge / Escalate / Suppress are hidden on the Campaigns and Hosts tabs (and the separator above them collapses with them). Those actions operate on a single finding's status and don't make sense on a synthesised aggregate row.
- **Campaign-only items** (View campaign in Graph, Export campaign ▸) appear when right-clicking a row in the Campaigns tab.
- **View-preserving actions** — every list-mutating action (Acknowledge, Escalate, Dismiss, bulk-dismiss-campaign, Add to Allowlist, Add to IOC List, Suppress, Allow this Relationship) reloads in place: the active tab, the page offset, and the scroll position are all preserved. The acted/curated rows drop out and the rest shift up, but you stay exactly where you were working — triaging or curating from deep in a long list no longer kicks you back to the top or to page 1. This holds on the Campaigns and Hosts tabs as well. Only deliberate view *changes* (running a query, toggling delta mode, changing the page size) reset to the top.

### Detail Pane

The detail pane is a persistent dock shared across all tabs — Findings, Campaigns, and Hosts all render into the same resizable, collapsible pane. Selecting a network finding shows full detail; clicking a Campaigns or Hosts row opens the corresponding pivot view.

The **Detail** tab renders structured labeled sections: identity (type, severity/score, status, sensor, timestamp, source file), endpoints (src/dst IP, port, **Service** — Zeek DPD's L7 protocol for the flow, on every conn-derived finding, blank when unfingerprinted — JA4/JA3 with sibling counts and per-fingerprint **Benign** / **Malicious** mark buttons — triage a fingerprint straight from the finding, including a low-concern one the TLS wall hides; same endpoints as the wall, so a benign mark gives the `FP Benign` chip and a malicious mark adds it to the JA3/JA4 IOC list, HTTP beacon paths), beacon triage (cadence, jitter, sample size, Timing/Data size/Histogram/Persistence sub-scores — beacon types only), detection detail (pipe-delimited analyzer output parsed into key-value rows), flags (NEW / IOC / ESCALATED colored chips, analyst note), and a **Why flagged** block — a plain-English summary of what the finding means and why it fired, a *Common false positives* hint, and a collapsible *Scoring detail* disclosure holding the formula and reference math (so the math is one click away rather than jammed into the prose). The **Notes** tab shows analyst annotations with an inline add-note box. The **TI Results** tab shows machine-authored TI Enrichment notes from escalation lookups.

Action footer:

- **Acknowledge** — marks the finding as reviewed
- **Escalate** — opens the TI escalation dialog
- **Beacon Chart** — three-view canvas dialog for `Beacon` and `HTTP Beacon` findings: **Timeline** (one vertical tick per connection event on a fit-to-span time axis — eyeball test for regularity), **Interval histogram** (distribution of inter-arrival gaps with a dashed mean-interval reference line — tall single peak confirms a beacon's heartbeat), **Bytes** (sent/received mirror — bytes sent per time bucket above a zero axis in the accent color, bytes received below in green, shared scale; a bucket whose sent volume exceeds 2× its received turns the sent bar critical-red, the **upload-heavy** flag, so an exfil burst reads as red spikes erupting over a quiet heartbeat). All three views render hi-DPI and carry hover tooltips (bucket range / counts / byte totals; the Timeline adds a crosshair). A stats strip above the canvas shows connection count / mean interval / jitter (CV) / span; a per-view PNG / JPEG export dropdown snaps the active canvas with a filename including the src→dst pair and view name. **Interactive zoom** on the Timeline view: click-drag to brush-select a time range and the view re-fits to that slice (the data is already client-side, so zoom doesn't refetch). Right-click on the canvas or the **Reset zoom** button returns to auto-fit. Switching to Interval histogram or Bytes drops the zoom since those views have their own X mappings.
- **Score Chart** — opens the 30-day score evolution modal (beacon types only; grayed out until history exists)
- **PCAP Filter** — copies a ready-to-use `tcpdump` or Suricata filter string to the clipboard
- **Source Records** — scans the original Zeek logs (and `/data/archive`) for records matching the finding's (src, dst) pair, then opens a dialog with the full standard schema for the relevant log types. Columns are resizable; the table scrolls on both axes. A **Search range** dropdown (±6h default, up to All time) broadens the scan when needed. **Export CSV** flattens every loaded record into a single CSV with a leading `_log_type` column and canonical Zeek field ordering per type. Right-click any data cell → **Copy cell** copies the exact value — native double-click selection truncates on punctuation (e.g. a Community ID's `:`/`=`).
- **Suppress** — suppresses alerts for the source or destination IP for a configurable duration; suppressed findings are hidden from all tabs until the suppression expires or is manually removed
- **Analyst Recommendation** — auto-generated investigative guidance based on the finding type and score

### Sensors Modal

Header **Sensors** button (admin + analyst). Three tables:

- **Enrolled Sensors** — read-only for analysts; admins get a per-row kebab (⋮) menu with **Reassign slot**, **Disenroll** (red), and **Purge data** (after disenroll). Slot renders timezone-independent (`:30 hourly`); Last seen renders as UTC `YYYY-MM-DD HH:MM` with the full `YYYY-MM-DD HH:MM:SS UTC` in the cell's hover title (v0.19.0; the rest of the UI's UTC convention now applies here too). **Health** column shows `✓ on time` (within 1h), `pending` (within 1.5h), `⚠ missed` (>1.5h since last checkin), or `never`. **Size** column shows the per-sensor `/logs/<name>/` byte total, populated from `/api/disk-usage` (5-minute server-side cache).
- **Pending Tokens** — outstanding enrollment tokens (24h TTL, single-use). Admins see the full token, override name, created/expires timestamps (UTC `YYYY-MM-DD HH:MM`), and a kebab. Fresh tokens: **Show enrollment command** (reopens the enroll dialog in show-mode with the curl one-liner pre-filled, Copy ready, and the same pulse-dot → green ✓ confirmation when the sensor checks in) and **Revoke**. Expired tokens: just **Revoke**. Used tokens disappear from this list — they become rows in Enrolled Sensors. Live SSE updates: when a sensor finishes enrollment, the open enrollment dialog flips to "✓ Enrolled as `<name>`" and the parent table refreshes automatically.
- **Unauthorized Attempts** — checkins from sensor names Archer doesn't know about. Auto-prunes after 30 days unless an admin pins a row. Kebab: **Enroll this sensor** (pre-fills override name in the token dialog) or **Dismiss attempt**. Live SSE updates the list when a fresh unrecognized checkin arrives.

Admin-only "+ Enroll new sensor" dialog: optional override name, **Generate token**, then a 1250px-wide dialog showing the full curl one-liner with **Copy**, plus a status row that flips from "Waiting for sensor to run the install command…" (pulsing accent dot) to "✓ Enrolled as `<name>`" (green check) the moment the server records the enrollment. The same dialog is reused by the Pending Tokens kebab's **Show enrollment command** action — it reopens in show-mode (header swaps to "Sensor Enrollment Command", the override input + Generate button are hidden) so an admin can replay an existing fresh token's curl line without revoking and regenerating. Closing the dialog refreshes the parent Sensors table.

### Settings Dialog

Opened with the gear button in the header. The configuration tabs below are **admin only**; **non-admin roles (analyst, viewer) see only the Appearance tab** — theme is a per-browser preference, so everyone can pick their own skin, but the detection / TI / watch / archive / danger-zone config stays admin-gated (and writes are enforced admin server-side regardless). Contains:

- **Beacon / DNS thresholds** — runtime-tunable detection parameters
- **Threat Intelligence** — VirusTotal, AbuseIPDB, OTX, CrowdSec, GreyNoise (optional), and Censys (`API ID` + `API Secret`, rendered as a single combined field where the secret half is masked). GreyNoise is the only entry that's optional — its Community API works unauthenticated; supplying a key lifts the rate limit.
- **Watch Mode** — opt-in **Always run full scan on every watch tick** checkbox. By default the watch loop runs the full pipeline only on the first UTC-day tick and a cheaper incremental TI/IOC pass on subsequent same-day ticks. Turning this on makes every tick a full pipeline run — closes the "wait until tomorrow" gap on statistical detectors at the cost of more CPU per tick. Useful during active hunts; off by default for resource-conscious background monitoring. The sidebar's schedule preview drops the "Next Full Scan:" follow-up line when this is on (every tick is full, so the line would be redundant).
- **Log Archive** — enable/disable automatic archive, retention days, and the opt-in **Also remove findings older than the archive cutoff** toggle; includes a **Run Archive Now** button that uses the saved settings, and a **Scan Archive for IOCs** button that retroactively re-scans `/data/archive` against the current IOC list and TI feeds (Feodo / URLhaus / Suspicious URL) without rerunning the heavy analysis phases. New IOC matches surface as findings via the same fingerprint-merge as a regular run.
  - **Retention is a detection-coverage decision, not just a disk-usage one.** Beacon detection only operates on whatever's currently in `/logs` — once a file is archived, the math can't see it. Minimum detectable beacon period ≈ `retention_days / BeaconMinConnections`. With the default 4-connection minimum: 5-day retention catches any beacon faster than ~30h (Cobalt Strike, hourly C2, etc.) but misses daily/weekly APT-cadence beacons; 30-day retention extends coverage down to every-3-day beacons; 60-day reaches every-6-day. Keep retention high enough for the slowest beacon period you care about catching. Findings detected on prior, larger-window runs persist across re-runs (fingerprint merge), but their scores are frozen at whatever the most recent successful detection computed — they don't accumulate as more data arrives. See `docs/DETECTION_METHODS.md` section 16 for the full tuning math.
- **Disk Usage** — auto-refreshing block (5-minute server-side cache via `/api/disk-usage`) showing per-sensor `/logs/<name>/` byte totals under a **Logs** section, the `/data/archive` total under an **Archive** section, and the free-space remaining on each volume. A red banner pins to the top of the page when any tracked volume drops below 10% free.
- **Detector Health** — block (via `/api/detector-activity`, refreshed each time Settings opens) listing new-detection counts per type for the last 7 days, the prior 7, and all-time. A detector that fired last week and is silent this week is highlighted and sorted to the top, with a one-line warning naming how many went quiet — a capture-side regression caught before the missing findings would otherwise be noticed.
- **Danger Zone** — **Discard findings & re-analyze** button that clears every finding in the database and runs a fresh analysis. Useful for clean re-baselines after threshold changes. Destructive — analyst notes and statuses on existing findings are lost; confirmation required.
- **Appearance** (available to every role) — picks the workbench color skin: **Cobalt slate** (default), **Tactical phosphor** (monospace, green accent), **GitHub dark** (dimmed), **Boardroom** (corporate light — soft gray canvas and navy accent for stakeholder/shareholder reporting), **Blackout** (true-black / OLED), plus a **Just for fun** set (Bikini Bottom, Vaporwave, Hot Dog Stand, Hollywood Hacker, Barbiecore, Nyan Cat). The choice is per-browser (localStorage `archer.theme`), applies instantly with no save or reload, and is applied before first paint so there's no flash of the default; it's also honored on the login/register pages. Skins are defined as design tokens in `web/static/css/themes.css`; the graph and beacon charts read the active skin's tokens so canvas colors track the theme too.

### New-Findings Badge

When an analysis run finishes — and once at login — a count badge appears on the **New only** button (same pill style as the notification bell) showing how many findings have been detected **since you last logged in**. The count is per-analyst and accumulates across every watch pass in between, so logging in once a day after hourly analyses shows the whole day's new findings, not just the last run's. The boundary is anchored at login and frozen for the session — it's the same cutoff the **New only** table filter uses, so the two always agree. Clicking **New only** both filters to the new findings and acknowledges the count (a server-side per-session high-water mark, not browser state) — the badge clears and stays cleared across page refreshes, returning only when the count climbs higher or a fresh login starts a new session; an unacknowledged badge deliberately survives a refresh. Acknowledging never empties the New view — the filter boundary re-anchors only at next login. Roll-ups (Host Risk Score, Correlated Activity) are excluded. The same login boundary drives the table's blue **new** dot and the detail pane's **NEW SINCE LAST LOGIN** badge, so every "new" surface agrees (the IOC purple diamond still takes precedence over the dot on a row that's both). Backed by `/api/findings/unseen` and the stable per-finding `detected_at` (migration 0029).

---

## API Reference

All API endpoints require authentication. Role requirements are noted where applicable. The single exception is `/api/version`, which is unauthenticated diagnostic.

> Full reference (every endpoint, request/response shapes, query parameters, error codes, deprecation policy): **[docs/API.md](docs/API.md)**. The summary tables below in this README are kept brief; `docs/API.md` is the contract for what counts as a breaking change.

### Build Identifier

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/version` | None | `{"version":"v0.63.0","commit":"<short-sha>","build_time":"<iso-8601>"}`. Unauthenticated — same diagnostic tier as a future `/api/health`. The values come from `internal/version` and are populated at build time via `-ldflags` from the git checkout (see `start.sh`). The web UI reads this on init to populate the statusbar version pill and the About dialog. |

### Authentication

| Method | Path | Description |
|---|---|---|
| `POST` | `/login` | Authenticate with `{"email":"...","password":"..."}` |
| `POST` | `/register` | Create account with `{"name":"...","email":"...","password":"..."}` |
| `POST` | `/logout` | Invalidate current session |

### Users

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/me` | Any | Current user profile |
| `POST` | `/api/me/password` | Any | Change own password (re-verifies current password) |
| `GET` | `/api/users` | Any | List users. Admins get every user; a non-admin gets only their own one-entry record. |
| `POST` | `/api/users` | Admin | Create user |
| `PATCH` | `/api/users/{id}` | Admin | Update user role/status, or reset the user's password |
| `DELETE` | `/api/users/{id}` | Admin | Delete user |
| `GET` | `/api/audit-log` | Admin | `{"entries":[...],"total":N,"next":<cursor>}` — cursor-paginated audit trail (id-DESC). Query params: `cursor` (exclusive, `0` = most-recent page), `count` (default 100, capped at 500). `next` is the cursor for the following page; `0` means no more. Each entry carries the structured before/after JSON written by the audit emitters. |

### Log Files

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/logs/tree` | Any | Sensor → date roll-up of `/logs` (file counts, sizes, newest mtime) |

### Analysis

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/api/analyze` | Analyst+ | Start analysis |
| `GET` | `/api/analyze/status` | Any | `{"running":bool,"paused":bool,"blocked":bool}`, plus `"pct"`/`"step"` while a run is active (so a page reloaded mid-analysis can restore its progress bar) |
| `POST` | `/api/analyze/cancel` | Analyst+ | Stop running analysis |
| `POST` | `/api/analyze/pause` | Analyst+ | Pause running analysis |
| `POST` | `/api/analyze/resume` | Analyst+ | Resume paused analysis |
| `POST` | `/api/analyze/reset` | Admin | Clear all findings and launch a fresh analysis — used for baselining after threshold changes. Returns `{"status":"started","findings_cleared":N}` |

### Findings

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/findings` | Any | List findings (projected — `ts_data` / `intervals` / `notes` stripped). Query params: `q` (the Lucene-style query language — the primary filter surface, ANDed on top of the others; a bad query returns `400` with a JSON `{error}` body rather than matching all/none — malformed syntax, an unknown field, or an exact `type:` value that isn't a real finding type are all rejected — see [docs/ANALYST_PLAYBOOK.md](docs/ANALYST_PLAYBOOK.md#querying-the-findings-table) for the grammar), `search`, `type` (exact, or the pseudo-value `beacons` for the whole beacon family), `severity`, `min_score`, `delta`, `src_ip` (IP or CIDR), `dst_ip` (IP or CIDR), `dst_port`, `sensor`, `from`, `to` (both accept `YYYY-MM-DD HH:MM:SS` UTC or RFC3339), `status` (`open` / `acknowledged` / `escalated` / `dismissed`), `include_dismissed` (`true` — fold dismissed findings into an otherwise-unscoped result; no effect when `status` is set explicitly), `ioc_only` (`true`), `spectral_only` (`true`), `ts_min`/`ts_max` · `ds_min`/`ds_max` · `hist_min`/`hist_max` · `dur_min`/`dur_max` (inclusive beacon sub-axis bounds — any one implicitly scopes to beacons), `ja3` (exact JA3 fingerprint match — powers TLS Pivot for JA3-only sensors), `ja4` (exact JA4 fingerprint match — powers TLS Pivot for JA4+ sensors), `sort`, `dir`, `limit` (default 1000, max 50000), `offset` (default 0). Sets `X-Total-Count` and `X-Has-More` response headers (and `Access-Control-Expose-Headers` so JS can read them in CORS contexts). The per-tab page-nav buttons drive this. |
| `GET` | `/api/findings/counts` | Any | `{open, ack, esc, ioc, total}` aggregate counts honoring the active filter set (`status` / `ioc_only` are stripped — the counts span all status buckets). Drives the dashboard's info-line counters without forcing a full-set scan from the client. |
| `GET` | `/api/findings/facets` | Any | `{types, sensors}` — distinct values across the filter set. `status`, `ioc_only`, `delta`, `type`, `sensor`, `limit`, `offset` are stripped so the dropdowns reflect every available value regardless of what's currently selected. Powers the Type and Sensor filter dropdowns. |
| `GET` | `/api/findings/trend` | Any | `{days, series, severity_series}` — per-UTC-day finding counts over a contiguous zero-filled day axis (bucketed on the event `timestamp` date), grouped two ways in one pass: `series` rolls the finding types into seven detection families (beaconing / ti / exfil / dns / lateral / tls / other), `severity_series` buckets by severity tier. Groups with no findings in range are omitted; roll-up types are excluded (they re-count detections already on the axis). Accepts the same filter surface as `GET /api/findings` (including `status` and `delta`; `limit`/`offset`/`sort`/`dir` are ignored) so the chart always matches the table. Powers the trend chart above the findings table. |
| `GET` | `/api/findings/unseen` | Any | Per-session new-findings count `{count, total, since, seen_count}` — findings detected since the analyst's login boundary (roll-ups excluded), plus the session's acknowledgment high-water. Same cutoff as the `delta` "New only" filter. Drives the New-only count badge (shown only when `count > seen_count`). |
| `POST` | `/api/findings/modal-ack` | Any | Acknowledge the new-findings count for this session (fired when the analyst clicks **New only**). Raises the session high-water to the current unseen count so the badge stays cleared across refreshes until the count climbs. Path name predates the badge — this was the modal's ack. |
| `GET` | `/api/findings/{id}` | Any | Single finding detail (full shape including `ts_data` / `intervals` / `notes`). |
| `GET` | `/api/findings/{id}/raw` | Any | Raw-log pivot. Returns source Zeek records matching the finding's (src, dst) pair. Query params: `limit` (default 500, max 5000), `window_hours` (default 6; `0` means no time filter — scan every matching file) |
| `GET` | `/api/findings/{id}/position` | Any | Absolute page offset of the finding under a given filter/sort, so the bell-notification **Jump** can load the page containing it. Accepts the same query params as `GET /api/findings`. |
| `GET` | `/api/findings/{id}/history` | Any | 30-day beacon-evolution series for the finding's (src, dst) pair, powering the SVG evolution chart in the detail pane. |
| `PATCH` | `/api/findings/{id}` | Analyst+ | Update status: `{"status":"acknowledged"\|"escalated","analyst":"...","note":"..."}` |
| `POST` | `/api/findings/{id}/escalate` | Analyst+ | Escalate + run TI lookups: `{"note":"...","ips":["..."],"services":["vt","crowdsec","otx","abuseipdb","greynoise","censys"]}`. Each lookup's outcome is streamed as a `ti_result` SSE event; once all settle, a single consolidated TI Enrichment note is appended to the finding. |
| `POST` | `/api/findings/{id}/notes` | Analyst+ | Add note: `{"text":"..."}` |
| `GET` | `/api/attack-coverage` | Any | MITRE ATT&CK coverage over the current findings, powering the **ATT&CK Coverage** modal. `{"techniques":[{"id","name","tactic","url","count","types":[{"type","count"}]}],"unmapped":[{"type","count"}],"total"}`. Techniques are sorted by count desc; a finding whose type maps to N techniques counts toward all N (coverage, not a partition). `unmapped` is the finding types with no ATT&CK technique (TI hits, roll-ups, Zeek notices). The finding-type → technique map itself is bootstrapped into the page as `window.ATTACK_MAP` for the detail-pane tags. |
| `GET` | `/api/fingerprints` | Any | Ranked TLS-fingerprint inventory powering the **TLS Fingerprints** modal. Returns the high-signal JA3/JA4 client fingerprints from the latest analysis pass — known-bad C2 matches (always critical) plus rare / cross-host shapes (concern ≥ medium); common browser/SDK shapes and low-confidence single-host JA3s are excluded. `[{"fingerprint","kind":"ja3"\|"ja4","level","known_bad","label","conns","src_hosts","dsts","finding_count","detail"},...]` sorted by level → src_hosts → conns. `detail` is the count-free concern reason; `finding_count` is the resident findings carrying it (a `0` row is a fingerprint that tripped no detector). Computed over the in-memory prevalence snapshot — empty before the first full pass of a process. Fingerprints marked benign via `/api/fingerprint-allowlist` are excluded (known-bad C2 matches are never excluded). |
| `GET` | `/api/fingerprint-allowlist` | Any | `[{"id","kind":"ja3"\|"ja4","fingerprint","note","created_by","created_at"},...]` — fingerprints an analyst has marked benign on the TLS Fingerprints wall. |
| `POST` | `/api/fingerprint-allowlist` | Analyst+ | Mark a fingerprint benign: `{"kind":"ja3"\|"ja4","fingerprint","note"}`. Idempotent on `(kind, fingerprint)`. Rejects (`400`) a known-bad C2 fingerprint — a confirmed C2 match can't be muted. The fingerprint drops out of `/api/fingerprints` and matching findings carry `tls_allowlisted:true`. |
| `DELETE` | `/api/fingerprint-allowlist/{id}` | Analyst+ | Remove a benign mark by id; the fingerprint returns to the inventory and the `tls_allowlisted` flag clears next fetch, no re-analysis. |

### Exports

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/export/json` | Any | Download filtered findings as JSON. Accepts every query param supported by `GET /api/findings`. The per-finding chart data (`ts_data`, `intervals`) is stripped from the output — it's only used by the in-UI beacon chart and bloats the file ~10–20×. Pass `?include_lists=true` to bundle the current allowlist and IOC list in the output (needed only for `/api/import` round-trips). |
| `GET` | `/api/export/csv` | Any | Download filtered findings as CSV. Accepts every query param supported by `GET /api/findings`. With `type=beacons` the export is beacon-scoped and **appends** ten triage columns (`ts_score`…`sample_size`, `ja3`, `ja4`) after the historical 13 — appended-not-inserted, so a column-index consumer of the default schema is unaffected. The `top_uris` footprint is JSON-export-only (a nested list doesn't fit a flat CSV cell). |
| `GET` | `/api/export/xlsx` | Any | Download filtered findings as an XLSX workbook (Findings sheet plus Campaigns and Hosts roll-up sheets). Accepts every query param supported by `GET /api/findings`. Formula-injection-neutralized like the CSV path. |
| `POST` | `/api/import` | Admin | Restore findings from a `/api/export/json` dump (admin-only — it writes findings and, with `include_lists`, the allowlist/IOC list). Imported findings are validated (type/severity/score/timestamp) and restored as non-new so they don't ring the bell. |

### Archive

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/archive` | Any | `{"enabled":bool,"after_days":N,"prune_findings_on_archive":bool,"last_run_at":"...","last_files_archived":N,"last_bytes_archived":N,"last_findings_pruned":N,"last_triggered_by":"..."}` — last_* fields are read-only telemetry omitted on a never-run instance |
| `POST` | `/api/archive` | Admin | Update archive config. Accepts `{"enabled":bool,"after_days":N,"prune_findings_on_archive":bool}` — last_* fields are ignored if sent |
| `POST` | `/api/archive/run` | Admin | Run the archive worker. Optional body `{"dry_run":true}` reports what would be moved/pruned without touching disk or the findings table; omit body or pass `{"dry_run":false}` to execute. Returns `{"files_archived":N,"bytes_archived":N,"findings_pruned":N,"skipped":N}` |
| `POST` | `/api/archive/scan` | Admin | Retroactive IOC + TI scan over `/data/archive`. Skips beacon/exfil/lateral/etc. — only the IOC list, Feodo Tracker, URLhaus, and Suspicious URL phases run. New matches surface as findings via the same fingerprint-merge as a regular run. Empty body. Returns `{"status":"started"}`; progress is emitted via the standard `progress` / `done` SSE events. |

### Disk Usage

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/disk-usage` | Any | `{"logs":{"total_bytes":N,"free_bytes":N,"sensors":[{"name":"...","bytes":N},...]},"archive":{"total_bytes":N,"free_bytes":N}}`. Server-side cached for 5 minutes — calling more often returns the cached snapshot. The Sensors modal Size column and the Settings → Operations → Log Archive (Disk Usage) block both poll this endpoint. |
| `GET` | `/api/detector-activity` | Any | `{"window_days":7,"generated_at":"...","detectors":[{"type":"Beacon","count_7d":N,"count_prior_7d":N,"total":N,"dropped":false},...]}` — per-type new-detection counts (by `detected_at`) for the last 7 days vs the prior 7, plus the all-time total. `dropped` is true when a detector fired in the prior window but is silent in the recent one — a capture-side regression signal. Roll-up types (Host Risk Score, Correlated Activity) are excluded; results sort dropped-first. Drives Settings → Operations → Detector Health. |

### Configuration

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/config` | Any | Get all thresholds and API key presence |
| `PUT` | `/api/config` | Admin | Replace full config (JSON body matching config schema) |

### Lists

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/allowlist` | Any | `["ip-or-domain", ...]` |
| `PUT` | `/api/allowlist` | Analyst+ | Replace allowlist: `["ip-or-domain", ...]` |
| `GET` | `/api/ioc` | Any | `["ip-or-domain", ...]` |
| `PUT` | `/api/ioc` | Analyst+ | Replace IOC list: `["ip-or-domain", ...]` |
| `GET` | `/api/ioc?kind=fp` | Any | JA3/JA4 fingerprint IOCs: `{"builtin":[{"kind","fingerprint","label"},...],"operator":["fp",...]}`. `builtin` is the always-active `KnownBadJA3`/`KnownBadJA4` tables (informational); `operator` is the editable list. |
| `PUT` | `/api/ioc?kind=fp` | Analyst+ | Replace the operator JA3/JA4 list: `["fp", ...]`. Built-in fingerprints and comment lines are dropped server-side; entries are lowercased and deduped. Matches emit **Malicious JA3 / JA4** on the next full analysis. |
| `POST` | `/api/ioc-fingerprint` | Analyst+ | Add one fingerprint to the operator JA3/JA4 list (the **Mark malicious** button): `{"fingerprint":"..."}`. A built-in fingerprint is a no-op success (`{"ok":true,"builtin":true}`). |

### Suppressions

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/suppressions` | Any | `[{"target":"1.2.3.4","expiry":1234567890,"detail":"..."},...]` |
| `POST` | `/api/suppressions` | Analyst+ | Add suppression: `{"target":"1.2.3.4","days":7,"detail":"..."}` |
| `DELETE` | `/api/suppressions/{target}` | Analyst+ | Remove suppression immediately |

### Relationship Allowlist

UI: the **Allowlist** modal's **Relationships** tab (the standalone
Pair Allowlist sidebar dialog was removed in v0.25.0). The API route
is unchanged — still `/api/pair-allowlist`.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/pair-allowlist` | Any | `[{"id":1,"src":"10.0.0.1","dst":"1.1.1.1","port":"53","finding_type":"Beacon","detail":"...","created_by":"...","created_at":1234567890},...]` |
| `POST` | `/api/pair-allowlist` | Analyst+ | Add a tuple-scoped view filter: `{"src","dst","port","finding_type","detail"}` (empty `finding_type` = all types on the tuple). `src` and `dst` each accept a single IP, a CIDR range (`10.0.0.0/24`, `2001:db8::/32`), a domain (`skype.com`), or a `*.domain` wildcard (`*.skype.com` — apex plus every name under it; DNS and TI-domain findings carry the domain as their destination); anything that parses as none of those is a `400`. No expiry — removal is explicit. |
| `DELETE` | `/api/pair-allowlist/{id}` | Analyst+ | Remove rule by id; matching findings reappear next fetch, no re-analysis |
| `GET` | `/api/pair-allowlist/suggested` | Any | Beacon pairs that qualify for suggestion: 14+ history days, acknowledged finding, not already allowlisted. `[{"src_ip","dst_ip","dst_port","finding_type","day_count","first_seen","last_seen","peak_score","acked_by"},...]` |

### Notifications

The bell fires for new findings with **`score >= 95`** — the top-tier confidence bucket the scoring formulas were calibrated to reach. The initial v0.17.0 cut at `>= 99` over-corrected (excluded most CRITICAL TI hits); v0.17.1 lowered the floor to 95 after operator feedback. Previous behaviour (CRITICAL severity or any TI type, regardless of score) fired often enough that operators learned to ignore the bell. `Host Risk Score` is still excluded — it's a per-host roll-up, not a discrete event, and the underlying network detections have already generated their own notifications. The bell also gates on the active allowlist + suppressions (v0.18.1 NEW-111): findings whose src or dst is hidden from the table at emit time skip the bell entirely, and adding an IP to the allowlist / suppression dismisses any active notification whose row would now be invisible.

Beyond detection findings, the bell also surfaces three operational alarms (each `Notification` carries a `kind` field — `finding`, `sensor`, or `feed`; empty reads as `finding` for backward compat):

- **`kind=sensor` / type `Sensor stale`** — heartbeat alarm. Emitted when an enrolled sensor's `last_seen_at` is older than the configurable `sensor_stale_threshold_hours` (default 2h). Transition-edge dedup: one alarm per staleness episode, cleared when the sensor checks in again. The **Jump** button opens the Sensors modal. External monitoring can read the same staleness state from [`GET /api/sensors/health`](#sensors).
- **`kind=sensor` / type `Sensor rsync stopped`** — rsync-dead alarm. Emitted when a sensor is actively checking in (fresh `last_seen_at`) but the sensor's log directory mtime has not advanced in more than `rsync_stale_threshold_hours` (default 4h). Indicates a live sensor that has stopped pushing logs — rsync configuration or connectivity issue on the sensor side. Same transition-edge dedup and **Jump** → Sensors modal.
- **`kind=feed`** — feed reliability alarm. Emitted when an enabled feed has either `consecutive_failures >= 3` or has gone `feed_stale_threshold_hours` (default 24h) without a successful refresh. Same transition-edge dedup. The **Jump** button opens the Feeds modal.

Each notification has a **Jump** button. For `kind=finding` it lands the analyst on the page containing that finding, regardless of the active tab's filter, sort, pagination, or delta-mode state — clears every filter input (search, src/dst/port, severity, type, sensor, score floor, spectral-only, time range → All time, delta off), switches to the tab matching the finding's status, queries `/api/findings/{id}/position` to find the absolute offset under the cleared filter, fetches the page that contains it, and scrolls the row into view. Filters that the analyst had set are intentionally lost — the Jump is a "show me this finding now" action; rebuilding the filter is the cost of guaranteed visibility. For `kind=sensor` / `kind=feed` the Jump opens the corresponding modal so the operator can investigate the offending sensor or feed.

A small green/red dot in the top bar tracks the `watch.heartbeat` SSE event (60s tick, unconditional). After 180s without a beat the dot flips red — proves the SSE pipeline is alive vs wedged.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/notifications` | Any | List alert notifications |
| `POST` | `/api/notifications` | Any | `{"action":"dismiss","id":N}` or `{"action":"dismiss_all"}` |

### Watch Mode

Watch ticks run in two tiers, automatic from the configured cadence:

- **First tick of each UTC calendar day → full analysis.** All phases (Beacon, HTTP analysis, DNS, SSL, X.509, Files, Weird, Notices, TI, Host Risk Score). Statistical detectors need the long temporal window to spot patterns, so they get refreshed daily. Before the full pass launches, every enabled MISP / OpenCTI feed is refreshed in parallel under a 10-minute global cap. Admins can also trigger a one-off refresh per feed via the Feeds modal's per-row kebab → **Refresh** (`POST /api/feeds/{id}/refresh`) — same 10-minute cap, detached from the inbound request context so a browser disconnect doesn't kill the fetch.
- **Subsequent same-day ticks → incremental TI pass.** Only Phase 0 (feed prefetch — built-in Feodo Tracker / URLhaus only, no MISP/OpenCTI fetch) + Phase 3 (TI matching over the file subset modified since the last run). MISP / OpenCTI matching uses the indicator cache populated by the most recent full pass, so fresh hits from configured feeds surface within one tick interval without paying the upstream fetch cost. Stateless per-record, fast — typically seconds instead of the full-window minutes-to-hours.

The decision is automatic and persisted: `LastFullAnalysisUnix` (most recent full run) gates the full/incremental switch, `LastAnalysisUnix` (most recent run of either kind) is the mtime cutoff for the incremental file filter (with a 5-minute overlap so a log rotated at the boundary gets re-checked instead of missed). Manual "Discard findings & re-analyze" runs as a full pass and resets both timestamps, so the cycle restarts cleanly.

The `done` SSE event for incremental ticks includes `"incremental": true` so the UI can distinguish them from full-pass completions.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/watch` | Any | `{"time":"HH:MM","enabled":bool,"timezone":"America/New_York","timezone_abbr":"EDT","interval_hours":N,"next_run":"today 06:00","next_run_kind":"full|incremental","next_full_run":"tomorrow 00:00"}` — `interval_hours` is one of `24` (daily), `12`, `6`, `4`, or `1` (hourly). Sub-daily cadences anchor on the configured minute-of-hour. `timezone_abbr` is the resolved abbreviation (`EDT`, `PST`, `UTC`, …) — the long IANA name in `timezone` is the source of truth, this is the display form. `next_run` and `next_full_run` are pre-formatted relative-date strings (`today HH:MM`, `tomorrow HH:MM`, `Mon HH:MM` for same-week, `Jan 2 HH:MM` for further-out, year added only when it differs from the current calendar year) — no timezone is appended since the abbreviation is shown once on the cadence head. `next_run_kind` reflects the two-tier cadence: `"full"` when the upcoming tick is the daily full-pipeline pass (statistical detectors refresh), `"incremental"` when it's the hourly TI/IOC pass over mtime-filtered new files only. `next_full_run` always reports when the next full pipeline pass will fire — equals `next_run` for daily cadence and for sub-daily ticks where the next tick happens to be the full one. The sidebar's schedule preview surfaces all three so an analyst knows whether beacon detection will refresh at the next tick or wait until the daily slot. |
| `POST` | `/api/watch` | Admin | `{"time":"HH:MM","enabled":bool,"timezone":"America/New_York","interval_hours":N}` — empty `timezone` means UTC. Server validates the IANA name with `time.LoadLocation`; bad names return 400. `interval_hours` must be one of `1`, `4`, `6`, `12`, `24`; out-of-range values fall back to daily. |

### Threat Intelligence

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/ti/services` | Any | `{"vt":bool,"crowdsec":bool,"otx":bool,"abuseipdb":bool,"greynoise":bool,"censys":bool}` — true means API key is configured. `greynoise` is always `true` (Community API works unauthenticated; supplying a key only raises the rate limit). `censys` is true only when both API ID and Secret are configured. |

### Feeds (Admin UI)

Endpoints powering the Feeds modal. Listing is open to any authenticated user; create / update / delete / refresh are admin-only and enforce the role inside the handler. Full request / response shapes are in [`docs/API.md`](docs/API.md); operator-facing setup, indicator types, and troubleshooting are in [`docs/FEEDS.md`](docs/FEEDS.md).

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/feeds` | Any | List configured feeds. `api_key` is redacted; the response carries `has_api_key` instead. Each row also carries `last_fetch_truncated` (bool) — `true` when the most recent fetch hit the adapter's page-walk cap with the upstream still indicating more data. |
| `POST` | `/api/feeds` | Admin | Create a feed. Required: `source_type` (`misp` / `opencti`), `name`, `url`, `api_key`, `indicator_aging_days`. Optional: `enabled`, `tls_skip_verify`, `allow_internal` (per-feed SSRF opt-out for internal MISP / OpenCTI at RFC1918 addresses; v0.18.5+). Audit-logged. |
| `PUT` | `/api/feeds/{id}` | Admin | Update a feed. Empty `api_key` keeps the existing value. `allow_internal` is captured in the `feed_update` before/after audit map. |
| `DELETE` | `/api/feeds/{id}` | Admin | Delete a feed. FK cascade drops its `feed_indicators`. |
| `POST` | `/api/feeds/{id}/refresh` | Admin | One-shot fetch + upsert + prune (10-minute hard cap, v0.19.0+). Detached from the request context so a browser disconnect doesn't kill the fetch. Backed by the **Refresh** item in the Feeds dialog's per-row kebab. |

### Sensors (Admin UI)

Endpoints powering the Sensors modal. Read endpoints are open to admin + analyst; write endpoints are admin-only and enforce the role inside the handler.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/sensors` | Analyst+ | List every sensor row (any status), most recent enrollment first |
| `GET` | `/api/sensors/health` | Any / `X-Archer-Token` | Per-sensor staleness state for scrape tooling and analyst-facing scripts: `{"sensors":[{"name":"...","last_seen_at":N,"stale":bool,"stale_for_seconds":N,"stale_threshold_sec":N}]}`. `stale_threshold_sec` reflects the configurable `sensor_stale_threshold_hours` (default 2h). Skips disenrolled sensors; never-reported sensors render with `stale=false` (the clock hasn't started). Accepts a session cookie or an `X-Archer-Token` service-account token — suitable for Prometheus/Nagios scraping. |
| `GET` | `/api/sensors/info` | Admin | `{"tls_fingerprint":"...","sensor_facing_host":"...","effective_host":"...","server_protocol_version":2,"supported_protocol_versions":[2]}` for rendering install one-liners and the Sensors-modal protocol compatibility matrix |
| `PUT` | `/api/sensors/host` | Admin | `{"host":"192.0.2.10"}` (or `"host:port"`); set the sensor-facing override that install one-liners target |
| `GET` | `/api/sensors/tokens` | Admin | List enrollment tokens (used + unused) |
| `POST` | `/api/sensors/tokens` | Admin | `{"override_name":"..."}` mints a new single-use 24h token; returns `{token, override_name, created_at, expires_at, ...}` |
| `POST` | `/api/sensors/tokens/revoke` | Admin | `{"id":N}` deletes an outstanding token row |
| `POST` | `/api/sensors/disenroll` | Admin | `{"id":N}` flips the row to `disenrolling`, removes the authorized_keys line; the sensor self-cleans on its next checkin |
| `POST` | `/api/sensors/purge` | Admin | `{"id":N}` archives `/logs/<name>/`, retags findings, drops the sensor row (only allowed once status is `disenrolled`) |
| `POST` | `/api/sensors/schedule` | Admin | `{"id":N,"hour":0,"minute":N}` reassigns the push minute (hour is unused under hourly mode but accepted for backward compat) |
| `GET` | `/api/sensors/unauthorized` | Analyst+ | List recent unrecognized checkin attempts |
| `POST` | `/api/sensors/unauthorized/dismiss` | Admin | `{"id":N}` removes an unauthorized-attempt row |

### Service-Account Tokens

Machine-to-machine tokens for endpoints that must be reachable by scrape tooling (Prometheus, Nagios, shell scripts) that cannot hold a browser session. Currently accepted by `GET /api/sensors/health` via the `X-Archer-Token` request header.

Tokens are generated as `archer_<40-hex-chars>`. The raw value is returned once at creation and never stored — the database holds only the SHA-256 hash. Each token has a label and is tied to the admin who created it.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/service-tokens` | Admin | `[{"id":N,"label":"...","created_at":N,"created_by":"..."},...]` — raw token never included. |
| `POST` | `/api/service-tokens` | Admin | `{"label":"..."}` — creates a token; returns `{"id":N,"label":"...","token":"archer_...","created_at":N,"created_by":"..."}`. Raw token returned once only. Audit-logged. |
| `DELETE` | `/api/service-tokens/{id}` | Admin | Revokes and removes the token. Audit-logged. |

### Quiver (sensor-facing, no session auth)

These endpoints are served on the TLS listener (`:8443`) and authenticated by single-use enrollment tokens (HTTPS) or per-sensor ed25519 keys (rsync sshd, host port `:2222`). They have no session cookies.

| Method | Path | Description |
|---|---|---|
| `GET` | `/quiver/install.sh` | Renders the install bash for the requesting host. Embeds the TLS fingerprint, host, ports, and base64-encoded daily + uninstall scripts so the install runs without a second network hop. |
| `POST` | `/api/quiver/enroll` | Body `{token, name, host, pubkey, protocol_version}` (current `protocol_version` is `2`). Validates the token + protocol version, validates `pubkey` is a recognized SSH key type with a base64-decodable blob, creates `/logs/<name>/`, writes the per-sensor `authorized_keys` line, persists the sensor row. Returns `{name, schedule_hour:0, schedule_minute:N, protocol_version, checkin_secret}` — `checkin_secret` is returned exactly once at enrollment and HMACs every subsequent checkin (NEW-16). A malformed `pubkey` returns HTTP 400 before any row is written; unsupported protocol versions return HTTP 400 with `{error, sensor_version, server_version, supported_versions}`. |
| `POST` | `/api/quiver/checkin` | Body `{name, protocol_version}` plus an `X-Quiver-Sig` header carrying the hex-encoded HMAC-SHA256 of the body keyed by `checkin_secret`. Returns `{"status":"enrolled","schedule":{"hour":0,"minute":N},"protocol_version":2}`, `{"status":"disenrolled","protocol_version":2}`, `{"status":"unknown","protocol_version":2}`, or `{"status":"protocol_unsupported","sensor_version":N,"server_version":2,"supported_versions":[2]}`. Unknown checkins (including signature failures) create `unauthorized_attempts` rows and push an SSE event. v1 sensors are no longer accepted — the v0.12.0 NEW-16 upgrade requires re-enrolling every sensor to issue a fresh checkin_secret. |

See [docs/QUIVER.md](docs/QUIVER.md) for the full Quiver protocol description.

### Real-Time Events

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/events` | Any | SSE stream. Event types: `progress` `{"pct":N,"step":"..."}`, `status` `{"msg":"..."}`, `done` `{"count":N,"new_count":N,"cancelled":bool}`, `notification` (`Notification` row — `kind` field is `finding`/`sensor`/`feed`; empty reads as `finding`), `ti_result` `{"finding_id":N,"source":"...","detail":"...","hit":bool}`, `ti_done` `{"finding_id":N,"hits":N}`, `unauthorized_attempt` (full unauthorized-attempt row when an unknown sensor name checks in), `sensor_enrolled` (full sensor row when a fresh enrollment completes — drives the in-flight enrollment dialog's confirmation tick and the parent Sensors table refresh), `watch.heartbeat` `{}` (unconditional 60s tick — UI flips a top-bar dot red after 180s without one), `resync_required` `{}` (SSE buffer overflowed for a slow client — the UI refetches source-of-truth endpoints rather than trusting its now-gapped event stream) |

---

## Versioning

Archer uses [Semantic Versioning](https://semver.org/) under the **0.x prefix**: `v0.MAJOR.MINOR`. Pre-1.0 minor versions may break any of four surfaces without a major bump:

1. **HTTP/SSE API contract** — renamed/removed `/api/*` fields, changed event shapes.
2. **DB schema** — table changes that require migration on upgrade.
3. **Quiver sensor protocol** — enrollment payload shape, rsync layout, ports, schedule contract.
4. **Detection semantics** — score formulas, thresholds, finding types, feed-matching logic.

These four surfaces become the stability contract once Archer reaches 1.0. Until then, releases call out breakage explicitly in `CHANGELOG.md` under `### Breaking` and (for detection-formula changes that may shift existing scores) `### Detection changes`.

**The current release** is identified by:

- `GET /api/version` — programmatic.
- The version pill at the bottom-right of the analyst UI status bar — clickable for build details (commit, build time).
- `docker inspect archer` — OCI image labels (`org.opencontainers.image.version`, `org.opencontainers.image.revision`).
- `git describe --tags` in the source checkout.

**To cut a release**, see [RELEASING.md](RELEASING.md) for the operator runbook.

**Release history** lives in [CHANGELOG.md](CHANGELOG.md), formatted per [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## Resetting to Factory State

Two paths, depending on scope.

**Soft reset — clear findings only.** From the Settings dialog, **Admin → Danger Zone → Discard findings & re-analyze** drops every finding in the database and relaunches analysis against the current log set. User accounts, allowlists, IOC lists, suppressions, threshold config, and API keys are preserved. Useful after threshold changes when you want a clean finding baseline without losing operator state.

**Hard reset — wipe the database volumes.** `reset.sh` stops Archer, removes the named Docker volumes (`archer-data`, `archer-sshd`, `archer-quiver` — i.e. SQLite DB, TLS material, sshd host keys, sensor `authorized_keys`), and starts a fresh instance. Log files in `./logs` are not affected. **Note:** wiping `archer-quiver` invalidates every enrolled sensor's pubkey — you'll need to re-enroll them. Wiping `archer-sshd` rotates the sshd host keys, so existing sensors' `known_hosts` will see a host-key mismatch on next push and need to re-pin (re-enrollment is the simplest path).

```bash
sudo ./reset.sh
```

The script prompts for confirmation before taking any action. After reset, navigate to `https://localhost:8443/` and register a new admin account.

---

## Running Without Docker

```bash
# Install Go 1.25+
go build -o archer ./cmd/archer

# Run (requires a writable data directory and a logs directory)
./archer \
  --tls-addr=:8443 \
  --web-dir=./web \
  --logs-dir=/path/to/zeek/logs \
  --data-dir=/path/to/data
```

The binary has no runtime dependencies beyond the operating system. SQLite is compiled in via a pure-Go driver — no `libsqlite3` required.

---

## Contributors

- [teehootchens](https://github.com/teehootchens)

---

## License

MIT License

Copyright (c) 2026 BushidoCyb3r

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
