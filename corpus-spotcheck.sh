#!/usr/bin/env bash
# corpus-spotcheck.sh — validates the spectral rescue plausibility gate
# against live findings in the Archer database.
#
# The gate is lower-bound only: spectral_period >= median_interval/5.
# There is no upper bound because burst-connect beacons (many connections
# per burst, long silence between bursts) have true spectral periods that
# are legitimately orders of magnitude above the median inter-arrival.
#
# Checks (1-2 validate the spectral gate; 3-12 are census/advisory sweeps over
# recent findings — there is no check 5, the number was retired):
#   1. PASS/FAIL — any rescued finding with spectral_period below
#      median_interval/5 is an artifact that slipped through the gate
#      (gate too loose, or a novel artifact shape not covered by the
#      lower-bound criterion).
#   2. ADVISORY — rescued findings that also contain a suppressed artifact
#      in the detail string. These fired on a plausible peak alongside a
#      rejected shorter-period peak; a human should eyeball whether the
#      suppressed period looks burst-shaped or beacon-shaped.
#   3. ADVISORY — fully-blocked rescues over recent runs.
#   4. ADVISORY — Port-Hopping Beacon census.
#   6. ADVISORY — per-channel beacon census.
#   7. ADVISORY — Protocol on Unexpected Port census.
#   8. ADVISORY — Multi-Stage Beacon census.
#   9. ADVISORY — service-triggered Lateral Movement census.
#  10. ADVISORY — C2 Port service cross-check census.
#  11. ADVISORY — Admin Protocol Egress census.
#  12. ADVISORY — Database Protocol Egress census.
#
# What this script CANNOT check: findings where rescue was blocked entirely
# because the only strong peak was below median/5. Those pairs still emit
# a beacon finding (at reduced score, without the spectral rescue credit),
# and the blocked artifact is logged at slog.Debug level at analysis time.
# If you need to audit fully-blocked rescues, filter the Archer log for
# "spectral artifact rejected".
#
# Usage:  bash corpus-spotcheck.sh [/path/to/archer.db]
#         default path: /data/archer.db
set -euo pipefail

DB="${1:-/data/archer.db}"

if [ ! -f "$DB" ]; then
    echo "ERROR: database not found at $DB" >&2
    exit 2
fi

# Spectral data lives in beacon_history. findings carries median_interval.
# The rescues we care about are in findings.detail (new-code format after
# re-analysis): "Spectral rescued: score=X (period Ys, N×median, ...)".
# Pre-re-analysis (old-code detail format), there is no ratio in the
# detail string — run analysis with the new code before using this script.

# ── Timing-layer census (advisory) ───────────────────────────────────────────
# Runs first, and regardless of whether any spectral rescue fired — the rest of
# this script validates spectral specifically, but the census exists to place
# spectral among the four timing layers (max(ts_raw, ts_mm, ts_ent, spectral)),
# and is most informative precisely when spectral is NOT the driver. Counts how
# often each layer is the deciding one; the winner expression mirrors conn.go's
# strict-greater upgrade chain (spectral if it rescued, else the highest of
# raw/mm/ent with raw winning ties). A spectral share that dwarfs the others, or
# an entropy/multimodal share climbing across runs, is a cue to validate that
# layer against analyst dispositions — which beacon-attribution.sh crosstabs in
# full. Requires migration 0034 (per-layer columns on findings).

LAYERS_OK=$(sqlite3 "$DB" "
  SELECT COUNT(*) FROM pragma_table_info('findings') WHERE name = 'ts_raw';
")

if [ "$LAYERS_OK" -eq 0 ]; then
    echo "INFO: findings.ts_raw not present (pre-0034 schema) — deploy current code,"
    echo "  re-run a full analysis, and re-run to see the timing-layer census."
else
    LAYER_BEACONS=$(sqlite3 "$DB" "
      SELECT COUNT(*) FROM findings
      WHERE type IN ('Beacon','HTTP Beacon','DNS Beacon','Port-Hopping Beacon')
        AND sample_size > 0;
    ")
    if [ "$LAYER_BEACONS" -eq 0 ]; then
        echo "INFO: no re-analysed beacon findings to attribute (run a full pass after 0034)."
    else
        echo "Deciding timing layer across $LAYER_BEACONS beacon finding(s):"
        sqlite3 -column -header "$DB" "
          SELECT CASE
                   WHEN spectral_rescued = 1            THEN 'spectral'
                   WHEN ts_ent > ts_raw AND ts_ent > ts_mm THEN 'entropy'
                   WHEN ts_mm  > ts_raw                 THEN 'multimodal'
                   ELSE 'raw'
                 END AS layer,
                 COUNT(*)              AS n,
                 ROUND(AVG(score), 1)  AS avg_score,
                 SUM(severity = 'CRITICAL') AS critical,
                 SUM(status = 'dismissed')  AS dismissed
          FROM findings
          WHERE type IN ('Beacon','HTTP Beacon','DNS Beacon','Port-Hopping Beacon')
            AND sample_size > 0
          GROUP BY layer
          ORDER BY n DESC;"
        echo ""
        echo "For the full per-finding crosstab (layer × severity, layer × disposition):"
        echo "  bash beacon-attribution.sh \"$DB\""
    fi
fi
echo ""

TOTAL=$(sqlite3 "$DB" "
  SELECT COUNT(*) FROM findings
  WHERE detail LIKE '%Spectral rescued%'
    AND median_interval > 0;
")
echo "Spectral-rescued findings with median_interval: $TOTAL"

if [ "$TOTAL" -eq 0 ]; then
    echo "PASS: no spectral-rescued findings to validate."
    echo "      (If you expected rescues, run analysis with the current code first.)"
fi

# Checks 1-2 validate the spectral-rescued findings themselves, so they only run
# when rescues exist. The detector censuses further down (blocked-rescue trend,
# Port-Hopping, per-channel, protocol-on-unexpected-port) are independent of
# spectral rescue and run regardless — so a corpus with no rescues no longer
# short-circuits the whole script before reaching them.
if [ "$TOTAL" -gt 0 ]; then

    # ── Check 1: lower-bound plausibility (PASS/FAIL) ──────────────────────
    # Extract spectral_period from the new-format detail string:
    # "Spectral rescued: score=X.XX (period Ys, N×median, ...)"
    # Note: old-format detail has "dominant period Ys" — different keyword.
    # Run analysis with current code to populate the new format before running.

    VIOLATIONS=$(sqlite3 "$DB" "
      WITH rescued AS (
        SELECT id, type, src_ip, dst_ip, score, severity, median_interval,
               CAST(
                 SUBSTR(detail,
                   INSTR(detail, 'period ') + 7,
                   INSTR(SUBSTR(detail, INSTR(detail, 'period ') + 7), 's') - 1
                 ) AS REAL
               ) AS spectral_period
        FROM findings
        WHERE detail LIKE '%Spectral rescued%'
          AND detail LIKE '% period %s,%'
          AND median_interval > 0
      )
      SELECT COUNT(*) FROM rescued
      WHERE spectral_period > 0
        AND spectral_period < median_interval / 5.0;
    ")

    echo "Gate violations (spectral_period < median/5): $VIOLATIONS"

    if [ "$VIOLATIONS" -gt 0 ]; then
        echo ""
        echo "FAIL: $VIOLATIONS rescued finding(s) have spectral_period below median/5:"
        sqlite3 -column -header "$DB" "
          WITH rescued AS (
            SELECT id, type, src_ip, dst_ip, score, severity, median_interval,
                   CAST(
                     SUBSTR(detail,
                       INSTR(detail, 'period ') + 7,
                       INSTR(SUBSTR(detail, INSTR(detail, 'period ') + 7), 's') - 1
                     ) AS REAL
                   ) AS spectral_period
            FROM findings
            WHERE detail LIKE '%Spectral rescued%'
              AND detail LIKE '% period %s,%'
              AND median_interval > 0
          )
          SELECT id, src_ip, dst_ip, type, score,
                 ROUND(spectral_period, 1)       AS spectral_period,
                 ROUND(median_interval, 1)       AS median_interval,
                 ROUND(spectral_period / median_interval, 4) AS ratio
          FROM rescued
          WHERE spectral_period > 0
            AND spectral_period < median_interval / 5.0
          ORDER BY ratio ASC;"
        echo ""
        echo "Remediation: the plausibility gate (median/5 lower bound) is not blocking"
        echo "these artifacts. Investigate the pair's connection pattern to understand"
        echo "why the short-period artifact survives — the burst clustering may be real."
        exit 1
    fi

    echo "PASS: all spectral-rescued findings have period >= median/5 (no artifacts slipping through)."

    # ── Check 2: suppressed artifacts alongside successful rescues (advisory) ──
    # These findings rescued on a plausible peak but also had a rejected
    # shorter-period artifact. A human should check whether the suppressed
    # period is clearly burst-shaped (artifact) or suspiciously beacon-shaped.

    SUPPRESSED=$(sqlite3 "$DB" "
      SELECT COUNT(*) FROM findings
      WHERE detail LIKE '%[artifact%suppressed]%';
    ")

    if [ "$SUPPRESSED" -gt 0 ]; then
        echo ""
        echo "ADVISORY: $SUPPRESSED finding(s) rescued on a plausible peak but with a"
        echo "suppressed artifact alongside. Eyeball these — confirm the suppressed"
        echo "period is burst-shaped (artifact), not beacon-shaped (real detection missed):"
        sqlite3 -column -header "$DB" "
          SELECT id, src_ip, dst_ip, type, score,
                 ROUND(median_interval, 1) AS median_interval,
                 SUBSTR(detail,
                   INSTR(detail, '[artifact'),
                   INSTR(detail, 'suppressed]') - INSTR(detail, '[artifact') + 11
                 ) AS suppressed_peak
          FROM findings
          WHERE detail LIKE '%[artifact%suppressed]%'
          ORDER BY score DESC
          LIMIT 30;"
        echo ""
        echo "Rule of thumb: if suppressed_period is < median/100, it's burst-shaped."
        echo "If suppressed_period is within an order of magnitude of median, investigate."
    fi
fi

# ── Check 3: fully-blocked rescues over recent runs (advisory) ───────────────
# A fully-blocked rescue is a pair where the plausibility gate rejected the
# ONLY strong periodogram peak. The pair still emits a beacon finding (at
# reduced score, without spectral credit), but the spectral evidence was
# suppressed. Accumulated across runs in analysis_stats so the trend is
# visible without relying on log lines. Non-zero is not always a problem —
# daily management traffic on long-lived sessions routinely lands here —
# but a high count or a sudden spike warrants spot-checking whether any
# legitimately periodic pair is being systematically under-scored.

STATS_OK=$(sqlite3 "$DB" "
  SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='analysis_stats';
")

if [ "$STATS_OK" -eq 0 ]; then
    echo ""
    echo "INFO: analysis_stats table not present — deploy current code and re-run."
else
    BLOCKED_TOTAL=$(sqlite3 "$DB" "
      SELECT COALESCE(SUM(spectral_blocked), 0)
      FROM (SELECT spectral_blocked FROM analysis_stats ORDER BY run_at DESC LIMIT 10);
    ")
    BLOCKED_RUNS=$(sqlite3 "$DB" "
      SELECT COUNT(*) FROM (SELECT 1 FROM analysis_stats ORDER BY run_at DESC LIMIT 10);
    ")
    if [ "$BLOCKED_TOTAL" -gt 0 ]; then
        echo ""
        echo "ADVISORY: $BLOCKED_TOTAL fully-blocked spectral rescue(s) across the last"
        echo "  $BLOCKED_RUNS recorded run(s). Pairs with only a short-period artifact"
        echo "  (< ivMedian/5) still emit beacon findings but without spectral credit."
        echo "  Per-run breakdown:"
        sqlite3 -column -header "$DB" "
          SELECT datetime(run_at, 'unixepoch') AS run_at, spectral_blocked
          FROM analysis_stats
          ORDER BY run_at DESC
          LIMIT 10;"
        echo ""
        echo "To identify blocked pairs: docker logs archer 2>&1 |"
        echo "  grep 'spectral artifact rejected' | tail -20"
    else
        echo "PASS: no fully-blocked spectral rescues in the last $BLOCKED_RUNS run(s)."
    fi
fi

# ── Check 4: Port-Hopping Beacon census (advisory) ───────────────────────────
# Port-Hopping Beacon is a downstream relabel of a Beacon that spans many
# destination ports with no dominant one. Because it is a relabel and never
# a gate, "no CRITICAL lost" holds by construction: every hopper would have
# emitted as a Beacon at the identical score. What this census exists to
# answer is the other half of the gate — does the relabel earn its FP budget?
# A healthy corpus shows a small set whose top scorers are plausibly C2
# (high ts/ds, persistent). A flood of low-score hoppers spread over wide
# ephemeral-port ranges is benign fan-out (P2P/RPC) — candidate allowlist
# entries, not a tuning emergency (the score is unchanged either way).

HOPPERS=$(sqlite3 "$DB" "
  SELECT COUNT(*) FROM findings WHERE type = 'Port-Hopping Beacon';
")

if [ "$HOPPERS" -gt 0 ]; then
    echo ""
    echo "ADVISORY: $HOPPERS Port-Hopping Beacon finding(s). Eyeball the top scorers —"
    echo "confirm the port spread looks like deliberate rotation (C2), not benign"
    echo "ephemeral-port fan-out (P2P/RPC, which is allowlist material):"
    sqlite3 -column -header "$DB" "
      SELECT id, src_ip, dst_ip, score, severity,
             ROUND(median_interval, 1) AS median_interval,
             SUBSTR(detail,
               INSTR(detail, 'Port-hopping:'),
               160
             ) AS port_spread
      FROM findings
      WHERE type = 'Port-Hopping Beacon'
      ORDER BY score DESC
      LIMIT 30;"
    echo ""
    echo "Severity split (relabel preserves the Beacon score, so this also stands"
    echo "as the by-construction proof that no CRITICAL was demoted by the relabel):"
    sqlite3 -column -header "$DB" "
      SELECT severity, COUNT(*) AS n, ROUND(AVG(score), 1) AS avg_score
      FROM findings
      WHERE type = 'Port-Hopping Beacon'
      GROUP BY severity
      ORDER BY avg_score DESC;"
else
    echo ""
    echo "INFO: no Port-Hopping Beacon findings in this corpus."
fi

# ── Check 6: per-channel beacon census (advisory) ────────────────────────────
# Per-channel scoring (Fork A) is non-destructive: a promoted channel is an
# overlay on top of the blend it split from, emitted only when a coherent JA3
# channel scores STRICTLY HIGHER than the blend. "No detection lost" therefore
# holds by construction — the blend is always kept. What this census answers is
# the other half of the gate: does the split earn its false-positive budget? A
# healthy corpus shows a small set of promoted channels whose top scorers are
# plausibly C2 (high score, hidden inside a lower-scoring blend). A flood of
# marginally-above-blend channels is fragmentation noise — a cue to raise the
# promotion margin, not a correctness failure (the blend is unaffected).

CHAN_OK=$(sqlite3 "$DB" "
  SELECT COUNT(*) FROM pragma_table_info('findings') WHERE name = 'channel';
")
if [ "$CHAN_OK" -eq 0 ]; then
    echo ""
    echo "INFO: findings.channel not present (pre-0035 schema) — deploy current code,"
    echo "  re-run a full analysis, and re-run to see the per-channel census."
else
    CHANS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM findings WHERE channel <> '';")
    if [ "$CHANS" -eq 0 ]; then
        echo ""
        echo "INFO: no per-channel beacon findings in this corpus."
    else
        echo ""
        echo "ADVISORY: $CHANS promoted per-channel beacon(s). Each split out of a blend"
        echo "it scored higher than — eyeball that the top scorers look like a real channel"
        echo "hidden in noisier co-traffic, not marginal fragmentation:"
        sqlite3 -column -header "$DB" "
          SELECT id, src_ip, dst_ip, score, severity,
                 SUBSTR(channel, 1, 16) AS channel,
                 ROUND(median_interval, 1) AS median_interval
          FROM findings
          WHERE channel <> ''
          ORDER BY score DESC
          LIMIT 30;"
        echo ""
        echo "Severity split (promoted only because they out-scored their blend — a"
        echo "concentration at LOW/MEDIUM suggests the promotion margin is too generous):"
        sqlite3 -column -header "$DB" "
          SELECT severity, COUNT(*) AS n, ROUND(AVG(score), 1) AS avg_score
          FROM findings
          WHERE channel <> ''
          GROUP BY severity
          ORDER BY avg_score DESC;"
    fi
fi

# ── Check 7: Protocol on Unexpected Port census (advisory) ───────────────────
# This detector keys on Zeek's DPD service vs. the curated expectedServicePorts
# whitelist: a recognized protocol egressing on a port outside its set. Unlike
# the relabel/overlay detectors above, this one EMITS a finding that wouldn't
# otherwise exist, so "no detection lost" is not the question — the FP-budget
# question is. The whitelist is the tuning surface: a benign service that
# legitimately runs on an odd port (an internal SaaS proxy on http/8090, a mail
# gateway on an alt port) will recur as the SAME (service, dst, port) tuple and
# is a candidate for an expectedServicePorts entry, not a real detection. This
# census surfaces the recurring (service, port) pairs so that judgement can be
# made on evidence. Requires migration 0036 (findings.service).

SVC_OK=$(sqlite3 "$DB" "
  SELECT COUNT(*) FROM pragma_table_info('findings') WHERE name = 'service';
")
if [ "$SVC_OK" -eq 0 ]; then
    echo ""
    echo "INFO: findings.service not present (pre-0036 schema) — deploy current code,"
    echo "  re-run a full analysis, and re-run to see the protocol-on-unexpected-port census."
else
    MISMATCHES=$(sqlite3 "$DB" "
      SELECT COUNT(*) FROM findings WHERE type = 'Protocol on Unexpected Port';
    ")
    if [ "$MISMATCHES" -eq 0 ]; then
        echo ""
        echo "INFO: no Protocol on Unexpected Port findings in this corpus."
    else
        echo ""
        echo "ADVISORY: $MISMATCHES Protocol on Unexpected Port finding(s). Recurring"
        echo "(service, port) pairs that are actually benign belong in the"
        echo "expectedServicePorts whitelist (internal/analysis/heuristics.go), not in"
        echo "the findings list — eyeball these before tuning:"
        sqlite3 -column -header "$DB" "
          SELECT service,
                 dst_port,
                 COUNT(*)                       AS n,
                 COUNT(DISTINCT dst_ip)         AS distinct_dsts,
                 COUNT(DISTINCT src_ip)         AS distinct_srcs,
                 ROUND(AVG(score), 1)           AS avg_score
          FROM findings
          WHERE type = 'Protocol on Unexpected Port'
          GROUP BY service, dst_port
          ORDER BY n DESC
          LIMIT 30;"
        echo ""
        echo "A pair with many connections to FEW distinct dsts across FEW srcs reads as"
        echo "a benign alt-port service (whitelist candidate); many distinct dsts/srcs on"
        echo "one (service, port) reads as a real egress-evasion pattern worth chasing."
        echo ""
        echo "Severity split:"
        sqlite3 -column -header "$DB" "
          SELECT severity, COUNT(*) AS n, ROUND(AVG(score), 1) AS avg_score
          FROM findings
          WHERE type = 'Protocol on Unexpected Port'
          GROUP BY severity
          ORDER BY avg_score DESC;"
    fi
fi

# ── Check 8: Multi-Stage Beacon census (advisory) ────────────────────────────
# Cross-host C2 staging: ≥2 internal hosts beaconing to the same rare external
# dst with staggered onsets (internal/analysis/stage.go). Like Check 7 this
# detector EMITS a finding that wouldn't otherwise exist, so the question is the
# FP budget. The gate is high-precision by design (rare dst + ≥2 hosts +
# clustered onsets), and CRITICAL requires corroboration (lateral hop / TI on
# dst / Malicious JA3-JA4 on dst). The recurring failure mode to watch for is a
# rare internal-use cloud app shared by a handful of users firing HIGH (staged
# but uncorroborated) — that destination is an allowlist candidate, not a real
# campaign. This census surfaces the clusters and their corroboration state so
# that judgement can be made on evidence.

MSB=$(sqlite3 "$DB" "
  SELECT COUNT(*) FROM findings WHERE type = 'Multi-Stage Beacon';
")
if [ "$MSB" -eq 0 ]; then
    echo ""
    echo "INFO: no Multi-Stage Beacon findings in this corpus."
else
    echo ""
    echo "ADVISORY: $MSB Multi-Stage Beacon finding(s). A HIGH (uncorroborated)"
    echo "cluster on a rare shared internal-use cloud app is an allowlist"
    echo "candidate, not a campaign; CRITICAL (corroborated) clusters are the"
    echo "conviction. Eyeball the destinations:"
    sqlite3 -column -header "$DB" "
      SELECT dst_ip                                              AS c2_dst,
             severity,
             score,
             CASE WHEN detail LIKE '%corroboration:%'
                  THEN 'yes' ELSE 'no' END                       AS corroborated,
             src_ip                                              AS patient_zero
      FROM findings
      WHERE type = 'Multi-Stage Beacon'
      ORDER BY score DESC, dst_ip
      LIMIT 30;"
    echo ""
    echo "A recurring c2_dst with corroborated=no across runs that is a known"
    echo "benign shared service belongs in the allowlist; corroborated=yes is a"
    echo "staged-C2 conviction worth chasing."
    echo ""
    echo "Severity split:"
    sqlite3 -column -header "$DB" "
      SELECT severity, COUNT(*) AS n, ROUND(AVG(score), 1) AS avg_score
      FROM findings
      WHERE type = 'Multi-Stage Beacon'
      GROUP BY severity
      ORDER BY avg_score DESC;"
fi

# ── Check 9: service-triggered Lateral Movement census (advisory) ─────────────
# Lateral Movement now fires on either axis: a known admin port (the original
# signal) or Zeek's DPD naming an admin protocol on a port OUTSIDE the lateral
# port set (RDP over 443, SSH on 8022). The service axis EMITS findings the
# port-only detector wouldn't, so the question is the FP budget, not lost
# detection. The recurring failure mode to watch: a benign internal service that
# Zeek labels as a lateral protocol on a fixed odd port (an SSH jumphost on a
# non-22 port, an internal RDP gateway on an alt port) recurs as the SAME
# (service, dst, port) tuple — that is a pair-allowlist candidate, not an
# intrusion. Service-triggered findings carry "Zeek DPD" in their detail; the
# port-triggered ones don't, so this isolates the net-new population. Requires
# migration 0036 (findings.service).

if [ "${SVC_OK:-0}" -eq 0 ]; then
    echo ""
    echo "INFO: findings.service not present (pre-0036 schema) — deploy current code,"
    echo "  re-run a full analysis, and re-run to see the service-lateral census."
else
    SVCLAT=$(sqlite3 "$DB" "
      SELECT COUNT(*) FROM findings
      WHERE type = 'Lateral Movement' AND detail LIKE '%Zeek DPD%';
    ")
    if [ "$SVCLAT" -eq 0 ]; then
        echo ""
        echo "INFO: no service-triggered Lateral Movement findings in this corpus"
        echo "  (all Lateral Movement, if any, came from the port axis)."
    else
        echo ""
        echo "ADVISORY: $SVCLAT service-triggered Lateral Movement finding(s) — an admin"
        echo "protocol on a port outside the lateral set. A recurring (service, dst, port)"
        echo "on a known-benign internal host (a jumphost / gateway on an alt port) is a"
        echo "pair-allowlist candidate, not an intrusion. Eyeball these:"
        sqlite3 -column -header "$DB" "
          SELECT service,
                 dst_port,
                 COUNT(*)               AS n,
                 COUNT(DISTINCT dst_ip) AS distinct_dsts,
                 COUNT(DISTINCT src_ip) AS distinct_srcs
          FROM findings
          WHERE type = 'Lateral Movement' AND detail LIKE '%Zeek DPD%'
          GROUP BY service, dst_port
          ORDER BY n DESC
          LIMIT 30;"
        echo ""
        echo "Few dsts/srcs on a fixed (service, port) reads as a benign alt-port admin"
        echo "service (allowlist candidate); many distinct src→dst pairs on one lateral"
        echo "protocol over an odd port reads as real lateral spread worth chasing."
    fi
fi

# ── Check 10: C2 Port service cross-check census (advisory) ───────────────────
# C2 Port fires on a known-C2 destination port, then cross-checks Zeek's DPD:
# when the port is one a benign protocol also uses (http on 3128/8008/8888) and
# DPD confirms that protocol, the finding is downgraded High→Medium and
# annotated "likely benign" rather than firing High. This census confirms the
# cross-check is downgrading the right population: the downgraded findings
# (detail contains "likely benign") should be recognizable benign services, and
# the still-High ones should be the genuine known-C2-port hits. If a downgraded
# row is a real implant speaking its expected protocol on the port, note it —
# the behavioral paths (beacon/JA3/TI) are the backstop, but it is worth an eye.
# Requires migration 0036 (findings.service).

if [ "${SVC_OK:-0}" -ne 0 ]; then
    C2N=$(sqlite3 "$DB" "SELECT COUNT(*) FROM findings WHERE type = 'C2 Port';")
    if [ "$C2N" -eq 0 ]; then
        echo ""
        echo "INFO: no C2 Port findings in this corpus."
    else
        DOWNG=$(sqlite3 "$DB" "
          SELECT COUNT(*) FROM findings
          WHERE type = 'C2 Port' AND detail LIKE '%likely benign%';
        ")
        echo ""
        echo "ADVISORY: $C2N C2 Port finding(s), $DOWNG downgraded by the DPD cross-check."
        echo "Downgraded rows should be recognizable benign services on a shared port;"
        echo "still-High rows are the genuine known-C2-port hits. Eyeball the split:"
        sqlite3 -column -header "$DB" "
          SELECT dst_port,
                 service,
                 CASE WHEN detail LIKE '%likely benign%'
                      THEN 'downgraded' ELSE 'high' END AS disposition,
                 severity,
                 COUNT(*)               AS n,
                 COUNT(DISTINCT dst_ip) AS distinct_dsts,
                 COUNT(DISTINCT src_ip) AS distinct_srcs
          FROM findings
          WHERE type = 'C2 Port'
          GROUP BY dst_port, service, disposition, severity
          ORDER BY n DESC
          LIMIT 30;"
    fi
fi

# ── Check 11: Admin Protocol Egress census (advisory) ────────────────────────
# An internal host speaking an interactive remoting protocol (ssh/rdp/rfb/
# telnet) to a public destination (internal/analysis/conn.go). This EMITS a
# finding that wouldn't otherwise exist, so the question is the FP budget. SSH
# egress is the expected high-volume population (cloud admin, git-over-ssh) and
# is scored Medium for exactly that reason — a recurring (service, dst) on a
# known-good cloud/host is a pair-allowlist candidate, not a finding. Telnet/RDP/
# VNC egress is High and far rarer; any of those to the internet deserves a look.
# This census splits the population by protocol and severity so the SSH noise is
# separable from the high-signal remote-control egress. Requires migration 0036.

if [ "${SVC_OK:-0}" -ne 0 ]; then
    AEN=$(sqlite3 "$DB" "SELECT COUNT(*) FROM findings WHERE type = 'Admin Protocol Egress';")
    if [ "$AEN" -eq 0 ]; then
        echo ""
        echo "INFO: no Admin Protocol Egress findings in this corpus."
    else
        echo ""
        echo "ADVISORY: $AEN Admin Protocol Egress finding(s). SSH egress (Medium) to a"
        echo "known cloud/host is a pair-allowlist candidate; Telnet/RDP/VNC egress (High)"
        echo "to the internet is high-signal — eyeball the split:"
        sqlite3 -column -header "$DB" "
          SELECT service,
                 severity,
                 dst_port,
                 COUNT(*)               AS n,
                 COUNT(DISTINCT dst_ip) AS distinct_dsts,
                 COUNT(DISTINCT src_ip) AS distinct_srcs
          FROM findings
          WHERE type = 'Admin Protocol Egress'
          GROUP BY service, severity, dst_port
          ORDER BY n DESC
          LIMIT 30;"
        echo ""
        echo "Few src→dst on a fixed (service, dst) reads as a sanctioned admin path"
        echo "(allowlist candidate); many internal sources fanning to one external dst on"
        echo "a remoting protocol reads as a compromised-host or exposed-service pattern."
    fi
fi

# ── Check 12: Database Protocol Egress census (advisory) ──────────────────────
# An internal host speaking a cleartext DB wire protocol (mysql/postgresql/
# mongodb/redis) to a public destination (internal/analysis/conn.go). EMITS a
# finding that wouldn't otherwise exist, so the question is the FP budget — but
# the budget is small by construction: managed cloud DBs ride TLS (Zeek labels
# them `ssl`, out of scope), so this only fires on the cleartext flow. The one
# benign population to expect is an app connecting cleartext to a known cloud-DB
# endpoint — a recurring (service, dst) that is a pair-allowlist candidate.
# Anything else (a DB protocol to a non-DB-provider public IP) is a real
# exposure/exfil lead. Cross-reference with beacons to the same dst — a host that
# both beacons to and runs a DB protocol to one external dst is a strong exfil-
# over-C2 story. Requires migration 0036.

if [ "${SVC_OK:-0}" -ne 0 ]; then
    DBN=$(sqlite3 "$DB" "SELECT COUNT(*) FROM findings WHERE type = 'Database Protocol Egress';")
    if [ "$DBN" -eq 0 ]; then
        echo ""
        echo "INFO: no Database Protocol Egress findings in this corpus."
    else
        echo ""
        echo "ADVISORY: $DBN Database Protocol Egress finding(s). A recurring (service, dst)"
        echo "that is a known cloud-DB endpoint is a pair-allowlist candidate; a DB protocol"
        echo "to any other public IP is a real exposure/exfil lead. Eyeball these:"
        sqlite3 -column -header "$DB" "
          SELECT service,
                 dst_ip,
                 dst_port,
                 COUNT(*)               AS n,
                 COUNT(DISTINCT src_ip) AS distinct_srcs
          FROM findings
          WHERE type = 'Database Protocol Egress'
          GROUP BY service, dst_ip, dst_port
          ORDER BY n DESC
          LIMIT 30;"
        echo ""
        echo "A host that BOTH beacons to and runs a DB protocol to the same external dst"
        echo "is a strong exfil-over-C2 story worth escalating — the beacon finding's detail"
        echo "is auto-annotated with that corroboration, but this census surfaces the dsts"
        echo "directly so you can scan for the pattern."
    fi
fi
