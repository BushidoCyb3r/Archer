#!/usr/bin/env bash
# corpus-spotcheck.sh — validates the spectral rescue plausibility gate
# against live findings in the Archer database.
#
# The gate is lower-bound only: spectral_period >= median_interval/5.
# There is no upper bound because burst-connect beacons (many connections
# per burst, long silence between bursts) have true spectral periods that
# are legitimately orders of magnitude above the median inter-arrival.
#
# Two checks:
#   1. PASS/FAIL — any rescued finding with spectral_period below
#      median_interval/5 is an artifact that slipped through the gate
#      (gate too loose, or a novel artifact shape not covered by the
#      lower-bound criterion).
#   2. ADVISORY — rescued findings that also contain a suppressed artifact
#      in the detail string. These fired on a plausible peak alongside a
#      rejected shorter-period peak; a human should eyeball whether the
#      suppressed period looks burst-shaped or beacon-shaped.
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
    exit 0
fi

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
