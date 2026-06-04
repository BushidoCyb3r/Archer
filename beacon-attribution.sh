#!/usr/bin/env bash
# beacon-attribution.sh — per-beacon timing-layer attribution for the
# timing-axis validation work (TODO §1 "Beacon timing-axis validation").
#
# The composed beacon timing score is an OR of four layers:
#
#   tsScore = max(ts_raw, ts_mm, ts_ent, spectral)
#
# (raw Bowley/MAD → multimodal augmentation → entropy augmentation →
# Lomb-Scargle spectral rescue, each upgrading the score only if strictly
# greater — see conn.go). Each layer rescues a beacon class the others miss,
# but the false-positive surface compounds per layer, and the stack has never
# been validated against analyst-labelled traffic: which layer drives which
# beacons, and does the population each layer rescues hold up when an analyst
# triages it?
#
# Migration 0034 persists the per-layer values (ts_raw / ts_mm / ts_ent /
# spectral_rescued / spectral_period) on the finding itself, so this script
# can attribute every beacon to its deciding layer and cross-tabulate that
# against the analyst's disposition — the live-corpus validation the mission
# needs, using the labels analysts already produce.
#
# It writes a per-finding CSV (one row per beacon) and prints two crosstabs:
#   1. winning layer × severity   — where each layer's score mass lands
#   2. winning layer × disposition — read this as an attention signal, NOT a
#      verdict. A dismissal means the analyst chose not to see the beacon
#      again, which conflates two populations: a true false positive AND a
#      real-but-benign beacon (cloud sync, OS update, telemetry). A layer
#      whose population skews dismissed is therefore a layer to INVESTIGATE,
#      never one to suppress on this signal alone — a benign-real beacon
#      shares its timing DNA with a malicious one, so muting the layer that
#      catches it would also blind the malicious case. That is the one
#      outcome the mission cannot accept.
#
# The "winning layer" expression mirrors conn.go's strict-greater upgrade
# chain exactly: spectral if it rescued, else the highest of raw/mm/ent with
# raw winning ties (a layer only wins by being strictly greater than the
# running max, so raw is the floor).
#
# Read-only. No detection-semantics judgement is baked in — this surfaces the
# distribution; a human decides, and any tuning still has to clear the global
# corpus gate.
#
# Usage:  bash beacon-attribution.sh [/path/to/archer.db] [out.csv]
#         defaults: /data/archer.db  ./beacon-attribution.csv
set -euo pipefail

DB="${1:-/data/archer.db}"
OUT="${2:-./beacon-attribution.csv}"

if [ ! -f "$DB" ]; then
    echo "ERROR: database not found at $DB" >&2
    exit 2
fi

# Beacon types carry timing-layer attribution; everything else reads back as
# all-zero layer columns. sample_size > 0 additionally excludes legacy beacons
# persisted before migration 0034 that haven't been re-analysed yet (their
# layer columns default to 0 and would masquerade as raw-layer wins).
BEACON_FILTER="type IN ('Beacon','HTTP Beacon','DNS Beacon','Port-Hopping Beacon') AND sample_size > 0"

# Shared SQL fragment: the deciding layer for one finding row.
WINNER="CASE
          WHEN spectral_rescued = 1            THEN 'spectral'
          WHEN ts_ent > ts_raw AND ts_ent > ts_mm THEN 'entropy'
          WHEN ts_mm  > ts_raw                 THEN 'multimodal'
          ELSE 'raw'
        END"

TOTAL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM findings WHERE $BEACON_FILTER;")
if [ "$TOTAL" -eq 0 ]; then
    echo "No re-analysed beacon findings to attribute (need a full analysis pass after migration 0034)."
    exit 0
fi

LEGACY=$(sqlite3 "$DB" "SELECT COUNT(*) FROM findings WHERE type IN ('Beacon','HTTP Beacon','DNS Beacon','Port-Hopping Beacon') AND sample_size = 0;")

echo "Beacon findings with layer attribution: $TOTAL"
if [ "$LEGACY" -gt 0 ]; then
    echo "  (excluding $LEGACY legacy beacon(s) with no layer data — re-run a full analysis to attribute them)"
fi
echo

# ── Per-finding CSV ──────────────────────────────────────────────────────────
sqlite3 -csv -header "$DB" "
  SELECT id, type, $WINNER AS winning_layer, score, severity,
         CASE status WHEN '' THEN 'open' ELSE status END AS disposition,
         sensor, src_ip, dst_ip, dst_port,
         ROUND(mean_interval, 1)   AS mean_interval,
         ROUND(median_interval, 1) AS median_interval,
         ROUND(jitter, 3)          AS jitter,
         sample_size, ja3,
         ROUND(ts_raw, 3) AS ts_raw, ROUND(ts_mm, 3) AS ts_mm,
         ROUND(ts_ent, 3) AS ts_ent,
         spectral_rescued, ROUND(spectral_period, 1) AS spectral_period
  FROM findings
  WHERE $BEACON_FILTER
  ORDER BY winning_layer, score DESC;
" > "$OUT"
echo "Wrote per-finding attribution to $OUT"
echo

# ── Crosstab 1: winning layer × severity ─────────────────────────────────────
echo "Winning layer × severity:"
sqlite3 -column -header "$DB" "
  SELECT $WINNER AS layer,
         SUM(severity = 'CRITICAL') AS critical,
         SUM(severity = 'HIGH')     AS high,
         SUM(severity = 'MEDIUM')   AS medium,
         SUM(severity = 'LOW')      AS low,
         COUNT(*)                   AS total
  FROM findings
  WHERE $BEACON_FILTER
  GROUP BY layer
  ORDER BY total DESC;
"
echo

# ── Crosstab 2: winning layer × analyst disposition ──────────────────────────
# An attention signal, not a verdict. A dismissal means the analyst chose not
# to see the beacon again — which conflates a true false positive with a
# real-but-benign beacon (cloud sync, OS update, telemetry). A layer skewing
# dismissed is a layer to INVESTIGATE, not to suppress: a benign-real beacon
# shares its timing signature with a malicious one, so muting the layer that
# catches it blinds the malicious case too.
echo "Winning layer × disposition (dismissed = chose not to see again — FP OR benign-real):"
sqlite3 -column -header "$DB" "
  SELECT $WINNER AS layer,
         SUM(status = '')            AS open,
         SUM(status = 'acknowledged') AS acknowledged,
         SUM(status = 'escalated')   AS escalated,
         SUM(status = 'dismissed')   AS dismissed,
         COUNT(*)                    AS total
  FROM findings
  WHERE $BEACON_FILTER
  GROUP BY layer
  ORDER BY total DESC;
"
