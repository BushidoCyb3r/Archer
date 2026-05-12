// beacon_evolution.js — 30-day score evolution chart for the
// Beaconing / HTTP Beaconing finding detail pane.
//
// Pure SVG drawing (no charting library). The chart shows up to 30
// daily snapshots persisted by store.SetFindings's beacon_history
// hook. Five lines: the composite Score (bold) and the four sub-
// scores (ts, ds, hist, dur — each on the 0..1 axis, the composite
// on its own 0..100 scale shown on the right gutter).
//
// Rendered into existing #beacon-evolution{svg,legend,header}
// elements. Show/hide the wrapper based on whether the current
// finding's type carries beacon_history rows.

'use strict';

const BeaconEvolution = (() => {
  const COLORS = {
    score: 'var(--sev-high)',
    ts:    'var(--accent)',
    ds:    'var(--accent-alt, #6bb6ff)',
    hist:  '#f0a040',
    dur:   '#8ec07c',
  };

  function _hide() {
    const wrap = document.getElementById('beacon-evolution');
    if (wrap) wrap.style.display = 'none';
  }

  function _show() {
    const wrap = document.getElementById('beacon-evolution');
    if (wrap) wrap.style.display = 'block';
  }

  function _empty(message) {
    const svg = document.getElementById('beacon-evolution-svg');
    if (!svg) return;
    svg.innerHTML =
      `<text x="50%" y="50%" text-anchor="middle" class="label" fill="var(--fg-dim)">${message}</text>`;
    const legend = document.getElementById('beacon-evolution-legend');
    if (legend) legend.innerHTML = '';
  }

  // load(findingID, type) fetches and renders the chart for the
  // given finding. type is gating: Beaconing / HTTP Beaconing show
  // the chart, anything else hides the container entirely.
  function load(findingID, type) {
    if (type !== 'Beaconing' && type !== 'HTTP Beaconing') {
      _hide();
      return;
    }
    _show();
    _empty('Loading…');
    fetch(`/api/findings/${findingID}/history`, { credentials: 'same-origin' })
      .then(r => {
        if (!r.ok) throw new Error(`history HTTP ${r.status}`);
        return r.json();
      })
      .then(rows => _render(rows))
      .catch(err => {
        console.warn('beacon evolution fetch failed:', err);
        _empty('History unavailable.');
      });
  }

  function _render(rows) {
    const svg = document.getElementById('beacon-evolution-svg');
    if (!svg) return;
    if (!rows || rows.length === 0) {
      _empty('No history yet — first daily snapshot lands on the next full pass.');
      return;
    }

    // Viewport: 600x120 with margins for axis labels. The SVG itself
    // is set to 100% width and preserveAspectRatio="none" so the
    // chart stretches to fit the detail pane, which keeps the
    // implementation simple at the cost of horizontal-stretch when
    // the pane is wide. Acceptable trade-off — sparkline-style charts
    // are aspect-ratio-flexible by convention.
    const W = 600, H = 120;
    const ML = 28, MR = 28, MT = 8, MB = 18;
    const plotW = W - ML - MR;
    const plotH = H - MT - MB;

    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

    const n = rows.length;
    const xOf = i => n === 1 ? ML + plotW / 2 : ML + (i / (n - 1)) * plotW;
    const yScore = v => MT + plotH * (1 - Math.max(0, Math.min(100, v)) / 100);
    const ySub   = v => MT + plotH * (1 - Math.max(0, Math.min(1, v)));

    const linePath = (values, yFn) => values
      .map((v, i) => `${i === 0 ? 'M' : 'L'} ${xOf(i).toFixed(1)} ${yFn(v).toFixed(1)}`)
      .join(' ');

    // Render max_score as the primary trajectory line. The spike value
    // is what triage cares about — a beacon that hit 88 at noon and
    // fell back to 60 by evening is a different story from one that
    // held at 60 all day, and the chart distinguishes them. last_score
    // is in the row payload for forensic detail but not drawn here.
    const scoreLine = linePath(rows.map(r => r.max_score), yScore);
    const tsLine    = linePath(rows.map(r => r.ts_score),   ySub);
    const dsLine    = linePath(rows.map(r => r.ds_score),   ySub);
    const histLine  = linePath(rows.map(r => r.hist_score), ySub);
    const durLine   = linePath(rows.map(r => r.dur_score),  ySub);

    const firstDay = rows[0].day_utc;
    const lastDay  = rows[rows.length - 1].day_utc;

    // Per-day data points carry an SVG <title> tooltip surfacing
    // max / last / max-time / last-time / sub-axes. The dual-column
    // schema NEW-76 introduced isn't useful unless the analyst can
    // see both numbers; v0.16.2 shipped only the max line, so the
    // last_score / max_score_at / last_score_at fields were dead
    // weight in the API response. NEW-87 from the twentieth audit
    // round closes the loop — native browser tooltip, no JS event
    // wiring required.
    const dataPoints = rows.map((r, i) => {
      const cx = xOf(i).toFixed(1);
      const cy = yScore(r.max_score).toFixed(1);
      const sameMaxLast = r.max_score === r.last_score;
      const titleLines = [
        r.day_utc,
        `Max: ${r.max_score} (peaked ${_fmtTime(r.max_score_at)})`,
      ];
      if (!sameMaxLast) {
        titleLines.push(`Last: ${r.last_score} (most recent ${_fmtTime(r.last_score_at)})`);
      }
      titleLines.push(`ts=${(r.ts_score||0).toFixed(2)}  ds=${(r.ds_score||0).toFixed(2)}  hist=${(r.hist_score||0).toFixed(2)}  dur=${(r.dur_score||0).toFixed(2)}`);
      return `
        <circle class="data-point" cx="${cx}" cy="${cy}" r="3" fill="${COLORS.score}" stroke="none">
          <title>${_esc(titleLines.join('\n'))}</title>
        </circle>`;
    }).join('');

    svg.innerHTML = `
      <line class="axis" x1="${ML}" y1="${MT}"        x2="${ML}" y2="${H - MB}"/>
      <line class="axis" x1="${ML}" y1="${H - MB}"    x2="${W - MR}" y2="${H - MB}"/>
      <line class="gridline" x1="${ML}" y1="${MT}"           x2="${W - MR}" y2="${MT}"/>
      <line class="gridline" x1="${ML}" y1="${MT + plotH/2}" x2="${W - MR}" y2="${MT + plotH/2}"/>
      <text class="label" x="${ML - 4}" y="${MT + 4}"             text-anchor="end">100</text>
      <text class="label" x="${ML - 4}" y="${MT + plotH/2 + 4}"   text-anchor="end">50</text>
      <text class="label" x="${ML - 4}" y="${H - MB + 2}"         text-anchor="end">0</text>
      <text class="label" x="${ML}"     y="${H - 4}">${_esc(firstDay)}</text>
      <text class="label" x="${W - MR}" y="${H - 4}" text-anchor="end">${_esc(lastDay)}</text>
      <path class="sub-line"   d="${tsLine}"    stroke="${COLORS.ts}"/>
      <path class="sub-line"   d="${dsLine}"    stroke="${COLORS.ds}"/>
      <path class="sub-line"   d="${histLine}"  stroke="${COLORS.hist}"/>
      <path class="sub-line"   d="${durLine}"   stroke="${COLORS.dur}"/>
      <path class="score-line" d="${scoreLine}" stroke="${COLORS.score}"/>
      ${dataPoints}
    `;

    const legend = document.getElementById('beacon-evolution-legend');
    if (legend) {
      legend.innerHTML = [
        ['Score (0-100)', COLORS.score],
        ['ts',            COLORS.ts],
        ['ds',            COLORS.ds],
        ['hist',          COLORS.hist],
        ['dur',           COLORS.dur],
      ].map(([label, color]) =>
        `<span class="leg-item"><span class="leg-swatch" style="background:${color}"></span>${_esc(label)}</span>`
      ).join('');
    }
  }

  // _fmtTime turns a Unix-seconds timestamp into a compact local-time
  // string like "14:23" for the tooltip. Empty / zero values render
  // as "—" so a partially-populated row (legacy / migration backfill
  // where *_at was set to 0) doesn't display "01:00 1970-01-01".
  function _fmtTime(unixSeconds) {
    if (!unixSeconds || unixSeconds <= 0) return '—';
    const d = new Date(unixSeconds * 1000);
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    return `${hh}:${mm}`;
  }

  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function clear() {
    _hide();
  }

  return { load, clear };
})();
