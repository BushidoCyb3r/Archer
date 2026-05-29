// beacon_evolution.js — 30-day score evolution chart for the
// Beaconing / HTTP Beaconing finding detail pane.
//
// Pure SVG drawing (no charting library). The chart shows up to 30
// daily snapshots persisted by store.SetFindings's beacon_history
// hook. Five lines: the composite Score (bold) and the four sub-
// scores (ts, ds, hist, dur — each on the 0..1 axis, the composite
// on its own 0..100 scale shown on the right gutter).
//
// Two render destinations: the in-place chart inside the Detail tab
// (small, fixed aspect ratio via CSS) and the expand-to-modal view
// (larger, exportable as PNG or JPEG). Both share the same render
// path — _renderInto draws into any (SVG, legend) element pair.
// v0.18.0 added the modal + export affordance.

'use strict';

const BeaconEvolution = (() => {
  const COLORS = {
    score:    'var(--sev-high)',
    ts:       'var(--accent)',
    ds:       'var(--accent-alt, #6bb6ff)',
    hist:     '#f0a040',
    dur:      '#8ec07c',
    spectral: 'var(--sev-critical, #e06c75)',
  };

  let _lastRows = null;
  let _currentFindingID = null;

  function _empty(svgEl, legendEl, message) {
    if (svgEl) svgEl.innerHTML =
      `<text x="50%" y="50%" text-anchor="middle" class="label" fill="var(--fg-dim)">${message}</text>`;
    if (legendEl) legendEl.innerHTML = '';
  }

  // load(findingID, type) pre-fetches history for the given finding
  // so Score Evo opens instantly when clicked. Enables #score-evo-btn
  // only when at least one history row exists. Non-beacon types clear
  // state and leave the button disabled.
  function load(findingID, type) {
    _lastRows = null;
    _currentFindingID = null;
    if (type !== 'Beaconing' && type !== 'HTTP Beaconing' && type !== 'DNS Beaconing') return;
    _currentFindingID = findingID;
    fetch(`/api/findings/${findingID}/history`, { credentials: 'same-origin' })
      .then(r => {
        if (!r.ok) throw new Error(`history HTTP ${r.status}`);
        return r.json();
      })
      .then(rows => {
        if (_currentFindingID !== findingID) return;
        _lastRows = rows;
        const btn = document.getElementById('score-evo-btn');
        if (btn) btn.disabled = !rows || rows.length === 0;
      })
      .catch(err => {
        console.warn('beacon evolution fetch failed:', err);
      });
  }

  // _renderInto draws the chart into any (svgEl, legendEl) pair.
  // Used by both the in-place small chart and the larger modal view.
  // viewBox stays 600x120; CSS aspect-ratio on each container scales
  // it to the right display dimensions while keeping the chart's
  // proportions consistent across both destinations.
  function _renderInto(rows, svgEl, legendEl) {
    if (!svgEl) return;
    if (!rows || rows.length === 0) {
      _empty(svgEl, legendEl, 'No history yet — first daily snapshot lands on the next full pass.');
      return;
    }

    const W = 600, H = 200;
    const ML = 36, MR = 32, MT = 12, MB = 22;
    const plotW = W - ML - MR;
    const plotH = H - MT - MB;

    svgEl.setAttribute('viewBox', `0 0 ${W} ${H}`);

    const n = rows.length;
    const xOf = i => n === 1 ? ML + plotW / 2 : ML + (i / (n - 1)) * plotW;
    const yScore = v => MT + plotH * (1 - Math.max(0, Math.min(100, v)) / 100);
    const ySub   = v => MT + plotH * (1 - Math.max(0, Math.min(1, v)));

    const linePath = (values, yFn) => values
      .map((v, i) => `${i === 0 ? 'M' : 'L'} ${xOf(i).toFixed(1)} ${yFn(v).toFixed(1)}`)
      .join(' ');

    const scoreLine = linePath(rows.map(r => r.max_score), yScore);
    const tsLine    = linePath(rows.map(r => r.ts_score),   ySub);
    const dsLine    = linePath(rows.map(r => r.ds_score),   ySub);
    const histLine  = linePath(rows.map(r => r.hist_score), ySub);
    const durLine   = linePath(rows.map(r => r.dur_score),  ySub);

    const firstDay = rows[0].day_utc;
    const lastDay  = rows[rows.length - 1].day_utc;

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
      if (r.spectral_rescued) {
        const period = r.spectral_period > 0 ? ` period≈${r.spectral_period.toFixed(1)}s` : '';
        titleLines.push(`Spectral rescue${period}`);
      }
      const title = `<title>${_esc(titleLines.join('\n'))}</title>`;
      if (r.spectral_rescued) {
        // Diamond marker (square rotated 45°) to distinguish spectral-rescue days.
        const s = 4.5;
        return `<polygon class="data-point" points="${cx},${(parseFloat(cy)-s).toFixed(1)} ${(parseFloat(cx)+s).toFixed(1)},${cy} ${cx},${(parseFloat(cy)+s).toFixed(1)} ${(parseFloat(cx)-s).toFixed(1)},${cy}" fill="${COLORS.spectral}" stroke="none">${title}</polygon>`;
      }
      return `<circle class="data-point" cx="${cx}" cy="${cy}" r="3.5" fill="${COLORS.score}" stroke="none">${title}</circle>`;
    }).join('');

    svgEl.innerHTML = `
      <line class="axis" x1="${ML}" y1="${MT}"        x2="${ML}" y2="${H - MB}"/>
      <line class="axis" x1="${ML}" y1="${H - MB}"    x2="${W - MR}" y2="${H - MB}"/>
      <line class="gridline" x1="${ML}" y1="${MT}"           x2="${W - MR}" y2="${MT}"/>
      <line class="gridline" x1="${ML}" y1="${MT + plotH/2}" x2="${W - MR}" y2="${MT + plotH/2}"/>
      <text class="label" x="${ML - 4}" y="${MT + 4}"             text-anchor="end">100</text>
      <text class="label" x="${ML - 4}" y="${MT + plotH/2 + 4}"   text-anchor="end">50</text>
      <text class="label" x="${ML - 4}" y="${H - MB + 2}"         text-anchor="end">0</text>
      <text class="label" x="${ML}"     y="${H - 6}">${_esc(firstDay)}</text>
      <text class="label" x="${W - MR}" y="${H - 6}" text-anchor="end">${_esc(lastDay)}</text>
      <path class="sub-line"   d="${tsLine}"    stroke="${COLORS.ts}"/>
      <path class="sub-line"   d="${dsLine}"    stroke="${COLORS.ds}"/>
      <path class="sub-line"   d="${histLine}"  stroke="${COLORS.hist}"/>
      <path class="sub-line"   d="${durLine}"   stroke="${COLORS.dur}"/>
      <path class="score-line" d="${scoreLine}" stroke="${COLORS.score}"/>
      ${dataPoints}
    `;

    if (legendEl) {
      legendEl.innerHTML = [
        ['Score (0-100)',   COLORS.score],
        ['ts',             COLORS.ts],
        ['ds',             COLORS.ds],
        ['hist',           COLORS.hist],
        ['dur',            COLORS.dur],
        ['Spectral rescue',COLORS.spectral],
      ].map(([label, color]) =>
        `<span class="leg-item"><span class="leg-swatch" style="background:${color}"></span>${_esc(label)}</span>`
      ).join('');
    }
  }

  // expand() opens the modal view with the same rows the in-place
  // chart is showing, rendered into the modal's larger SVG. Modal-
  // local PNG/JPEG buttons then export the rendered chart.
  function expand() {
    if (!_lastRows) return;
    const dlg = document.getElementById('beacon-evolution-modal');
    if (!dlg) return;
    const svg = document.getElementById('beacon-evolution-modal-svg');
    const legend = document.getElementById('beacon-evolution-modal-legend');
    _renderInto(_lastRows, svg, legend);
    if (typeof dlg.showModal === 'function') dlg.showModal();
    else dlg.setAttribute('open', '');
  }

  // exportImage(format) renders the modal SVG to a PNG or JPEG and
  // triggers a download. Client-side only: serialize SVG → draw to
  // a backing canvas → toDataURL → <a download>. Resolution is
  // pegged at the SVG's natural viewBox scaled 2x so the export is
  // crisp on hi-DPI screens without ballooning file size.
  function exportImage(format) {
    const svg = document.getElementById('beacon-evolution-modal-svg');
    if (!svg) return;
    const fmt = format === 'jpeg' ? 'jpeg' : 'png';
    const mime = fmt === 'jpeg' ? 'image/jpeg' : 'image/png';

    // Inline computed styles so the serialized SVG carries the
    // colours/fonts the page CSS provides. Without this the
    // canvas-drawn image renders as transparent strokes — the SVG
    // has no inline styles, only class selectors that the off-DOM
    // image element can't resolve.
    const cloned = svg.cloneNode(true);
    const cssVarSamples = [
      ['--sev-critical', 'var(--sev-critical)'],
      ['--sev-high',     'var(--sev-high)'],
      ['--sev-low',      'var(--sev-low)'],
      ['--sev-info',     'var(--sev-info)'],
      ['--accent',       'var(--accent)'],
      ['--fg-dim',       'var(--fg-dim)'],
      ['--border-subtle','var(--border-subtle)'],
      ['--bg-elev-2',    'var(--bg-elev-2)'],
    ];
    const probe = document.createElement('div');
    probe.style.position = 'absolute';
    probe.style.visibility = 'hidden';
    document.body.appendChild(probe);
    const resolve = name => {
      probe.style.color = `var(${name})`;
      return getComputedStyle(probe).color;
    };
    const resolved = {};
    cssVarSamples.forEach(([k]) => { resolved[k] = resolve(k); });
    document.body.removeChild(probe);

    // Replace var() references with the resolved RGB values so the
    // serialized markup is self-contained.
    cloned.querySelectorAll('*').forEach(el => {
      ['stroke', 'fill'].forEach(attr => {
        const v = el.getAttribute(attr);
        if (v && v.startsWith('var(')) {
          // var(NAME) or var(NAME, FALLBACK): split on the first comma
          // so a fallback literal doesn't get folded into the key. Off-DOM
          // canvas render can't resolve var() at all, so we substitute the
          // resolved value, or the fallback if the var isn't in our sample
          // list. Without this, "var(--accent-alt, #6bb6ff)" strokes as
          // transparent in the exported PNG.
          const inner = v.slice(4, v.lastIndexOf(')'));
          const comma = inner.indexOf(',');
          const name = (comma >= 0 ? inner.slice(0, comma) : inner).trim();
          const fallback = comma >= 0 ? inner.slice(comma + 1).trim() : '';
          const repl = resolved[name] || fallback;
          if (repl) el.setAttribute(attr, repl);
        }
      });
    });

    // Match the class-based stroke widths and fills via inline
    // style so they survive the off-DOM render.
    cloned.querySelectorAll('.axis')      .forEach(e => { e.style.stroke = resolved['--border-subtle']; e.style.strokeWidth = '1'; });
    cloned.querySelectorAll('.gridline')  .forEach(e => { e.style.stroke = resolved['--border-subtle']; e.style.strokeWidth = '1'; e.style.strokeDasharray = '2 4'; e.style.opacity = '0.5'; });
    cloned.querySelectorAll('.score-line').forEach(e => { e.style.fill = 'none'; e.style.strokeWidth = '2'; });
    cloned.querySelectorAll('.sub-line')  .forEach(e => { e.style.fill = 'none'; e.style.strokeWidth = '1.2'; e.style.opacity = '0.75'; });
    cloned.querySelectorAll('.label')     .forEach(e => { e.style.fontSize = '11px'; e.style.fill = resolved['--fg-dim']; e.style.fontFamily = 'monospace'; });

    const viewBox = cloned.getAttribute('viewBox') || '0 0 600 200';
    const [, , vbW, vbH] = viewBox.split(/\s+/).map(Number);
    const scale = 2;
    cloned.setAttribute('width',  String(vbW * scale));
    cloned.setAttribute('height', String(vbH * scale));
    cloned.setAttribute('xmlns', 'http://www.w3.org/2000/svg');

    const svgString = new XMLSerializer().serializeToString(cloned);
    const blob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width  = vbW * scale;
      canvas.height = vbH * scale;
      const ctx = canvas.getContext('2d');
      if (fmt === 'jpeg') {
        // JPEG has no alpha — fill the background so the chart
        // doesn't end up on a black canvas-default field.
        ctx.fillStyle = resolved['--bg-elev-2'] || '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
      }
      ctx.drawImage(img, 0, 0);
      URL.revokeObjectURL(url);
      const dataUrl = canvas.toDataURL(mime, fmt === 'jpeg' ? 0.92 : undefined);
      const a = document.createElement('a');
      a.href = dataUrl;
      a.download = `beacon-evolution-finding-${_currentFindingID || 'chart'}.${fmt === 'jpeg' ? 'jpg' : 'png'}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    };
    img.onerror = err => {
      console.warn('beacon evolution export failed:', err);
      URL.revokeObjectURL(url);
    };
    img.src = url;
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

  // init() wires the modal close button. The Export button is a
  // single dropdown (PNG / JPEG); app.js's _initExportDropdown wires
  // it during boot because that helper lives in app.js's IIFE scope.
  function init() {
    const closeBtn = document.getElementById('beacon-evolution-modal-close');
    if (closeBtn) closeBtn.addEventListener('click', () => {
      const dlg = document.getElementById('beacon-evolution-modal');
      if (dlg && typeof dlg.close === 'function') dlg.close();
    });
  }

  function clear() {
    _lastRows = null;
    _currentFindingID = null;
    const btn = document.getElementById('score-evo-btn');
    if (btn) btn.disabled = true;
  }

  return { init, load, expand, exportImage, clear };
})();
