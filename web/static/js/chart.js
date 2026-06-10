// chart.js — beacon visualization
//
// Three views, one dialog. The view-mode tabs at the top of the
// dialog switch between them; each view answers a different
// analyst question.
//
//   Timeline (default) — every connection event as a vertical tick
//     on a continuous time axis from first to last observation.
//     The eye-test for "is this regular?".
//   Interval histogram — distribution of inter-arrival gaps
//     between consecutive connections. A tight single-bar peak
//     confirms a beacon's heartbeat; multi-modal/wide spread does
//     not.
//   Bytes — bytes-sent per time bucket. The original chart, kept
//     for cross-checking exfil suspicion alongside a beacon.
//
// All three auto-fit the X axis to the data span — the previous
// fixed time-window presets (5m, 30m, …) only made sense when the
// dataset was a few hours; on a 9-month log corpus they collapsed
// to arbitrary slices.
'use strict';

const BeaconChart = (() => {
  let _finding = null;
  let _viewMode = 'timeline'; // 'timeline' | 'intervals' | 'bytes'

  // Interactive zoom on the Timeline view. _xRange = [tMin, tMax] in
  // unix-second floats; null means auto-fit. Click-drag on the canvas
  // selects a range; right-click resets. Only applies to the Timeline
  // view (the histogram and bytes views have their own X mappings).
  let _xRange = null;
  let _brushing = false;
  let _brushStartX = 0;
  let _brushCurrentX = 0;

  // Last-rendered Timeline plot geometry. Captured during _drawTimeline
  // so the brush handlers can map canvas X coordinates back to data
  // timestamps without re-running the stats pipeline.
  let _timelinePlot = null; // { padLeft, plotW, tMin, tMax, buckets }

  let _intervalsPlot = null;
  let _bytesPlot = null;

  // Logical drawing space. The backing store is scaled by devicePixelRatio
  // (capped at 2) in _setupCanvas; every draw routine keeps working in
  // 720x340 logical units via the canvas transform.
  const LOGICAL_W = 720, LOGICAL_H = 340;
  const FONT_MONO = 'ui-monospace, "SF Mono", Menlo, Monaco, Consolas, monospace';

  function _setupCanvas(cv) {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const bw = Math.round(LOGICAL_W * dpr), bh = Math.round(LOGICAL_H * dpr);
    if (cv.width !== bw || cv.height !== bh) {
      cv.width = bw;
      cv.height = bh;
    }
    const ctx = cv.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return ctx;
  }

  function _bucketAt(x, padLeft, plotW, numBuckets) {
    const i = Math.floor((x - padLeft) / (plotW / numBuckets));
    return i >= 0 && i < numBuckets ? i : -1;
  }

  function _xTickCount(plotW) {
    return Math.max(3, Math.min(8, Math.floor(plotW / 90)));
  }

  let _animT = 1;
  let _animRaf = 0;

  function _reducedMotion() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function _startAnim() {
    cancelAnimationFrame(_animRaf);
    if (_reducedMotion()) { _animT = 1; _render(); return; }
    const t0 = performance.now(), DUR = 300;
    _animT = 0;
    const step = now => {
      const p = Math.min(1, (now - t0) / DUR);
      _animT = 1 - Math.pow(1 - p, 3);
      _render();
      if (p < 1) _animRaf = requestAnimationFrame(step);
    };
    _animRaf = requestAnimationFrame(step);
  }

  let _crosshairX = null;

  // Canvas can't read CSS vars, so the palette is resolved from the active
  // skin's tokens each render (refreshed at the top of _render and on
  // archer:themechange). barHi flags sent > received (potential exfil).
  function _tok(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }
  function _readPalette() {
    return {
      bg:    _tok('--bg-elev-2'),
      panel: _tok('--bg-elev-3'),
      bar:   _tok('--accent'),
      barHi: _tok('--sev-critical'),
      tick:  _tok('--accent'),
      grid:  _tok('--border'),
      axis:  _tok('--fg-faint'),
      text:  _tok('--fg-primary'),
      label: _tok('--fg-secondary'),
      accent:_tok('--accent'),
      recv:  _tok('--chart-4'),
    };
  }
  let PALETTE = _readPalette();

  // ── Formatters ────────────────────────────────────────────────────

  function _fmtBytes(n) {
    if (n >= 1073741824) return (n / 1073741824).toFixed(1) + ' GB';
    if (n >= 1048576)    return (n / 1048576).toFixed(1) + ' MB';
    if (n >= 1024)       return (n / 1024).toFixed(0) + ' KB';
    return n + ' B';
  }

  function _fmtInterval(s) {
    if (!isFinite(s) || s <= 0) return '—';
    if (s < 1)    return s.toFixed(2) + 's';
    if (s < 60)   return s.toFixed(1) + 's';
    if (s < 3600) return (s / 60).toFixed(1) + 'm';
    if (s < 86400) return (s / 3600).toFixed(1) + 'h';
    return (s / 86400).toFixed(1) + 'd';
  }

  function _fmtSpan(secs) {
    if (secs <= 0) return '0s';
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${Math.floor(secs % 60)}s`;
    return `${Math.floor(secs)}s`;
  }

  function _timeLabel(ts, spanSecs) {
    const d = new Date(ts * 1000);
    const hh = d.getUTCHours().toString().padStart(2, '0');
    const mm = d.getUTCMinutes().toString().padStart(2, '0');
    const ss = d.getUTCSeconds().toString().padStart(2, '0');
    const mo = (d.getUTCMonth() + 1).toString().padStart(2, '0');
    const dd = d.getUTCDate().toString().padStart(2, '0');
    if (spanSecs <= 1800)  return `${hh}:${mm}:${ss}`;
    if (spanSecs <= 86400) return `${hh}:${mm}`;
    return `${mo}/${dd} ${hh}:${mm}`;
  }

  // Theme tokens are opaque colors; canvas gradients need alpha steps of
  // the same hue. Round-trips through fillStyle to normalize any token
  // format to #rrggbb before adding the alpha channel.
  function _alphaColor(ctx, color, alpha) {
    ctx.fillStyle = color;
    const c = ctx.fillStyle;
    if (c[0] === '#' && c.length === 7) {
      const r = parseInt(c.slice(1, 3), 16);
      const g = parseInt(c.slice(3, 5), 16);
      const b = parseInt(c.slice(5, 7), 16);
      return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    }
    return c;
  }

  // ── Stats ────────────────────────────────────────────────────────

  function _computeStats(tsData) {
    if (!tsData || tsData.length === 0) {
      return { count: 0, intervals: [], mean: 0, cv: 0, span: 0, tMin: 0, tMax: 0 };
    }
    const sorted = tsData.slice().sort((a, b) => a[0] - b[0]);
    const n = sorted.length;
    const tMin = sorted[0][0];
    const tMax = sorted[n - 1][0];
    const intervals = [];
    for (let i = 1; i < n; i++) {
      const dt = sorted[i][0] - sorted[i - 1][0];
      if (dt > 0) intervals.push(dt);
    }
    let mean = 0, cv = 0;
    if (intervals.length > 0) {
      const sum = intervals.reduce((a, b) => a + b, 0);
      mean = sum / intervals.length;
      if (mean > 0) {
        let v = 0;
        for (const iv of intervals) v += (iv - mean) * (iv - mean);
        cv = Math.sqrt(v / intervals.length) / mean;
      }
    }
    return { count: n, intervals, mean, cv, span: tMax - tMin, tMin, tMax, sorted };
  }

  function _renderStats(s) {
    const el = document.getElementById('chart-stats');
    if (!el) return;
    if (s.count === 0) {
      el.innerHTML = `<span class="stat-label">No timeline data on this finding.</span>`;
      return;
    }
    const countLabel = _finding && _finding.type === 'HTTP Beacon' ? 'Requests'
                     : _finding && _finding.type === 'DNS Beacon'  ? 'Queries'
                     : 'Connections';
    el.innerHTML =
      `<span><span class="stat-label">${countLabel}</span><span class="stat-value">${s.count.toLocaleString()}</span></span>` +
      `<span><span class="stat-label">Mean interval</span><span class="stat-value">${_fmtInterval(s.mean)}</span></span>` +
      `<span><span class="stat-label">Jitter (CV)</span><span class="stat-value">${s.cv.toFixed(2)}</span></span>` +
      `<span><span class="stat-label">Span</span><span class="stat-value">${_fmtSpan(s.span)}</span></span>`;
  }

  // ── Common drawing helpers ───────────────────────────────────────

  function _clearCanvas(ctx, W, H) {
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = PALETTE.bg;
    ctx.fillRect(0, 0, W, H);
  }

  function _drawEmpty(ctx, W, H, msg) {
    ctx.fillStyle = PALETTE.axis;
    ctx.font = `13px ${FONT_MONO}`;
    ctx.textAlign = 'center';
    ctx.fillText(msg, W / 2, H / 2);
  }

  // ── Phase 1: Timeline view ───────────────────────────────────────
  // Vertical ticks at each connection's timestamp, time on X.
  // Auto-fit the X axis so the full observed span is in frame.
  function _drawTimeline(ctx, W, H, stats) {
    if (stats.count === 0) {
      _drawEmpty(ctx, W, H, 'No timeline data for this finding');
      _timelinePlot = null;
      return;
    }
    const PAD = { top: 28, right: 16, bottom: 54, left: 72 };
    const plotW = W - PAD.left - PAD.right;
    const plotH = H - PAD.top  - PAD.bottom;

    // Apply zoom if the analyst brush-selected a sub-range. Falls back
    // to the full data span when _xRange is null. Filtering the sorted
    // array means dense regions render at the new pixel-density and
    // sparse regions stretch.
    let tMin = stats.tMin, tMax = stats.tMax, sorted = stats.sorted;
    if (_xRange) {
      tMin = Math.max(_xRange[0], stats.tMin);
      tMax = Math.min(_xRange[1], stats.tMax);
      if (tMax <= tMin) {
        // Nonsense range — drop the zoom, go back to auto-fit.
        _xRange = null;
        tMin = stats.tMin; tMax = stats.tMax;
      } else {
        sorted = stats.sorted.filter(r => r[0] >= tMin && r[0] <= tMax);
      }
    }
    const span = Math.max(tMax - tMin, 1);

    const ptsX = sorted.map(r => PAD.left + ((r[0] - tMin) / span) * plotW);

    // Density alpha: collapse alpha when many ticks fall in one pixel
    const buckets = new Array(plotW).fill(0);
    ptsX.forEach(x => {
      const i = Math.floor(x - PAD.left);
      if (i >= 0 && i < plotW) buckets[i]++;
    });
    const maxDensity = Math.max(...buckets, 1);
    const midY = PAD.top + plotH / 2;
    const tickHalf = plotH * 0.42;

    _timelinePlot = { padLeft: PAD.left, plotW, tMin, tMax, buckets };

    // Y-axis label
    ctx.save();
    ctx.fillStyle = PALETTE.label;
    ctx.font = `11px ${FONT_MONO}`;
    ctx.textAlign = 'center';
    ctx.translate(14, PAD.top + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('Connections', 0, 0);
    ctx.restore();

    // Soft band behind tick area gives the eye an anchor in sparse stretches
    ctx.globalAlpha = 0.04;
    ctx.fillStyle = PALETTE.accent;
    ctx.fillRect(PAD.left, midY - tickHalf, plotW, tickHalf * 2);
    ctx.globalAlpha = 1;

    // Faint horizontal guideline at the midline
    ctx.strokeStyle = PALETTE.grid;
    ctx.globalAlpha = 0.6;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(PAD.left, midY); ctx.lineTo(PAD.left + plotW, midY);
    ctx.stroke();
    ctx.globalAlpha = 1;

    // Ticks
    ctx.lineCap = 'round';
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = PALETTE.bar;
    ptsX.forEach(x => {
      const idx = Math.max(0, Math.min(plotW - 1, Math.floor(x - PAD.left)));
      const density = buckets[idx];
      // Alpha climbs with density up to a soft cap so dense regions stay
      // visible but sparse ticks aren't washed out
      const alpha = Math.min(0.95, 0.35 + 0.65 * Math.min(1, density / Math.max(2, maxDensity / 4))) * _animT;
      ctx.globalAlpha = alpha;
      ctx.beginPath();
      ctx.moveTo(x, midY - tickHalf);
      ctx.lineTo(x, midY + tickHalf);
      ctx.stroke();
    });
    ctx.globalAlpha = 1;

    // Axes
    ctx.strokeStyle = PALETTE.grid;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(PAD.left, PAD.top + plotH);
    ctx.lineTo(PAD.left + plotW, PAD.top + plotH);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(PAD.left, PAD.top);
    ctx.lineTo(PAD.left, PAD.top + plotH);
    ctx.stroke();

    // X tick labels: scaled to plot width, rendered horizontally
    const xTicks = _xTickCount(plotW);
    ctx.fillStyle = PALETTE.label;
    ctx.font = `10px ${FONT_MONO}`;
    ctx.textAlign = 'center';
    for (let i = 0; i <= xTicks; i++) {
      const t = tMin + (i / xTicks) * span;
      const x = PAD.left + (i / xTicks) * plotW;
      ctx.fillText(_timeLabel(t, span), x, PAD.top + plotH + 16);
    }
    ctx.fillStyle = PALETTE.label;
    ctx.font = `11px ${FONT_MONO}`;
    ctx.textAlign = 'center';
    const axisLabel = _xRange
      ? `Time (UTC) — zoomed: ${sorted.length} of ${stats.count} connections`
      : 'Time (UTC)';
    ctx.fillText(axisLabel, PAD.left + plotW / 2, H - 4);

    // Crosshair on hover
    if (_crosshairX !== null) {
      ctx.save();
      ctx.setLineDash([3, 3]);
      ctx.strokeStyle = PALETTE.text;
      ctx.globalAlpha = 0.35;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(_crosshairX, PAD.top);
      ctx.lineTo(_crosshairX, PAD.top + plotH);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.globalAlpha = 1;
      ctx.restore();
    }

    // Brush selection rectangle, drawn last so it sits on top of ticks.
    if (_brushing) {
      const x0 = Math.min(_brushStartX, _brushCurrentX);
      const x1 = Math.max(_brushStartX, _brushCurrentX);
      const w = Math.max(1, x1 - x0);
      ctx.globalAlpha = 0.18;
      ctx.fillStyle = PALETTE.accent;
      ctx.fillRect(x0, PAD.top, w, plotH);
      ctx.globalAlpha = 0.6;
      ctx.strokeStyle = PALETTE.accent;
      ctx.lineWidth = 1;
      ctx.strokeRect(x0 + 0.5, PAD.top + 0.5, w, plotH);
      ctx.globalAlpha = 1;
    }
  }

  // ── Phase 2: Interval histogram ──────────────────────────────────
  // Bar chart of how many inter-arrival gaps fell into each bucket
  // of seconds-between-connections. A beacon's heartbeat shows up
  // as a tall single-bar peak at its period.
  function _drawIntervals(ctx, W, H, stats) {
    if (!stats.intervals || stats.intervals.length === 0) {
      _drawEmpty(ctx, W, H, 'Need at least 2 connections to compute intervals');
      return;
    }
    const ivs = stats.intervals.slice().sort((a, b) => a - b);
    // Trim the top 1% so a single multi-day gap doesn't squash the
    // histogram into the leftmost bar. Keeps the heartbeat visible.
    const trimIdx = Math.max(1, Math.floor(ivs.length * 0.99));
    const trimmed = ivs.slice(0, trimIdx);
    const lo = trimmed[0];
    const hi = trimmed[trimmed.length - 1];
    const numBuckets = Math.min(40, Math.max(12, Math.floor(Math.sqrt(trimmed.length) * 2)));
    // Linear bucketing across the trimmed range. Log scaling tempts but
    // makes the "is there a peak?" question harder to answer at a glance.
    const range = Math.max(hi - lo, 0.001);
    const bw = range / numBuckets;
    const counts = new Array(numBuckets).fill(0);
    trimmed.forEach(v => {
      let i = Math.floor((v - lo) / bw);
      if (i < 0) i = 0;
      if (i >= numBuckets) i = numBuckets - 1;
      counts[i]++;
    });
    const maxCount = Math.max(...counts, 1);

    const PAD = { top: 28, right: 16, bottom: 56, left: 72 };
    const plotW = W - PAD.left - PAD.right;
    const plotH = H - PAD.top  - PAD.bottom;
    const slotW = plotW / numBuckets;
    const barW  = Math.max(Math.floor(slotW * 0.78), 2);

    _intervalsPlot = { padLeft: PAD.left, plotW, lo, range, numBuckets, counts, total: trimmed.length };

    // Y gridlines + labels (counts)
    const yTicks = 4;
    ctx.lineWidth = 1;
    for (let i = 0; i <= yTicks; i++) {
      const y = PAD.top + plotH - (i / yTicks) * plotH;
      ctx.strokeStyle = PALETTE.grid;
      ctx.globalAlpha = 0.6;
      ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(PAD.left + plotW, y); ctx.stroke();
      ctx.globalAlpha = 1;
      ctx.fillStyle = PALETTE.axis;
      ctx.font = `10px ${FONT_MONO}`;
      ctx.textAlign = 'right';
      ctx.fillText(Math.round((i / yTicks) * maxCount).toLocaleString(), PAD.left - 5, y + 3);
    }
    ctx.save();
    ctx.fillStyle = PALETTE.label;
    ctx.font = `11px ${FONT_MONO}`;
    ctx.textAlign = 'center';
    ctx.translate(14, PAD.top + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('Connections', 0, 0);
    ctx.restore();

    // Gradient for bars, built once before the loop. Fades within the
    // accent hue, not toward the background — short bars sampling the
    // bottom stops must still read as accent-colored.
    const grad = ctx.createLinearGradient(0, PAD.top, 0, PAD.top + plotH);
    grad.addColorStop(0, PALETTE.bar);
    grad.addColorStop(1, _alphaColor(ctx, PALETTE.bar, 0.35));

    // Bars
    counts.forEach((c, i) => {
      const x  = PAD.left + i * slotW;
      const cx = x + slotW / 2;
      const barH = (c / maxCount) * plotH * _animT;
      const barY = PAD.top + plotH - barH;
      const barX = cx - barW / 2;
      if (c > 0) {
        ctx.fillStyle = grad;
        const r = Math.min(2, barW / 2, barH);
        ctx.beginPath();
        ctx.moveTo(barX, barY + barH);
        ctx.lineTo(barX, barY + r);
        ctx.arcTo(barX, barY, barX + r, barY, r);
        ctx.lineTo(barX + barW - r, barY);
        ctx.arcTo(barX + barW, barY, barX + barW, barY + r, r);
        ctx.lineTo(barX + barW, barY + barH);
        ctx.closePath();
        ctx.fill();
      }
    });

    // Mean-interval reference line (where a perfect beacon's peak should land)
    if (stats.mean > 0 && stats.mean >= lo && stats.mean <= hi) {
      const mx = PAD.left + ((stats.mean - lo) / range) * plotW;
      ctx.strokeStyle = PALETTE.accent;
      ctx.setLineDash([4, 3]);
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.moveTo(mx, PAD.top); ctx.lineTo(mx, PAD.top + plotH);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = PALETTE.accent;
      ctx.font = `10px ${FONT_MONO}`;
      ctx.textAlign = 'left';
      ctx.fillText(`mean ${_fmtInterval(stats.mean)}`, mx + 4, PAD.top + 10);
    }

    // Axes
    ctx.strokeStyle = PALETTE.grid;
    ctx.beginPath();
    ctx.moveTo(PAD.left, PAD.top + plotH);
    ctx.lineTo(PAD.left + plotW, PAD.top + plotH);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(PAD.left, PAD.top);
    ctx.lineTo(PAD.left, PAD.top + plotH);
    ctx.stroke();

    // X tick labels: scaled to plot width, rendered horizontally
    const xTicks = _xTickCount(plotW);
    ctx.fillStyle = PALETTE.label;
    ctx.font = `10px ${FONT_MONO}`;
    ctx.textAlign = 'center';
    for (let i = 0; i <= xTicks; i++) {
      const v = lo + (i / xTicks) * range;
      const x = PAD.left + (i / xTicks) * plotW;
      ctx.fillText(_fmtInterval(v), x, PAD.top + plotH + 16);
    }
    ctx.fillStyle = PALETTE.label;
    ctx.font = `11px ${FONT_MONO}`;
    ctx.textAlign = 'center';
    ctx.fillText('Inter-arrival interval (top 1% trimmed)', PAD.left + plotW / 2, H - 4);
  }

  // ── Phase 3: Bytes view ──────────────────────────────────────────
  // Mirror chart: bytes sent per time bucket above the zero axis,
  // bytes received below it, on a shared scale. Useful when verifying
  // whether a beacon also exfils — heartbeat = constant bytes per
  // call; exfil callbacks = upward spike with no matching download.
  function _drawBytes(ctx, W, H, stats) {
    if (stats.count === 0) {
      _drawEmpty(ctx, W, H, 'No timeline data for this finding');
      return;
    }
    const span = Math.max(stats.span, 1);
    const numBuckets = Math.min(stats.count, 24);
    const bucketSec = span / numBuckets;
    const buckets = Array.from({length: numBuckets}, (_, i) => ({
      tStart: stats.tMin + i * bucketSec,
      origBytes: 0,
      respBytes: 0,
      count: 0,
    }));
    stats.sorted.forEach(r => {
      const idx = Math.min(Math.floor((r[0] - stats.tMin) / bucketSec), numBuckets - 1);
      buckets[idx].origBytes += r[1];
      buckets[idx].respBytes += r[2];
      buckets[idx].count++;
    });
    // Shared scale across both directions so the halves are comparable.
    const maxBytes = Math.max(...buckets.map(b => Math.max(b.origBytes, b.respBytes)), 1);

    const PAD = { top: 28, right: 16, bottom: 56, left: 72 };
    const plotW = W - PAD.left - PAD.right;
    const plotH = H - PAD.top  - PAD.bottom;
    const halfH = plotH / 2;
    const midY  = PAD.top + halfH;
    const slotW = plotW / numBuckets;
    const barW  = Math.max(Math.floor(slotW * 0.7), 2);

    _bytesPlot = { padLeft: PAD.left, plotW, buckets, span };

    // Symmetric gridlines: zero axis at mid, half/full magnitude each way.
    [-1, -0.5, 0, 0.5, 1].forEach(f => {
      const y = midY - f * halfH;
      ctx.strokeStyle = PALETTE.grid;
      ctx.globalAlpha = f === 0 ? 1 : 0.6;
      ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(PAD.left + plotW, y); ctx.stroke();
      ctx.globalAlpha = 1;
      ctx.fillStyle = PALETTE.axis;
      ctx.font = `10px ${FONT_MONO}`;
      ctx.textAlign = 'right';
      ctx.fillText(_fmtBytes(Math.abs(f) * maxBytes), PAD.left - 5, y + 3);
    });
    ctx.save();
    ctx.fillStyle = PALETTE.label;
    ctx.font = `11px ${FONT_MONO}`;
    ctx.textAlign = 'center';
    ctx.translate(14, midY);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('Sent ↑ · Received ↓', 0, 0);
    ctx.restore();

    // Sent in the accent hue, received in the chart-4 series hue —
    // distinct directions at a glance. Both fade to a lighter stop at
    // the zero axis, strongest at their outer edge.
    const grad = ctx.createLinearGradient(0, PAD.top, 0, midY);
    grad.addColorStop(0, PALETTE.bar);
    grad.addColorStop(1, _alphaColor(ctx, PALETTE.bar, 0.35));
    const recvFill = ctx.createLinearGradient(0, midY, 0, PAD.top + plotH);
    recvFill.addColorStop(0, _alphaColor(ctx, PALETTE.recv, 0.35));
    recvFill.addColorStop(1, PALETTE.recv);

    const labelEvery = Math.max(1, Math.ceil(numBuckets / 10));
    buckets.forEach((b, i) => {
      const x  = PAD.left + i * slotW;
      const cx = x + slotW / 2;
      const barX = cx - barW / 2;
      if (b.origBytes > 0) {
        const sentH = (b.origBytes / maxBytes) * halfH * _animT;
        const sentY = midY - sentH;
        // Upload-dominant flag: 2x, not merely sent > recv — header and
        // keepalive jitter tips near-balanced buckets either way, and the
        // mirror already shows the margin. Red is reserved for buckets
        // where outbound volume clearly leads.
        ctx.fillStyle = b.origBytes > 2 * b.respBytes ? PALETTE.barHi : grad;
        const r = Math.min(2, barW / 2, sentH);
        ctx.beginPath();
        ctx.moveTo(barX, midY);
        ctx.lineTo(barX, sentY + r);
        ctx.arcTo(barX, sentY, barX + r, sentY, r);
        ctx.lineTo(barX + barW - r, sentY);
        ctx.arcTo(barX + barW, sentY, barX + barW, sentY + r, r);
        ctx.lineTo(barX + barW, midY);
        ctx.closePath();
        ctx.fill();
        if (sentH > 16) {
          ctx.fillStyle = 'rgba(255,255,255,0.75)';
          ctx.font = `9px ${FONT_MONO}`;
          ctx.textAlign = 'center';
          ctx.fillText(_fmtBytes(b.origBytes), cx, sentY + 10);
        }
      }
      if (b.respBytes > 0) {
        const recvH = (b.respBytes / maxBytes) * halfH * _animT;
        const recvBot = midY + recvH;
        ctx.fillStyle = recvFill;
        const r = Math.min(2, barW / 2, recvH);
        ctx.beginPath();
        ctx.moveTo(barX, midY);
        ctx.lineTo(barX, recvBot - r);
        ctx.arcTo(barX, recvBot, barX + r, recvBot, r);
        ctx.lineTo(barX + barW - r, recvBot);
        ctx.arcTo(barX + barW, recvBot, barX + barW, recvBot - r, r);
        ctx.lineTo(barX + barW, midY);
        ctx.closePath();
        ctx.fill();
        if (recvH > 16) {
          ctx.fillStyle = 'rgba(255,255,255,0.75)';
          ctx.font = `9px ${FONT_MONO}`;
          ctx.textAlign = 'center';
          ctx.fillText(_fmtBytes(b.respBytes), cx, recvBot - 5);
        }
      }
      if (i % labelEvery === 0) {
        ctx.fillStyle = PALETTE.label;
        ctx.font = `9px ${FONT_MONO}`;
        ctx.textAlign = 'center';
        ctx.fillText(_timeLabel(b.tStart, span), cx, PAD.top + plotH + 16);
      }
    });

    ctx.strokeStyle = PALETTE.grid;
    ctx.beginPath();
    ctx.moveTo(PAD.left, PAD.top + plotH);
    ctx.lineTo(PAD.left + plotW, PAD.top + plotH);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(PAD.left, PAD.top);
    ctx.lineTo(PAD.left, PAD.top + plotH);
    ctx.stroke();

    ctx.fillStyle = PALETTE.label;
    ctx.font = `11px ${FONT_MONO}`;
    ctx.textAlign = 'center';
    ctx.fillText('Time (UTC)', PAD.left + plotW / 2, H - 4);

    // Legend
    const legX = PAD.left + 4;
    ctx.font = `9px ${FONT_MONO}`;
    ctx.textAlign = 'left';
    ctx.fillStyle = PALETTE.bar;
    ctx.fillRect(legX, 8, 10, 8);
    ctx.fillStyle = PALETTE.text;
    ctx.fillText('sent ↑', legX + 14, 16);
    ctx.fillStyle = PALETTE.barHi;
    ctx.fillRect(legX + 62, 8, 10, 8);
    ctx.fillStyle = PALETTE.text;
    ctx.fillText('upload-heavy', legX + 76, 16);
    ctx.fillStyle = PALETTE.recv;
    ctx.fillRect(legX + 148, 8, 10, 8);
    ctx.fillStyle = PALETTE.text;
    ctx.fillText('received ↓', legX + 162, 16);
  }

  // ── Tooltip + crosshair ──────────────────────────────────────────

  function _showTooltip(ev, html) {
    const tip = document.getElementById('chart-tooltip');
    const cv = document.getElementById('chart-canvas');
    if (!tip || !cv) return;
    tip.innerHTML = html;
    tip.hidden = false;
    const rect = cv.getBoundingClientRect();
    const wrap = cv.parentElement.getBoundingClientRect();
    let left = ev.clientX - wrap.left + 14;
    let top = ev.clientY - wrap.top + 14;
    if (ev.clientX - rect.left > rect.width * 0.65) left -= tip.offsetWidth + 28;
    // Flip above the cursor near the bottom edge so the tooltip never
    // overflows the dialog body (which would flash a scrollbar).
    if (ev.clientY - rect.top > rect.height * 0.6) top -= tip.offsetHeight + 28;
    tip.style.left = left + 'px';
    tip.style.top = top + 'px';
  }

  function _hideTooltip() {
    const tip = document.getElementById('chart-tooltip');
    if (tip) tip.hidden = true;
    if (_crosshairX !== null) { _crosshairX = null; if (_viewMode === 'timeline') _render(); }
  }

  function _onHoverMove(ev) {
    if (_brushing) { _hideTooltip(); return; }
    const x = _canvasX(ev);
    let html = '';
    if (_viewMode === 'intervals' && _intervalsPlot) {
      const p = _intervalsPlot;
      const i = _bucketAt(x, p.padLeft, p.plotW, p.numBuckets);
      if (i >= 0) {
        const b0 = p.lo + (i / p.numBuckets) * p.range;
        const b1 = p.lo + ((i + 1) / p.numBuckets) * p.range;
        const c = p.counts[i];
        const share = p.total ? Math.round((c / p.total) * 100) : 0;
        html = `<span class="tt-dim">${_fmtInterval(b0)} – ${_fmtInterval(b1)}</span><br>` +
               `<strong>${c.toLocaleString()}</strong> connections · ${share}%`;
      }
    } else if (_viewMode === 'bytes' && _bytesPlot) {
      const p = _bytesPlot;
      const i = _bucketAt(x, p.padLeft, p.plotW, p.buckets.length);
      if (i >= 0) {
        const b = p.buckets[i];
        html = `<span class="tt-dim">${_timeLabel(b.tStart, p.span)}</span><br>` +
               `sent <strong>${_fmtBytes(b.origBytes)}</strong> · recv ${_fmtBytes(b.respBytes)}<br>` +
               `<span class="tt-dim">${b.count} connections</span>`;
      }
    } else if (_viewMode === 'timeline' && _timelinePlot && _timelinePlot.buckets) {
      const p = _timelinePlot;
      const i = Math.floor(x - p.padLeft);
      if (i >= 0 && i < p.plotW) {
        const t = p.tMin + (i / p.plotW) * (p.tMax - p.tMin);
        html = `<span class="tt-dim">${_timeLabel(t, p.tMax - p.tMin)}</span><br>` +
               `<strong>${p.buckets[i]}</strong> in this column`;
        _crosshairX = x;
      }
    }
    if (!html) { _hideTooltip(); return; }
    _showTooltip(ev, html);
    if (_viewMode === 'timeline') _render();
  }

  // ── Render ───────────────────────────────────────────────────────

  function _render() {
    PALETTE = _readPalette();
    const cv  = document.getElementById('chart-canvas');
    const ctx = _setupCanvas(cv);
    const W = LOGICAL_W, H = LOGICAL_H;
    _intervalsPlot = null;
    _bytesPlot = null;
    _clearCanvas(ctx, W, H);
    const tsData = (_finding && _finding.ts_data) || [];
    const stats = _computeStats(tsData);
    _renderStats(stats);
    if (_viewMode === 'intervals') return _drawIntervals(ctx, W, H, stats);
    if (_viewMode === 'bytes')     return _drawBytes(ctx, W, H, stats);
    return _drawTimeline(ctx, W, H, stats);
  }

  function show(finding) {
    _finding = finding;
    _xRange = null;
    _brushing = false;
    // DNS Beacon emits timing-only TSData (byte columns are zero).
    // Drop back to timeline if the analyst was on the bytes view, and
    // hide the Bytes button so they can't navigate to a meaningless chart.
    const hasByteData = finding.type !== 'DNS Beacon';
    if (!hasByteData && _viewMode === 'bytes') _viewMode = 'timeline';
    const dialog = document.getElementById('chart-dialog');
    document.getElementById('chart-title').textContent =
      `Beacon — ${finding.src_ip} → ${finding.dst_ip || '?'}${finding.dst_port ? ':' + finding.dst_port : ''}`;
    document.querySelectorAll('.chart-view-btn').forEach(b => {
      if (b.dataset.view === 'bytes') b.style.display = hasByteData ? '' : 'none';
      b.classList.toggle('active', b.dataset.view === _viewMode);
    });
    _updateZoomUI();
    dialog.showModal();
    _hideTooltip();
    _startAnim();
  }

  // ── Export ───────────────────────────────────────────────────────
  // Snapshot the current canvas as PNG or JPEG. Filename includes the
  // src→dst pair and the active view so an analyst exporting all three
  // tabs gets distinct files. Mirrors the cytoscape-graph export
  // pattern from app.js (_commitGraphExport).
  function _safeFilenamePart(s) {
    return String(s || '').replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/^_+|_+$/g, '');
  }
  function _ts() {
    const d = new Date();
    const pad = n => n.toString().padStart(2, '0');
    return `${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
  }

  function exportImage(format) {
    const cv = document.getElementById('chart-canvas');
    if (!cv || !_finding) return;
    const isJpeg = format === 'jpeg';
    const mime = isJpeg ? 'image/jpeg' : 'image/png';
    const ext  = isJpeg ? 'jpg' : 'png';
    // The canvas already paints PALETTE.bg, so JPEG (no alpha) lands on
    // the same dark panel color the analyst sees on screen — no need
    // for a pre-export fill pass.
    cv.toBlob(blob => {
      if (!blob) return;
      const dst = _finding.dst_ip || 'dst';
      const port = _finding.dst_port ? ':' + _finding.dst_port : '';
      const tag  = _safeFilenamePart(`${_finding.src_ip || 'src'}_${dst}${port}_${_viewMode}`);
      const filename = `archer_beacon_${tag}_${_ts()}.${ext}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }, mime, isJpeg ? 0.95 : undefined);
  }

  function _updateZoomUI() {
    const btn = document.getElementById('chart-reset-zoom');
    if (btn) btn.style.display = (_xRange && _viewMode === 'timeline') ? '' : 'none';
    const cv = document.getElementById('chart-canvas');
    if (cv) cv.style.cursor = (_viewMode === 'timeline') ? 'crosshair' : 'default';
  }

  function _canvasX(ev) {
    const cv = document.getElementById('chart-canvas');
    const rect = cv.getBoundingClientRect();
    const scale = LOGICAL_W / rect.width;
    return (ev.clientX - rect.left) * scale;
  }

  function _onMouseDown(ev) {
    if (_viewMode !== 'timeline' || !_timelinePlot) return;
    if (ev.button !== 0) return;
    _brushing = true;
    _brushStartX = _canvasX(ev);
    _brushCurrentX = _brushStartX;
    ev.preventDefault();
  }

  function _onMouseMove(ev) {
    if (!_brushing) return;
    _brushCurrentX = _canvasX(ev);
    _render();
  }

  function _onMouseUp(ev) {
    if (!_brushing) return;
    _brushing = false;
    if (!_timelinePlot) { _render(); return; }
    const x0 = Math.min(_brushStartX, _brushCurrentX);
    const x1 = Math.max(_brushStartX, _brushCurrentX);
    // Ignore tiny drags (treat as a click, no zoom change)
    if (x1 - x0 < 6) { _render(); return; }
    const { padLeft, plotW, tMin, tMax } = _timelinePlot;
    const fracStart = Math.max(0, Math.min(1, (x0 - padLeft) / plotW));
    const fracEnd   = Math.max(0, Math.min(1, (x1 - padLeft) / plotW));
    const span = tMax - tMin;
    _xRange = [tMin + fracStart * span, tMin + fracEnd * span];
    _updateZoomUI();
    _render();
  }

  function _onContextMenu(ev) {
    if (_viewMode !== 'timeline') return;
    if (!_xRange) return;
    ev.preventDefault();
    _xRange = null;
    _updateZoomUI();
    _render();
  }

  function _resetZoom() {
    _xRange = null;
    _updateZoomUI();
    _render();
  }

  function init() {
    document.querySelectorAll('.chart-view-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        _viewMode = btn.dataset.view;
        // Switching away from Timeline drops any active zoom — the
        // other views have their own X mappings and the zoom range
        // would be meaningless on them.
        if (_viewMode !== 'timeline') _xRange = null;
        document.querySelectorAll('.chart-view-btn').forEach(b =>
          b.classList.toggle('active', b === btn));
        _updateZoomUI();
        _hideTooltip();
        if (_finding) _startAnim();
      });
    });
    document.getElementById('chart-close').addEventListener('click', () => {
      document.getElementById('chart-dialog').close();
    });
    document.getElementById('chart-dialog').addEventListener('close', () => cancelAnimationFrame(_animRaf));
    const resetBtn = document.getElementById('chart-reset-zoom');
    if (resetBtn) resetBtn.addEventListener('click', _resetZoom);

    const cv = document.getElementById('chart-canvas');
    if (cv) {
      cv.addEventListener('mousedown', _onMouseDown);
      cv.addEventListener('contextmenu', _onContextMenu);
      cv.addEventListener('mousemove', _onHoverMove);
      cv.addEventListener('mouseleave', _hideTooltip);
      // Mouse-up and move bind to window so dragging off the canvas
      // still completes the brush cleanly.
      window.addEventListener('mousemove', _onMouseMove);
      window.addEventListener('mouseup', _onMouseUp);
    }
    // Repaint with the new skin's tokens if the theme changes while open.
    window.addEventListener('archer:themechange', () => {
      const dlg = document.getElementById('chart-dialog');
      if (dlg && dlg.open) _render();
    });
  }

  return { init, show, exportImage };
})();
