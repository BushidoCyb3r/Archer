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
  let _timelinePlot = null; // { padLeft, plotW, tMin, tMax }

  const PALETTE = {
    bg:    '#1e1e2e',
    panel: '#2a2a3e',
    bar:   '#7c3aed',
    barHi: '#f38ba8',  // sent > received (potential exfil)
    tick:  '#7c3aed',
    grid:  '#313244',
    axis:  '#6c7086',
    text:  '#cdd6f4',
    label: '#a6adc8',
    accent:'#89b4fa',
  };

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
    ctx.font = '13px Helvetica';
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
    _timelinePlot = { padLeft: PAD.left, plotW, tMin, tMax };

    const ptsX = sorted.map(r => PAD.left + ((r[0] - tMin) / span) * plotW);

    // Density alpha: collapse alpha when many ticks fall in one pixel
    const buckets = new Array(plotW).fill(0);
    ptsX.forEach(x => {
      const i = Math.floor(x - PAD.left);
      if (i >= 0 && i < plotW) buckets[i]++;
    });
    const maxDensity = Math.max(...buckets, 1);

    // Y-axis label
    ctx.save();
    ctx.fillStyle = PALETTE.label;
    ctx.font = '10px Helvetica';
    ctx.textAlign = 'center';
    ctx.translate(14, PAD.top + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('Connections', 0, 0);
    ctx.restore();

    // Faint horizontal guideline at the midline so empty stretches still
    // give the eye an anchor
    ctx.strokeStyle = PALETTE.grid;
    ctx.lineWidth = 1;
    const midY = PAD.top + plotH / 2;
    ctx.beginPath();
    ctx.moveTo(PAD.left, midY); ctx.lineTo(PAD.left + plotW, midY);
    ctx.stroke();

    // Ticks
    const tickHalf = plotH * 0.42;
    ctx.lineCap = 'round';
    ctx.lineWidth = 1.5;
    ptsX.forEach(x => {
      const idx = Math.max(0, Math.min(plotW - 1, Math.floor(x - PAD.left)));
      const density = buckets[idx];
      // Alpha climbs with density up to a soft cap so dense regions stay
      // visible but sparse ticks aren't washed out
      const alpha = Math.min(0.95, 0.35 + 0.65 * Math.min(1, density / Math.max(2, maxDensity / 4)));
      ctx.strokeStyle = `rgba(124,58,237,${alpha.toFixed(3)})`;
      ctx.beginPath();
      ctx.moveTo(x, midY - tickHalf);
      ctx.lineTo(x, midY + tickHalf);
      ctx.stroke();
    });

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

    // X tick labels: 6 evenly spaced
    const xTicks = 6;
    ctx.fillStyle = PALETTE.label;
    ctx.font = '9px Helvetica';
    ctx.textAlign = 'center';
    for (let i = 0; i <= xTicks; i++) {
      const t = tMin + (i / xTicks) * span;
      const x = PAD.left + (i / xTicks) * plotW;
      ctx.save();
      ctx.translate(x, PAD.top + plotH + 10);
      ctx.rotate(Math.PI / 6);
      ctx.textAlign = 'left';
      ctx.fillText(_timeLabel(t, span), 0, 0);
      ctx.restore();
    }
    ctx.fillStyle = PALETTE.label;
    ctx.font = '10px Helvetica';
    ctx.textAlign = 'center';
    const axisLabel = _xRange
      ? `Time (UTC) — zoomed: ${sorted.length} of ${stats.count} connections`
      : 'Time (UTC)';
    ctx.fillText(axisLabel, PAD.left + plotW / 2, H - 4);

    // Brush selection rectangle, drawn last so it sits on top of ticks.
    if (_brushing) {
      const x0 = Math.min(_brushStartX, _brushCurrentX);
      const x1 = Math.max(_brushStartX, _brushCurrentX);
      const w = Math.max(1, x1 - x0);
      ctx.fillStyle = 'rgba(137,180,250,0.18)';
      ctx.fillRect(x0, PAD.top, w, plotH);
      ctx.strokeStyle = 'rgba(137,180,250,0.6)';
      ctx.lineWidth = 1;
      ctx.strokeRect(x0 + 0.5, PAD.top + 0.5, w, plotH);
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

    // Y gridlines + labels (counts)
    const yTicks = 4;
    ctx.lineWidth = 1;
    for (let i = 0; i <= yTicks; i++) {
      const y = PAD.top + plotH - (i / yTicks) * plotH;
      ctx.strokeStyle = PALETTE.grid;
      ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(PAD.left + plotW, y); ctx.stroke();
      ctx.fillStyle = PALETTE.axis;
      ctx.font = '9px Helvetica';
      ctx.textAlign = 'right';
      ctx.fillText(Math.round((i / yTicks) * maxCount).toLocaleString(), PAD.left - 5, y + 3);
    }
    ctx.save();
    ctx.fillStyle = PALETTE.label;
    ctx.font = '10px Helvetica';
    ctx.textAlign = 'center';
    ctx.translate(14, PAD.top + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('Connections', 0, 0);
    ctx.restore();

    // Bars
    counts.forEach((c, i) => {
      const x  = PAD.left + i * slotW;
      const cx = x + slotW / 2;
      const barH = (c / maxCount) * plotH;
      const barY = PAD.top + plotH - barH;
      const barX = cx - barW / 2;
      if (i % 2 === 0) {
        ctx.fillStyle = 'rgba(255,255,255,0.018)';
        ctx.fillRect(x, PAD.top, slotW, plotH);
      }
      if (c > 0) {
        ctx.fillStyle = PALETTE.bar;
        ctx.fillRect(barX, barY, barW, barH);
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
      ctx.font = '9px Helvetica';
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

    // X tick labels: 6 evenly spaced, formatted as intervals
    const xTicks = 6;
    ctx.fillStyle = PALETTE.label;
    ctx.font = '9px Helvetica';
    for (let i = 0; i <= xTicks; i++) {
      const v = lo + (i / xTicks) * range;
      const x = PAD.left + (i / xTicks) * plotW;
      ctx.save();
      ctx.translate(x, PAD.top + plotH + 10);
      ctx.rotate(Math.PI / 6);
      ctx.textAlign = 'left';
      ctx.fillText(_fmtInterval(v), 0, 0);
      ctx.restore();
    }
    ctx.fillStyle = PALETTE.label;
    ctx.font = '10px Helvetica';
    ctx.textAlign = 'center';
    ctx.fillText('Inter-arrival interval (top 1% trimmed)', PAD.left + plotW / 2, H - 4);
  }

  // ── Phase 3: Bytes view (legacy) ─────────────────────────────────
  // Bytes-sent per time bucket. Useful when verifying whether a
  // beacon also exfils — heartbeat = constant bytes per call;
  // exfil callbacks = occasional spike.
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
    const maxBytes = Math.max(...buckets.map(b => b.origBytes), 1);

    const PAD = { top: 28, right: 16, bottom: 56, left: 72 };
    const plotW = W - PAD.left - PAD.right;
    const plotH = H - PAD.top  - PAD.bottom;
    const slotW = plotW / numBuckets;
    const barW  = Math.max(Math.floor(slotW * 0.7), 2);

    const yTicks = 4;
    for (let i = 0; i <= yTicks; i++) {
      const y = PAD.top + plotH - (i / yTicks) * plotH;
      ctx.strokeStyle = PALETTE.grid;
      ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(PAD.left + plotW, y); ctx.stroke();
      ctx.fillStyle = PALETTE.axis;
      ctx.font = '9px Helvetica';
      ctx.textAlign = 'right';
      ctx.fillText(_fmtBytes((i / yTicks) * maxBytes), PAD.left - 5, y + 3);
    }
    ctx.save();
    ctx.fillStyle = PALETTE.label;
    ctx.font = '10px Helvetica';
    ctx.textAlign = 'center';
    ctx.translate(14, PAD.top + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('Bytes Sent', 0, 0);
    ctx.restore();

    const labelEvery = Math.max(1, Math.ceil(numBuckets / 10));
    buckets.forEach((b, i) => {
      const x  = PAD.left + i * slotW;
      const cx = x + slotW / 2;
      const barH = (b.origBytes / maxBytes) * plotH;
      const barY = PAD.top + plotH - barH;
      const barX = cx - barW / 2;
      if (i % 2 === 0) {
        ctx.fillStyle = 'rgba(255,255,255,0.018)';
        ctx.fillRect(x, PAD.top, slotW, plotH);
      }
      if (b.origBytes > 0) {
        ctx.fillStyle = b.origBytes > b.respBytes ? PALETTE.barHi : PALETTE.bar;
        ctx.fillRect(barX, barY, barW, barH);
        if (barH > 16) {
          ctx.fillStyle = 'rgba(255,255,255,0.75)';
          ctx.font = '8px Helvetica';
          ctx.textAlign = 'center';
          ctx.fillText(_fmtBytes(b.origBytes), cx, barY + 10);
        }
      }
      if (i % labelEvery === 0) {
        ctx.fillStyle = PALETTE.label;
        ctx.font = '8px Helvetica';
        ctx.save();
        ctx.translate(cx, PAD.top + plotH + 10);
        ctx.rotate(Math.PI / 6);
        ctx.textAlign = 'left';
        ctx.fillText(_timeLabel(b.tStart, span), 0, 0);
        ctx.restore();
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
    ctx.font = '10px Helvetica';
    ctx.textAlign = 'center';
    ctx.fillText('Time (UTC)', PAD.left + plotW / 2, H - 4);

    // Legend
    const legX = PAD.left + 4;
    ctx.fillStyle = PALETTE.bar;
    ctx.fillRect(legX, 8, 10, 8);
    ctx.fillStyle = PALETTE.text;
    ctx.font = '9px Helvetica';
    ctx.textAlign = 'left';
    ctx.fillText('normal', legX + 14, 16);
    ctx.fillStyle = PALETTE.barHi;
    ctx.fillRect(legX + 70, 8, 10, 8);
    ctx.fillStyle = PALETTE.text;
    ctx.fillText('sent > recv', legX + 84, 16);
  }

  // ── Render ───────────────────────────────────────────────────────

  function _render() {
    const cv  = document.getElementById('chart-canvas');
    const ctx = cv.getContext('2d');
    const W = cv.width, H = cv.height;
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
    _render();
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
    // Canvas can be CSS-scaled relative to its drawing-buffer width
    const scale = cv.width / rect.width;
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
        if (_finding) _render();
      });
    });
    document.getElementById('chart-close').addEventListener('click', () => {
      document.getElementById('chart-dialog').close();
    });
    const resetBtn = document.getElementById('chart-reset-zoom');
    if (resetBtn) resetBtn.addEventListener('click', _resetZoom);

    const cv = document.getElementById('chart-canvas');
    if (cv) {
      cv.addEventListener('mousedown', _onMouseDown);
      cv.addEventListener('contextmenu', _onContextMenu);
      // Mouse-up and move bind to window so dragging off the canvas
      // still completes the brush cleanly.
      window.addEventListener('mousemove', _onMouseMove);
      window.addEventListener('mouseup', _onMouseUp);
    }
  }

  return { init, show, exportImage };
})();
