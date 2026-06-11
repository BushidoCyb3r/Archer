// trend.js — findings-over-time chart above the findings table.
//
// One line per detection family, fed by /api/findings/trend with the same
// filter params as the table below it, so the two always agree. Drag on the
// canvas to zoom an x range; "Apply as filter" writes the zoomed range into
// the query box as a ts:[a TO b] token (wired via init's onApplyRange).
// Hand-drawn canvas — no chart library, consistent with chart.js/graph.js
// and the no-CDN constraint of air-gapped installs.
'use strict';

const Trend = (() => {
  let _days = [];
  let _series = [];          // family lens
  let _sevSeries = [];       // severity lens — same day axis, same response
  let _mode = localStorage.getItem('archer.trendMode') === 'severity' ? 'severity' : 'family';
  let _off = new Set();      // legend-toggled-off series keys (family and severity keys don't collide)
  let _zoom = null;          // [i0, i1] day-index range, null = full span
  let _collapsed = localStorage.getItem('archer.trendCollapsed') === '1';
  let _onApplyRange = null;

  // Refetch bookkeeping: _lastQS is re-fetched on expand if a refresh
  // arrived while collapsed; _fetchSeq drops stale responses when filter
  // changes race.
  let _lastQS = null;
  let _pendingQS = null;
  let _fetchSeq = 0;

  let _plot = null;          // geometry of the last render, for mouse mapping
  let _brushing = false;
  let _brushStartX = 0;
  let _brushCurX = 0;

  const FONT = '10px ui-monospace, "SF Mono", Menlo, Monaco, Consolas, monospace';
  const HEIGHT = 150;
  const PAD = { left: 46, right: 14, top: 10, bottom: 20 };

  function _tok(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  // Series key → theme token, both lenses. Family colors deliberately use
  // no green (--ok) — green reads "safe" and every line here is a
  // detection; the severity lens maps straight onto the severity tokens.
  const SERIES_TOKEN = {
    beaconing: '--accent',
    ti:        '--sev-critical',
    exfil:     '--sev-high',
    dns:       '--sev-medium',
    lateral:   '--ioc',
    tls:       '--fg-secondary',
    other:     '--fg-faint',
    critical:  '--sev-critical',
    high:      '--sev-high',
    medium:    '--sev-medium',
    low:       '--sev-low',
    info:      '--sev-info',
  };
  function _colorOf(key) { return _tok(SERIES_TOKEN[key] || '--fg-faint'); }

  function _el(id) { return document.getElementById(id); }

  function _activeSeries() { return _mode === 'severity' ? _sevSeries : _series; }

  function _visibleSeries() { return _activeSeries().filter(s => !_off.has(s.key)); }

  // _yMaxFor is the y-axis ceiling over the visible series within the
  // zoomed day range — never 0, so the axis stays drawable when every
  // visible line is flat-zero (or every series is toggled off). Pure
  // (web/test/trend.test.js).
  function _yMaxFor(series, i0, i1) {
    let yMax = 0;
    series.forEach(s => {
      for (let i = i0; i <= i1; i++) if (s.counts[i] > yMax) yMax = s.counts[i];
    });
    return yMax === 0 ? 1 : yMax;
  }

  function _range() {
    if (!_days.length) return [0, -1];
    return _zoom || [0, _days.length - 1];
  }

  // ── Fetch ──────────────────────────────────────────────────────────────

  async function refresh(qs) {
    _pendingQS = qs;
    if (_collapsed) return; // fetched lazily on expand
    const seq = ++_fetchSeq;
    let data;
    try {
      const r = await fetch('/api/findings/trend' + (qs ? '?' + qs : ''));
      if (!r.ok) return; // bad query — the table's own error toast covers it
      data = await r.json();
    } catch (e) { return; }
    if (seq !== _fetchSeq) return;
    _lastQS = qs;
    _days = Array.isArray(data.days) ? data.days : [];
    _series = Array.isArray(data.series) ? data.series : [];
    _sevSeries = Array.isArray(data.severity_series) ? data.severity_series : [];
    _zoom = null;
    _updateZoomControls();
    _renderLegend();
    render();
  }

  // setVisible toggles the whole panel (hidden on the aggregate views).
  // No fetch here — every findings-tab render calls refresh() right after,
  // and nothing refreshes while the panel is hidden.
  function setVisible(on) {
    const panel = _el('trend-panel');
    if (!panel) return;
    panel.classList.toggle('hidden', !on);
    if (on) render();
  }

  // ── Legend ─────────────────────────────────────────────────────────────

  function _renderLegend() {
    const box = _el('trend-legend');
    if (!box) return;
    box.textContent = '';
    _activeSeries().forEach(s => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'trend-key' + (_off.has(s.key) ? ' off' : '');
      const sw = document.createElement('span');
      sw.className = 'trend-swatch';
      sw.style.background = _off.has(s.key) ? 'transparent' : _colorOf(s.key);
      sw.style.borderColor = _colorOf(s.key);
      btn.appendChild(sw);
      btn.appendChild(document.createTextNode(s.label));
      btn.addEventListener('click', () => {
        if (_off.has(s.key)) _off.delete(s.key); else _off.add(s.key);
        _renderLegend();
        render();
      });
      box.appendChild(btn);
    });
  }

  // ── Lens toggle ────────────────────────────────────────────────────────

  // Both lenses share the day axis, so the zoom survives a mode switch.
  function _setMode(mode) {
    _mode = mode;
    localStorage.setItem('archer.trendMode', mode);
    const fam = _el('trend-mode-family');
    const sev = _el('trend-mode-severity');
    if (fam) fam.classList.toggle('active', mode === 'family');
    if (sev) sev.classList.toggle('active', mode === 'severity');
    _renderLegend();
    render();
  }

  // ── Zoom controls ──────────────────────────────────────────────────────

  function _updateZoomControls() {
    const ctl = _el('trend-zoom-controls');
    if (!ctl) return;
    ctl.classList.toggle('hidden', !_zoom);
    if (_zoom) {
      const lbl = _el('trend-zoom-range');
      if (lbl) lbl.textContent = _days[_zoom[0]] + ' — ' + _days[_zoom[1]];
    }
  }

  function _resetZoom() {
    _zoom = null;
    _updateZoomControls();
    render();
  }

  // ── Rendering ──────────────────────────────────────────────────────────

  function _setupCanvas(cv, cssW, cssH) {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const bw = Math.round(cssW * dpr), bh = Math.round(cssH * dpr);
    if (cv.width !== bw || cv.height !== bh) { cv.width = bw; cv.height = bh; }
    cv.style.height = cssH + 'px';
    const ctx = cv.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return ctx;
  }

  function render() {
    const cv = _el('trend-canvas');
    const panel = _el('trend-panel');
    if (!cv || !panel || panel.classList.contains('hidden') || _collapsed) return;

    const W = cv.parentElement.clientWidth || 600;
    const H = HEIGHT;
    const ctx = _setupCanvas(cv, W, H);
    ctx.clearRect(0, 0, W, H);
    ctx.font = FONT;

    const [i0, i1] = _range();
    const n = i1 - i0 + 1;
    if (n <= 0) {
      ctx.fillStyle = _tok('--fg-faint');
      ctx.textAlign = 'center';
      ctx.fillText('No findings in the current view', W / 2, H / 2);
      _plot = null;
      return;
    }

    const plotW = W - PAD.left - PAD.right;
    const plotH = H - PAD.top - PAD.bottom;
    const xAt = i => PAD.left + (n === 1 ? plotW / 2 : ((i - i0) / (n - 1)) * plotW);

    const yMax = _yMaxFor(_visibleSeries(), i0, i1);
    const yAt = v => PAD.top + plotH - (v / yMax) * plotH;

    // Grid + y labels
    ctx.strokeStyle = _tok('--border-subtle');
    ctx.fillStyle = _tok('--fg-muted');
    ctx.lineWidth = 1;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    const ySteps = 4;
    for (let t = 0; t <= ySteps; t++) {
      const v = Math.round((yMax / ySteps) * t);
      const y = yAt(v);
      ctx.beginPath();
      ctx.moveTo(PAD.left, y);
      ctx.lineTo(W - PAD.right, y);
      ctx.stroke();
      ctx.fillText(v.toLocaleString(), PAD.left - 6, y);
    }

    // X tick labels — at most ~12, "MM-DD" from the UTC day string (full
    // dates live in the tooltip and the zoom-range label)
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    const every = Math.max(1, Math.ceil(n / 12));
    for (let i = i0; i <= i1; i += every) {
      ctx.fillText(_days[i].slice(5), xAt(i), H - PAD.bottom + 6);
    }

    // Series lines — cardinal-spline smoothing so day-to-day steps read as
    // a trend rather than a sawtooth. Control points are clamped to the
    // plot's y range so a curve can't dip below the zero axis (or overshoot
    // the top) next to a sharp spike.
    const drawPoints = n <= 60;
    const K = 0.22; // curvature: 1/6 ≈ Catmull-Rom; higher = rounder
    const yLo = PAD.top, yHi = PAD.top + plotH;
    const clampY = v => Math.max(yLo, Math.min(yHi, v));
    _visibleSeries().forEach(s => {
      const color = _colorOf(s.key);
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      const pts = [];
      for (let i = i0; i <= i1; i++) pts.push({ x: xAt(i), y: yAt(s.counts[i]) });
      ctx.moveTo(pts[0].x, pts[0].y);
      for (let j = 1; j < pts.length; j++) {
        const p0 = pts[j - 1], p1 = pts[j];
        const pm = pts[j - 2] || p0, pn = pts[j + 1] || p1;
        ctx.bezierCurveTo(
          p0.x + (p1.x - pm.x) * K, clampY(p0.y + (p1.y - pm.y) * K),
          p1.x - (pn.x - p0.x) * K, clampY(p1.y - (pn.y - p0.y) * K),
          p1.x, p1.y);
      }
      ctx.stroke();
      if (drawPoints || n === 1) {
        ctx.fillStyle = color;
        for (let i = i0; i <= i1; i++) {
          ctx.beginPath();
          ctx.arc(xAt(i), yAt(s.counts[i]), n === 1 ? 3 : 2, 0, Math.PI * 2);
          ctx.fill();
        }
      }
    });

    _plot = { i0, i1, n, xAt, padLeft: PAD.left, plotW, W, H };

    if (_brushing) {
      const a = Math.min(_brushStartX, _brushCurX), b = Math.max(_brushStartX, _brushCurX);
      ctx.fillStyle = _tok('--accent-soft');
      ctx.fillRect(a, PAD.top, b - a, plotH);
      ctx.strokeStyle = _tok('--accent');
      ctx.strokeRect(a, PAD.top, b - a, plotH);
    }
  }

  // ── Mouse: brush zoom + hover tooltip ──────────────────────────────────

  // _idxFor maps a canvas x to the nearest day index within [i0, i0+n-1].
  // Pure — the hit-testing core both the brush zoom and the hover tooltip
  // stand on (web/test/trend.test.js).
  function _idxFor(x, i0, n, padLeft, plotW) {
    if (n === 1) return i0;
    const f = (x - padLeft) / plotW;
    return Math.max(i0, Math.min(i0 + n - 1, i0 + Math.round(f * (n - 1))));
  }

  function _idxAtX(x) {
    if (!_plot) return null;
    return _idxFor(x, _plot.i0, _plot.n, _plot.padLeft, _plot.plotW);
  }

  function _hideTip() {
    const tip = _el('trend-tip');
    if (tip) tip.classList.add('hidden');
  }

  function _showTip(evX, idx) {
    const tip = _el('trend-tip');
    if (!tip || idx == null) return;
    tip.textContent = '';
    const title = document.createElement('div');
    title.className = 'trend-tip-day';
    title.textContent = _days[idx];
    tip.appendChild(title);
    _visibleSeries().forEach(s => {
      const row = document.createElement('div');
      const sw = document.createElement('span');
      sw.className = 'trend-swatch';
      sw.style.background = _colorOf(s.key);
      sw.style.borderColor = _colorOf(s.key);
      row.appendChild(sw);
      row.appendChild(document.createTextNode(s.label + ': ' + s.counts[idx].toLocaleString()));
      tip.appendChild(row);
    });
    tip.classList.remove('hidden');
    const body = _el('trend-body');
    const flip = evX > body.clientWidth - 170;
    tip.style.left = flip ? '' : (evX + 12) + 'px';
    tip.style.right = flip ? (body.clientWidth - evX + 12) + 'px' : '';
  }

  function _initMouse(cv) {
    cv.addEventListener('mousedown', e => {
      if (e.button !== 0 || !_plot) return;
      _brushing = true;
      _brushStartX = _brushCurX = e.offsetX;
      _hideTip();
      e.preventDefault();
    });
    cv.addEventListener('mousemove', e => {
      if (_brushing) {
        _brushCurX = e.offsetX;
        render();
      } else if (_plot) {
        _showTip(e.offsetX, _idxAtX(e.offsetX));
      }
    });
    cv.addEventListener('mouseleave', () => {
      _hideTip();
      if (_brushing) { _brushing = false; render(); }
    });
    cv.addEventListener('mouseup', e => {
      if (!_brushing) return;
      _brushing = false;
      const a = _idxAtX(Math.min(_brushStartX, e.offsetX));
      const b = _idxAtX(Math.max(_brushStartX, e.offsetX));
      // A click (no drag) isn't a zoom
      if (a == null || b == null || Math.abs(e.offsetX - _brushStartX) < 4) { render(); return; }
      _zoom = [a, b];
      _updateZoomControls();
      render();
    });
    cv.addEventListener('contextmenu', e => {
      if (_zoom) { e.preventDefault(); _resetZoom(); }
    });
  }

  // ── Collapse ───────────────────────────────────────────────────────────

  function _setCollapsed(on) {
    _collapsed = on;
    localStorage.setItem('archer.trendCollapsed', on ? '1' : '0');
    const body = _el('trend-body');
    const legend = _el('trend-legend');
    const mode = _el('trend-mode');
    const btn = _el('trend-collapse-btn');
    if (body) body.classList.toggle('hidden', on);
    if (legend) legend.classList.toggle('hidden', on);
    if (mode) mode.classList.toggle('hidden', on);
    if (btn) {
      btn.textContent = on ? '▸' : '▾';
      btn.setAttribute('aria-expanded', String(!on));
    }
    if (!on) {
      if (_pendingQS !== null && _pendingQS !== _lastQS) refresh(_pendingQS);
      else render();
    }
  }

  // ── Init ───────────────────────────────────────────────────────────────

  function init(opts) {
    _onApplyRange = opts && opts.onApplyRange;
    const cv = _el('trend-canvas');
    if (cv) _initMouse(cv);

    const collapseBtn = _el('trend-collapse-btn');
    if (collapseBtn) collapseBtn.addEventListener('click', () => _setCollapsed(!_collapsed));
    _setCollapsed(_collapsed);

    const famBtn = _el('trend-mode-family');
    if (famBtn) famBtn.addEventListener('click', () => _setMode('family'));
    const sevBtn = _el('trend-mode-severity');
    if (sevBtn) sevBtn.addEventListener('click', () => _setMode('severity'));
    _setMode(_mode);

    const applyBtn = _el('trend-apply-btn');
    if (applyBtn) applyBtn.addEventListener('click', () => {
      if (_zoom && _onApplyRange) _onApplyRange(_days[_zoom[0]], _days[_zoom[1]]);
    });
    const resetBtn = _el('trend-reset-btn');
    if (resetBtn) resetBtn.addEventListener('click', _resetZoom);

    window.addEventListener('resize', () => render());
    window.addEventListener('archer:themechange', () => { _renderLegend(); render(); });
  }

  return { init, refresh, setVisible, render };
})();
