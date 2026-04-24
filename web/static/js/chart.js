// chart.js — beacon data-volume chart
// X axis: time buckets  |  Y axis: bytes sent (vertical bars)
'use strict';

const BeaconChart = (() => {
  let _finding = null;
  let _windowSecs = 3600; // default: 1 hour

  const PALETTE = {
    bg:    '#1e1e2e',
    panel: '#2a2a3e',
    bar:   '#7c3aed',
    barHi: '#f38ba8',  // sent > received (potential exfil)
    grid:  '#313244',
    axis:  '#6c7086',
    text:  '#cdd6f4',
    label: '#a6adc8',
  };

  function _fmtBytes(n) {
    if (n >= 1073741824) return (n / 1073741824).toFixed(1) + ' GB';
    if (n >= 1048576)    return (n / 1048576).toFixed(1) + ' MB';
    if (n >= 1024)       return (n / 1024).toFixed(0) + ' KB';
    return n + ' B';
  }

  function _timeLabel(ts) {
    const d = new Date(ts * 1000);
    const hh = d.getUTCHours().toString().padStart(2, '0');
    const mm = d.getUTCMinutes().toString().padStart(2, '0');
    const ss = d.getUTCSeconds().toString().padStart(2, '0');
    const mo = (d.getUTCMonth() + 1).toString().padStart(2, '0');
    const dd = d.getUTCDate().toString().padStart(2, '0');

    if (_windowSecs <= 1800)  return `${hh}:${mm}:${ss}`;
    if (_windowSecs <= 86400) return `${hh}:${mm}`;
    return `${mo}/${dd} ${hh}:${mm}`;
  }

  function _draw(tsData) {
    const cv  = document.getElementById('chart-canvas');
    const ctx = cv.getContext('2d');
    const W = cv.width, H = cv.height;

    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = PALETTE.bg;
    ctx.fillRect(0, 0, W, H);

    if (!tsData || tsData.length === 0) {
      ctx.fillStyle = PALETTE.axis;
      ctx.font = '13px Helvetica';
      ctx.textAlign = 'center';
      ctx.fillText('No timeline data for this finding', W / 2, H / 2);
      return;
    }

    // Filter to selected window
    const allTs = tsData.map(r => r[0]);
    const tMax  = Math.max(...allTs);
    const tMin  = tMax - _windowSecs;
    const pts   = tsData.filter(r => r[0] >= tMin);

    if (pts.length === 0) {
      ctx.fillStyle = PALETTE.axis;
      ctx.font = '13px Helvetica';
      ctx.textAlign = 'center';
      ctx.fillText('No connections in selected window', W / 2, H / 2);
      return;
    }

    // Aim for ~24 buckets but scale to data density
    const numBuckets = Math.min(pts.length, 24);
    const bucketSec  = _windowSecs / numBuckets;

    const buckets = Array.from({length: numBuckets}, (_, i) => ({
      tStart:    tMin + i * bucketSec,
      origBytes: 0,
      respBytes: 0,
      count:     0,
    }));

    pts.forEach(r => {
      const idx = Math.min(Math.floor((r[0] - tMin) / bucketSec), numBuckets - 1);
      buckets[idx].origBytes += r[1];
      buckets[idx].respBytes += r[2];
      buckets[idx].count++;
    });

    const maxBytes = Math.max(...buckets.map(b => b.origBytes), 1);

    // Layout
    const PAD  = { top: 28, right: 16, bottom: 54, left: 72 };
    const plotW = W - PAD.left - PAD.right;
    const plotH = H - PAD.top  - PAD.bottom;
    const slotW = plotW / numBuckets;
    const barW  = Math.max(Math.floor(slotW * 0.7), 2);

    // Y-axis gridlines and byte labels
    const yTicks = 4;
    ctx.lineWidth = 1;
    for (let i = 0; i <= yTicks; i++) {
      const y = PAD.top + plotH - (i / yTicks) * plotH;
      ctx.strokeStyle = PALETTE.grid;
      ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(PAD.left + plotW, y); ctx.stroke();
      ctx.fillStyle = PALETTE.axis;
      ctx.font = '9px Helvetica';
      ctx.textAlign = 'right';
      ctx.fillText(_fmtBytes((i / yTicks) * maxBytes), PAD.left - 5, y + 3);
    }

    // Y-axis label (rotated)
    ctx.save();
    ctx.fillStyle = PALETTE.label;
    ctx.font = '10px Helvetica';
    ctx.textAlign = 'center';
    ctx.translate(10, PAD.top + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('Bytes Sent', 0, 0);
    ctx.restore();

    // Bars
    const labelEvery = Math.max(1, Math.ceil(numBuckets / 10));
    buckets.forEach((b, i) => {
      const x    = PAD.left + i * slotW;
      const cx   = x + slotW / 2;
      const barH = (b.origBytes / maxBytes) * plotH;
      const barY = PAD.top + plotH - barH;
      const barX = cx - barW / 2;

      // Alternating column background
      if (i % 2 === 0) {
        ctx.fillStyle = 'rgba(255,255,255,0.018)';
        ctx.fillRect(x, PAD.top, slotW, plotH);
      }

      // Bar
      if (b.origBytes > 0) {
        ctx.fillStyle = b.origBytes > b.respBytes ? PALETTE.barHi : PALETTE.bar;
        ctx.fillRect(barX, barY, barW, barH);

        // Byte label above bar (only if bar is tall enough)
        if (barH > 16) {
          ctx.fillStyle = 'rgba(255,255,255,0.75)';
          ctx.font = '8px Helvetica';
          ctx.textAlign = 'center';
          ctx.fillText(_fmtBytes(b.origBytes), cx, barY + 10);
        }
      }

      // X-axis time label (every Nth bucket, rotated slightly)
      if (i % labelEvery === 0) {
        ctx.fillStyle = PALETTE.label;
        ctx.font = '8px Helvetica';
        ctx.save();
        ctx.translate(cx, PAD.top + plotH + 10);
        ctx.rotate(Math.PI / 6);
        ctx.textAlign = 'left';
        ctx.fillText(_timeLabel(b.tStart), 0, 0);
        ctx.restore();
      }
    });

    // Axes
    ctx.strokeStyle = PALETTE.grid;
    ctx.lineWidth = 1;
    // X baseline
    ctx.beginPath();
    ctx.moveTo(PAD.left, PAD.top + plotH);
    ctx.lineTo(PAD.left + plotW, PAD.top + plotH);
    ctx.stroke();
    // Y axis
    ctx.beginPath();
    ctx.moveTo(PAD.left, PAD.top);
    ctx.lineTo(PAD.left, PAD.top + plotH);
    ctx.stroke();

    // X-axis label
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

  function show(finding) {
    _finding = finding;
    const dialog = document.getElementById('chart-dialog');
    document.getElementById('chart-title').textContent =
      `Beacon Data Volume — ${finding.src_ip} → ${finding.dst_ip || '?'}${finding.dst_port ? ':' + finding.dst_port : ''}`;
    document.querySelectorAll('.chart-preset-btn').forEach(b => {
      b.classList.toggle('active', parseInt(b.dataset.secs) === _windowSecs);
    });
    dialog.showModal();
    _draw(finding.ts_data || []);
  }

  function init() {
    document.querySelectorAll('.chart-preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        _windowSecs = parseInt(btn.dataset.secs);
        document.querySelectorAll('.chart-preset-btn').forEach(b =>
          b.classList.toggle('active', b === btn));
        if (_finding) _draw(_finding.ts_data || []);
      });
    });
    document.getElementById('chart-close').addEventListener('click', () => {
      document.getElementById('chart-dialog').close();
    });
  }

  return { init, show };
})();
