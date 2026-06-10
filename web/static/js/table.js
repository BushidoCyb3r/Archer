// table.js — findings table renderer with virtual scrolling
//
// Only the rows currently in the viewport (plus a small buffer) are inserted
// into the DOM. Total scroll height is faked with a top/bottom spacer <tr>, so
// the scrollbar reflects the full dataset size. This removes the previous
// 1000-row cap — the table stays smooth at 50k+ rows.
'use strict';

const Table = (() => {
  let _findings = [];
  let _sorted   = [];
  let _sortCol  = 'score';
  let _sortDir  = -1; // -1=desc, 1=asc
  let _selected = null;
  let _onSelect    = null;
  let _onCtx       = null;

  // Row height is pinned in archer.css (#findings-tbody > tr:not([aria-hidden])
  // { height: 32px }). Using a constant here — and a CSS rule there — keeps
  // the spacer math identical to actual rendered geometry so we never drift
  // into a scroll/render feedback loop.
  const ROW_H     = 32;
  const BUFFER    = 8;     // rows of overscan above/below the visible window
  const COL_COUNT = 11;    // matches thead column count for spacer colspan
  let _lastStart = -1;     // remember last window so we can skip no-op renders
  let _lastEnd   = -1;
  let _skeleton  = false;  // true while shimmer rows are displayed; suppresses empty-state clear

  const SEV_ORDER = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};

  function _statusIcon(f) {
    // Precedence: analyst-action states (esc/ack) win because they show
    // triage progress. Otherwise the IOC diamond wins over the "new" dot —
    // an IOC hit is a persistent classification we want surfaced for the
    // lifetime of the finding. The "new" dot is is_new_to_me (detected since
    // this analyst last logged in), not the per-run is_new flag, so it agrees
    // with the "New only" filter and the new-findings modal.
    if (f.status === 'escalated')    return '<span class="si-esc">▲</span>';
    if (f.status === 'acknowledged') return '<span class="si-ack">✓</span>';
    if (f.ioc_match)    return '<span class="si-ioc">◆</span>';
    if (f.is_new_to_me) return '<span class="si-new">●</span>';
    return '';
  }

  function _statusLabel(s) {
    if (s === 'acknowledged') return 'ACK';
    if (s === 'escalated')    return 'ESC';
    return 'OPEN';
  }

  function _cmp(a, b) {
    let av = a[_sortCol], bv = b[_sortCol];
    if (_sortCol === 'severity') {
      av = SEV_ORDER[av] ?? 99;
      bv = SEV_ORDER[bv] ?? 99;
    }
    if (av == null && bv == null) return 0;
    if (av == null) return 1;
    if (bv == null) return -1;
    if (typeof av === 'string') return _sortDir * av.localeCompare(bv);
    return _sortDir * (av - bv);
  }

  // Rows are emitted as HTML strings rather than DOM nodes — the visible
  // window can swap on every scroll event, so building thousands of <tr>s
  // up-front and then discarding them is wasteful. Escape user-controlled
  // fields so log content can't break out of attribute values.
  //
  // Canonical strong-_esc — see app.js for the convention notes.
  // Pre-NEW-30 this copy escaped only & < > " (missing single quote).
  // Audit 2026-05-10 NEW-30.
  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  // Trim the Detail string for the table cell: keep whole pipe-delimited
  // segments up to a ~60-char budget so the cell always ends on a complete
  // clause — no mid-word cut, no trailing ellipsis. The full string lives in
  // the cell's title tooltip and the detail pane. If the lead segment alone
  // already exceeds the budget, fall back to a word-boundary trim.
  const _DETAIL_BUDGET = 60;
  function _trimDetail(s) {
    if (s.length <= _DETAIL_BUDGET) return s;
    let out = '';
    for (const seg of s.split('|').map(x => x.trim()).filter(Boolean)) {
      const next = out ? out + ' | ' + seg : seg;
      if (next.length > _DETAIL_BUDGET) break;
      out = next;
    }
    if (out) return out;
    const head = s.slice(0, _DETAIL_BUDGET);
    const sp = head.lastIndexOf(' ');
    return sp > 0 ? head.slice(0, sp) : head;
  }

  function _rowHTML(f, isSel) {
    const detailRaw = f.detail || '';
    const detail = _trimDetail(detailRaw);
    const sev = f.severity || '';
    const cls = sev + (isSel ? ' selected' : '');
    // TLS-allowlist chip — this finding's JA3/JA4 client fingerprint has been
    // marked benign on the TLS Fingerprints wall. A hint, not a filter: the
    // finding still shows, but the analyst is told its fingerprint was triaged.
    const fpChip = f.tls_allowlisted
      ? ' <span class="fp-allow-chip" title="' +
          _esc("This finding's TLS client fingerprint was marked benign on the TLS Fingerprints wall.") +
          '">fp benign</span>'
      : '';
    return '<tr class="' + cls + '" data-id="' + f.id + '">' +
      '<td class="status-icon">' + _statusIcon(f) + '</td>' +
      '<td class="score">' + _esc(f.score) + '</td>' +
      '<td class="severity">' + _esc(sev) + '</td>' +
      '<td title="' + _esc(f.type) + '">' + _esc(f.type) + fpChip + '</td>' +
      '<td class="src-ip" title="' + _esc(f.src_ip) + '" style="font-family:monospace">' + _esc(f.src_ip) + '</td>' +
      '<td class="dst-ip" title="' + _esc(f.dst_ip) + '" style="font-family:monospace">' + _esc(f.dst_ip) + '</td>' +
      '<td class="port">' + _esc(f.dst_port) + '</td>' +
      '<td title="' + _esc(f.timestamp) + '">' + _esc((f.timestamp || '').slice(0, 16)) + '</td>' +
      '<td>' + _statusLabel(f.status) + '</td>' +
      '<td style="color:var(--fg-dim)" title="' + _esc(f.sensor) + '">' + _esc(f.sensor) + '</td>' +
      '<td title="' + _esc(detailRaw) + '" style="color:var(--fg-dim)">' + _esc(detail) + '</td>' +
      '</tr>';
  }

  function _spacer(px) {
    return '<tr aria-hidden="true"><td colspan="' + COL_COUNT +
      '" style="height:' + px + 'px;padding:0;border:0;background:transparent"></td></tr>';
  }

  // Compute which rows are currently visible from scrollTop and rebuild only
  // those rows. Top/bottom spacer <tr>s preserve the scrollbar size.
  function _renderWindow() {
    const tbody = document.getElementById('findings-tbody');
    if (!tbody) return;
    const wrap = tbody.closest('.table-wrap');
    if (!wrap) return;

    const total = _sorted.length;
    if (total === 0) {
      if (_skeleton) return;
      tbody.innerHTML = '';
      _lastStart = _lastEnd = -1;
      return;
    }

    const viewportH = wrap.clientHeight || 600;
    const scrollTop = wrap.scrollTop;
    const visCount  = Math.ceil(viewportH / ROW_H);
    const start = Math.max(0, Math.floor(scrollTop / ROW_H) - BUFFER);
    const end   = Math.min(total, start + visCount + BUFFER * 2);

    // Bail if the visible window hasn't shifted — keeps a scroll/layout
    // feedback loop from re-rendering identical content every frame.
    if (start === _lastStart && end === _lastEnd) return;
    _lastStart = start;
    _lastEnd   = end;

    const topPad = start * ROW_H;
    const botPad = (total - end) * ROW_H;

    const selId = _selected ? _selected.id : null;
    const parts = [];
    if (topPad > 0) parts.push(_spacer(topPad));
    for (let i = start; i < end; i++) {
      const f = _sorted[i];
      parts.push(_rowHTML(f, f.id === selId));
    }
    if (botPad > 0) parts.push(_spacer(botPad));
    tbody.innerHTML = parts.join('');
  }

  function _render() {
    _sorted = [..._findings].sort(_cmp);
    // Reset the window cache so _renderWindow definitely runs (sort/load
    // changes the underlying data even if start/end happen to match).
    _lastStart = _lastEnd = -1;
    _renderWindow();
    document.getElementById('findings-count').textContent =
      `${_sorted.length} finding${_sorted.length !== 1 ? 's' : ''}`;
  }

  function _select(f) {
    _selected = f;
    if (_onSelect) _onSelect(f);
    document.querySelectorAll('#findings-tbody tr').forEach(tr => {
      const id = parseInt(tr.dataset.id, 10);
      tr.classList.toggle('selected', !isNaN(id) && id === f.id);
    });
  }

  function _findById(id) {
    return _findings.find(f => f.id === id);
  }

  // Event delegation — one click + one contextmenu listener on tbody rather
  // than per-row handlers. Rows are recycled on every scroll, so per-row
  // listeners would have to be re-attached constantly.
  function _onTbodyClick(e) {
    const tr = e.target.closest('tr[data-id]');
    if (!tr) return;
    const id = parseInt(tr.dataset.id, 10);
    const f = _findById(id);
    if (!f) return;
    _select(f);
  }

  function _onTbodyCtx(e) {
    const tr = e.target.closest('tr[data-id]');
    if (!tr) return;
    e.preventDefault();
    const id = parseInt(tr.dataset.id, 10);
    const f = _findById(id);
    if (f) {
      _select(f);
      if (_onCtx) _onCtx(e, f);
    }
  }

  function _sortBy(col) {
    if (_sortCol === col) _sortDir *= -1;
    else { _sortCol = col; _sortDir = -1; }
    _updateSortHeaders();
    // After a sort, the user expects to see the new top of the list — keeping
    // their previous scrollTop would land them in arbitrary middle data.
    const tbody = document.getElementById('findings-tbody');
    const wrap  = tbody && tbody.closest('.table-wrap');
    if (wrap) wrap.scrollTop = 0;
    _render();
  }

  function _updateSortHeaders() {
    document.querySelectorAll('#findings-table thead th[data-col]').forEach(th => {
      th.classList.remove('sort-asc', 'sort-desc');
      if (th.dataset.col === _sortCol) {
        th.classList.add(_sortDir === 1 ? 'sort-asc' : 'sort-desc');
      }
    });
  }

  function load(findings, opts) {
    _skeleton = false;
    _findings = findings || [];
    const tbody = document.getElementById('findings-tbody');
    const wrap  = tbody && tbody.closest('.table-wrap');
    // Default: reset scroll on load — fresh data should land the analyst
    // at the top. opts.preserveScroll skips that reset, used by the
    // in-place reload path so analysts stay where they were reading.
    if (wrap && !(opts && opts.preserveScroll)) wrap.scrollTop = 0;
    _render();
  }

  function flash(id) {
    const tr = document.querySelector('#findings-tbody tr[data-id="' + id + '"]');
    if (!tr) return;
    tr.classList.remove('flash-new');
    void tr.offsetWidth;
    tr.classList.add('flash-new');
    tr.addEventListener('animationend', () => tr.classList.remove('flash-new'), { once: true });
  }

  function update(finding) {
    const idx = _findings.findIndex(f => f.id === finding.id);
    if (idx >= 0) _findings[idx] = finding;
    if (_selected && _selected.id === finding.id) _selected = finding;
    _render();
  }

  function getSelected() { return _selected; }

  function showSkeleton(n) {
    const tbody = document.getElementById('findings-tbody');
    if (!tbody) return;
    _findings = [];
    _sorted = [];
    _skeleton = true;
    _lastStart = _lastEnd = -1;
    const parts = [];
    for (let i = 0; i < (n || 10); i++) {
      parts.push('<tr class="skel-row" aria-hidden="true"><td colspan="' + COL_COUNT +
        '"><span class="skel-bar" style="width:' + (55 + ((i * 17) % 40)) + '%"></span></td></tr>');
    }
    tbody.innerHTML = parts.join('');
  }

  function clearSkeleton() {
    if (!_skeleton) return;
    const tbody = document.getElementById('findings-tbody');
    _skeleton = false;
    if (tbody) tbody.innerHTML = '';
    _lastStart = _lastEnd = -1;
  }

  function jumpTo(id) {
    const idx = _sorted.findIndex(f => f.id === id);
    if (idx < 0) return;
    const f = _sorted[idx];
    const tbody = document.getElementById('findings-tbody');
    const wrap  = tbody && tbody.closest('.table-wrap');
    if (!wrap) { _select(f); return; }
    // Centre the target row in the viewport when possible.
    const target = idx * ROW_H - wrap.clientHeight / 2 + ROW_H / 2;
    wrap.scrollTop = Math.max(0, target);
    _renderWindow();
    _select(f);
  }

  function _navigateBy(delta) {
    if (!_selected || _sorted.length === 0) return;
    const idx = _sorted.findIndex(f => f.id === _selected.id);
    if (idx < 0) return;
    const next = _sorted[idx + delta];
    if (!next) return;
    jumpTo(next.id);
  }

  function init(onSelect, onCtx) {
    _onSelect   = onSelect;
    _onCtx      = onCtx;
    document.querySelectorAll('#findings-table thead th[data-col]').forEach(th => {
      th.addEventListener('click', () => _sortBy(th.dataset.col));
    });
    _updateSortHeaders();

    const tbody = document.getElementById('findings-tbody');
    if (tbody) {
      tbody.addEventListener('click',       _onTbodyClick);
      tbody.addEventListener('contextmenu', _onTbodyCtx);
      // One rAF gate covers both scroll and resize. Re-renders are idempotent
      // once the visible window settles (the _lastStart/_lastEnd guard in
      // _renderWindow returns early), so coalescing keeps us at one render
      // per animation frame regardless of how many events fire.
      let raf = 0;
      const schedule = () => {
        if (raf) return;
        raf = requestAnimationFrame(() => { raf = 0; _renderWindow(); });
      };
      const wrap = tbody.closest('.table-wrap');
      if (wrap) wrap.addEventListener('scroll', schedule, {passive: true});
      window.addEventListener('resize', schedule);
    }

    document.addEventListener('keydown', e => {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const t = e.target;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
      if (e.key === 'ArrowUp')   { e.preventDefault(); _navigateBy(-1); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); _navigateBy(1); }
    });
  }

  return { init, load, update, jumpTo, getSelected, flash, showSkeleton, clearSkeleton };
})();
