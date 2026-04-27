// table.js — findings table renderer and sorting
'use strict';

const Table = (() => {
  let _findings = [];
  let _sortCol = 'score';
  let _sortDir = -1; // -1=desc, 1=asc
  let _selected = null;
  let _onSelect = null;
  let _onCtx = null;

  const SEV_ORDER = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};

  function _statusIcon(f) {
    // Precedence: analyst-action states (esc/ack) win because they show
    // triage progress. Otherwise IOC match wins over "new" — an IOC hit is
    // a persistent classification we want surfaced for the lifetime of the
    // finding, not just on the first analysis run that produced it.
    if (f.status === 'escalated')    return '<span class="si-esc">▲</span>';
    if (f.status === 'acknowledged') return '<span class="si-ack">✓</span>';
    if (f.ioc_match) return '<span class="si-ioc">◆</span>';
    if (f.is_new)    return '<span class="si-new">●</span>';
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

  const ROW_CAP = 1000;

  function _render() {
    const tbody  = document.getElementById('findings-tbody');
    const sorted = [..._findings].sort(_cmp);
    const capped = sorted.length > ROW_CAP;
    const visible = capped ? sorted.slice(0, ROW_CAP) : sorted;

    const frag = document.createDocumentFragment();
    visible.forEach(f => {
      const tr = document.createElement('tr');
      tr.className = f.severity || '';
      tr.dataset.id = f.id;
      if (_selected && f.id === _selected.id) tr.classList.add('selected');
      const detail = (f.detail || '').slice(0, 60) + ((f.detail || '').length > 60 ? '…' : '');
      tr.innerHTML = `
        <td class="status-icon">${_statusIcon(f)}</td>
        <td class="score">${f.score}</td>
        <td class="severity">${f.severity || ''}</td>
        <td title="${f.type || ''}">${f.type || ''}</td>
        <td title="${f.src_ip || ''}" style="font-family:monospace;font-size:11px">${f.src_ip || ''}</td>
        <td title="${f.dst_ip || ''}" style="font-family:monospace;font-size:11px">${f.dst_ip || ''}</td>
        <td class="port">${f.dst_port || ''}</td>
        <td title="${f.timestamp || ''}">${(f.timestamp || '').slice(0, 16)}</td>
        <td>${_statusLabel(f.status)}</td>
        <td style="font-size:11px;color:var(--fg-dim)" title="${f.dataset || ''}">${f.dataset || ''}</td>
        <td title="${f.detail || ''}" style="color:var(--fg-dim);font-size:11px">${detail}</td>`;
      tr.addEventListener('click', () => _select(f));
      tr.addEventListener('contextmenu', e => {
        e.preventDefault();
        _select(f);
        if (_onCtx) _onCtx(e, f);
      });
      frag.appendChild(tr);
    });

    if (capped) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="11" style="text-align:center;color:var(--fg-dim);padding:6px;font-style:italic">… ${sorted.length - ROW_CAP} more — use filters to narrow results</td>`;
      frag.appendChild(tr);
    }

    tbody.innerHTML = '';
    tbody.appendChild(frag);

    document.getElementById('findings-count').textContent =
      `${sorted.length} finding${sorted.length !== 1 ? 's' : ''}`;
  }

  function _select(f) {
    _selected = f;
    if (_onSelect) _onSelect(f);
    document.querySelectorAll('#findings-tbody tr').forEach(tr => {
      tr.classList.toggle('selected', parseInt(tr.dataset.id, 10) === f.id);
    });
  }

  function _sortBy(col) {
    if (_sortCol === col) _sortDir *= -1;
    else { _sortCol = col; _sortDir = -1; }
    _updateSortHeaders();
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

  function load(findings) {
    _findings = findings || [];
    _render();
  }

  function update(finding) {
    const idx = _findings.findIndex(f => f.id === finding.id);
    if (idx >= 0) _findings[idx] = finding;
    if (_selected && _selected.id === finding.id) _selected = finding;
    _render();
  }

  function getSelected() { return _selected; }

  function jumpTo(id) {
    const f = _findings.find(f => f.id === id);
    if (f) {
      _select(f);
      // Scroll into view
      const tr = document.querySelector(`#findings-tbody tr[data-id="${id}"]`);
      if (tr) tr.scrollIntoView({block: 'nearest'});
    }
  }

  function init(onSelect, onCtx) {
    _onSelect = onSelect;
    _onCtx = onCtx;
    document.querySelectorAll('#findings-table thead th[data-col]').forEach(th => {
      th.addEventListener('click', () => _sortBy(th.dataset.col));
    });
    _updateSortHeaders();
  }

  function populateTypeFilter(findings) {
    const types = [...new Set((findings || []).map(f => f.type).filter(Boolean))].sort();
    const sel = document.getElementById('filter-type');
    const cur = sel.value;
    sel.innerHTML = '<option value="">All Types</option>';
    types.forEach(t => {
      const opt = document.createElement('option');
      opt.value = t; opt.textContent = t;
      if (t === cur) opt.selected = true;
      sel.appendChild(opt);
    });
  }

  return { init, load, update, jumpTo, getSelected, populateTypeFilter };
})();
