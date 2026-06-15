// fingerprints.js — the TLS Fingerprints modal.
//
// A fingerprint-first hunt surface: lists the high-signal JA3/JA4 client
// fingerprints from the latest analysis pass (known C2 matches plus rare/
// cross-host shapes), ranked by severity. Clicking a row hands the fingerprint
// back to app.js, which pivots the Findings tab to every finding carrying it —
// the same path the per-finding "TLS Pivot" button uses. Opened from the
// filter-bar "TLS Fingerprints" button; read-only, no auto-polling.

'use strict';

const Fingerprints = (() => {
  // app.js owns the pivot (pivotByTLS lives inside its IIFE), so it injects a
  // callback at init time rather than us reaching into its private scope.
  let _onPivot = null;
  let _onToast = null;
  let _onChange = null;
  let _canWrite = true;
  // Set when a benign mark/unmark mutates the allowlist while the modal is open.
  // The findings table behind the modal caches each row's tls_allowlisted at
  // fetch time, so the "FP Benign" chip is stale until it re-fetches; we fire
  // _onChange on close (once, if dirty) to let app.js reload the table in place.
  let _dirty = false;
  // Last-fetched data + the active search term, so filtering re-renders from
  // memory without refetching. _filter is lowercased.
  let _rows = [];
  let _benign = [];
  let _filter = '';

  // _concernText is the human-readable concern string for a wall row, shared by
  // the renderer and the search filter so they agree on what's searchable.
  function _concernText(r) {
    return r.known_bad
      ? ('Known C2' + (r.label ? ': ' + r.label : ''))
      : (r.detail || '');
  }

  // Module-local fetch wrapper — app.js's api() is IIFE-private. Canonical
  // body shared with the other SPA modules (pinned by a Go consistency test).
  function _api(url, opts) {
    return fetch(url, opts || {}).then(r => {
      if (!r.ok) {
        return r.json().catch(() => ({})).then(e => Promise.reject(new Error(e.error || r.statusText)));
      }
      const ct = r.headers.get('content-type') || '';
      return ct.includes('json') ? r.json() : r.text();
    });
  }

  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function _render(rows) {
    const tbody = document.getElementById('fingerprints-tbody');
    const empty = document.getElementById('fingerprints-empty');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!rows || !rows.length) {
      if (empty) empty.style.display = '';
      return;
    }
    if (empty) empty.style.display = 'none';
    rows.forEach(r => {
      const tr = document.createElement('tr');
      // Uppercase level class drives the findings-table severity colouring
      // (left bar + .severity cell colour) that already lives in archer.css.
      const sev = String(r.level || '').toUpperCase();
      tr.className = 'fp-row ' + sev;
      tr.dataset.kind = r.kind;
      tr.dataset.fp = r.fingerprint;
      const concern = _concernText(r);
      // Known-C2 rows are non-markable — analysts must not be able to mute a
      // confirmed C2 fingerprint off the wall (the server rejects it too), and
      // it's already malicious so there's nothing to add. Markable rows get
      // both actions: promote to the IOC list, or hide as benign.
      const action = (r.known_bad || !_canWrite)
        ? ''
        : `<button class="dlg-btn secondary fp-benign-btn" type="button" title="Mark this fingerprint benign and hide it from the list">Benign</button>` +
          `<button class="dlg-btn secondary fp-malicious-btn" type="button" title="Add this fingerprint to the IOC list — it flags as Malicious JA3/JA4 on the next analysis">Malicious</button>`;
      tr.innerHTML =
        `<td class="severity">${_esc(sev)}</td>` +
        `<td>${r.kind === 'ja4' ? 'JA4' : 'JA3'}</td>` +
        `<td class="fp-hash" title="${_esc(r.fingerprint)}">${_esc(r.fingerprint)}</td>` +
        `<td class="fp-concern" title="${_esc(concern)}">${_esc(concern)}</td>` +
        `<td>${r.src_hosts}</td>` +
        `<td>${r.dsts}</td>` +
        `<td>${r.conns}</td>` +
        `<td>${r.finding_count}</td>` +
        `<td class="fp-action">${action}</td>`;
      tbody.appendChild(tr);
    });
  }

  function _renderBenign(entries) {
    const wrap = document.getElementById('fingerprints-benign');
    const tbody = document.getElementById('fingerprints-benign-tbody');
    const count = document.getElementById('fingerprints-benign-count');
    if (!wrap || !tbody) return;
    tbody.innerHTML = '';
    if (count) count.textContent = entries.length;
    if (!entries.length) {
      wrap.style.display = 'none';
      return;
    }
    wrap.style.display = '';
    entries.forEach(e => {
      const tr = document.createElement('tr');
      tr.dataset.id = e.id;
      tr.innerHTML =
        `<td>${e.kind === 'ja4' ? 'JA4' : 'JA3'}</td>` +
        `<td class="fp-hash" title="${_esc(e.fingerprint)}">${_esc(e.fingerprint)}</td>` +
        `<td class="fp-concern" title="${_esc(e.note)}">${_esc(e.note || '')}</td>` +
        `<td class="fp-action">${_canWrite ? '<button class="dlg-btn secondary fp-unbenign-btn" type="button" title="Restore this fingerprint to the list">Unmark</button>' : ''}</td>`;
      tbody.appendChild(tr);
    });
  }

  async function _markBenign(kind, fp) {
    try {
      await _api('/api/fingerprint-allowlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kind, fingerprint: fp, note: '' }),
      });
    } catch (err) {
      if (_onToast) _onToast('Could not mark benign: ' + err.message);
      return;
    }
    _dirty = true;
    await _reload();
  }

  async function _markMalicious(kind, fp) {
    try {
      await _api('/api/ioc-fingerprint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint: fp }),
      });
    } catch (err) {
      if (_onToast) _onToast('Could not mark malicious: ' + err.message);
      return;
    }
    if (_onToast) _onToast('Added to IOC list — flags as malicious on the next analysis', 'err');
    await _reload();
  }

  async function _unmarkBenign(id) {
    try {
      await _api('/api/fingerprint-allowlist/' + encodeURIComponent(id), { method: 'DELETE' });
    } catch (err) {
      if (_onToast) _onToast('Could not unmark: ' + err.message);
      return;
    }
    _dirty = true;
    await _reload();
  }

  function _onRowClick(e) {
    const maliciousBtn = e.target.closest('.fp-malicious-btn');
    if (maliciousBtn) {
      const tr = e.target.closest('tr.fp-row');
      if (tr) _markMalicious(tr.dataset.kind, tr.dataset.fp);
      return;
    }
    const benignBtn = e.target.closest('.fp-benign-btn');
    if (benignBtn) {
      const tr = e.target.closest('tr.fp-row');
      if (tr) _markBenign(tr.dataset.kind, tr.dataset.fp);
      return;
    }
    const tr = e.target.closest('tr.fp-row');
    if (!tr) return;
    const kind = tr.dataset.kind;
    const fp = tr.dataset.fp;
    const dlg = document.getElementById('fingerprints-dialog');
    if (dlg) dlg.close();
    if (_onPivot) _onPivot(kind, fp);
  }

  function _onBenignClick(e) {
    const btn = e.target.closest('.fp-unbenign-btn');
    if (!btn) return;
    const tr = e.target.closest('tr[data-id]');
    if (tr) _unmarkBenign(tr.dataset.id);
  }

  // _applyFilter re-renders the wall + benign list from the cached data,
  // narrowed to rows whose fingerprint / type / concern (or, for benign, the
  // note) contains the current search term. Re-rendering from memory keeps
  // typing responsive — no refetch per keystroke.
  function _applyFilter() {
    const q = _filter;
    const rows = q
      ? _rows.filter(r =>
          (r.fingerprint + ' ' + (r.kind === 'ja4' ? 'ja4' : 'ja3') + ' ' + _concernText(r))
            .toLowerCase().includes(q))
      : _rows;
    const benign = q
      ? _benign.filter(e =>
          (e.fingerprint + ' ' + (e.kind === 'ja4' ? 'ja4' : 'ja3') + ' ' + (e.note || ''))
            .toLowerCase().includes(q))
      : _benign;
    // Distinguish "no fingerprints at all" from "no search matches" so the
    // empty-state text doesn't wrongly tell the analyst to run an analysis.
    const empty = document.getElementById('fingerprints-empty');
    if (empty) {
      empty.textContent = (q && _rows.length)
        ? 'No fingerprints match your search.'
        : 'No high-signal TLS fingerprints — run an analysis.';
    }
    _render(rows);
    _renderBenign(benign);
  }

  async function _reload() {
    try {
      _rows = await _api('/api/fingerprints') || [];
    } catch (_) {
      _rows = [];
    }
    try {
      _benign = await _api('/api/fingerprint-allowlist') || [];
    } catch (_) {
      _benign = [];
    }
    _applyFilter();
  }

  async function open() {
    // Fresh search each time the modal opens.
    _filter = '';
    _dirty = false;
    const search = document.getElementById('fingerprints-search');
    if (search) search.value = '';
    await _reload();
    const dlg = document.getElementById('fingerprints-dialog');
    if (dlg) dlg.showModal();
  }

  function init(opts) {
    _onPivot = (opts && opts.onPivot) || null;
    _onToast = (opts && opts.onToast) || null;
    _onChange = (opts && opts.onChange) || null;
    _canWrite = !opts || opts.canWrite !== false;
    const btn = document.getElementById('fingerprints-btn');
    if (!btn) return;
    btn.addEventListener('click', open);
    const dlg = document.getElementById('fingerprints-dialog');
    // Refresh the findings table once on close if any benign mark/unmark
    // landed — covers the close button, Escape, and backdrop dismissal alike.
    if (dlg) {
      dlg.addEventListener('close', () => {
        if (_dirty && _onChange) _onChange();
        _dirty = false;
      });
    }
    const closeBtn = document.getElementById('fingerprints-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        if (dlg) dlg.close();
      });
    }
    const tbody = document.getElementById('fingerprints-tbody');
    if (tbody) tbody.addEventListener('click', _onRowClick);
    const benignTbody = document.getElementById('fingerprints-benign-tbody');
    if (benignTbody) benignTbody.addEventListener('click', _onBenignClick);
    const search = document.getElementById('fingerprints-search');
    if (search) {
      search.addEventListener('input', () => {
        _filter = search.value.trim().toLowerCase();
        _applyFilter();
      });
    }
  }

  return { init, open };
})();
