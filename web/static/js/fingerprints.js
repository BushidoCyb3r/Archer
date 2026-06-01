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
      const concern = r.known_bad
        ? ('Known C2' + (r.label ? ': ' + r.label : ''))
        : (r.detail || '');
      tr.innerHTML =
        `<td class="severity">${_esc(sev)}</td>` +
        `<td>${r.kind === 'ja4' ? 'JA4' : 'JA3'}</td>` +
        `<td class="fp-hash" title="${_esc(r.fingerprint)}">${_esc(r.fingerprint)}</td>` +
        `<td class="fp-concern" title="${_esc(concern)}">${_esc(concern)}</td>` +
        `<td>${r.src_hosts}</td>` +
        `<td>${r.dsts}</td>` +
        `<td>${r.conns}</td>` +
        `<td>${r.finding_count}</td>`;
      tbody.appendChild(tr);
    });
  }

  function _onRowClick(e) {
    const tr = e.target.closest('tr.fp-row');
    if (!tr) return;
    const kind = tr.dataset.kind;
    const fp = tr.dataset.fp;
    const dlg = document.getElementById('fingerprints-dialog');
    if (dlg) dlg.close();
    if (_onPivot) _onPivot(kind, fp);
  }

  async function open() {
    let rows = [];
    try {
      rows = await _api('/api/fingerprints');
    } catch (_) {
      rows = [];
    }
    _render(rows);
    const dlg = document.getElementById('fingerprints-dialog');
    if (dlg) dlg.showModal();
  }

  function init(opts) {
    _onPivot = (opts && opts.onPivot) || null;
    const btn = document.getElementById('fingerprints-btn');
    if (!btn) return;
    btn.addEventListener('click', open);
    const closeBtn = document.getElementById('fingerprints-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        const dlg = document.getElementById('fingerprints-dialog');
        if (dlg) dlg.close();
      });
    }
    const tbody = document.getElementById('fingerprints-tbody');
    if (tbody) tbody.addEventListener('click', _onRowClick);
  }

  return { init, open };
})();
