// feeds.js — TI-feed admin UI (Phase 7 slice 5b).
//
// Renders the list of configured MISP / OpenCTI feeds with status,
// indicator count, and last-refresh timestamp. Admin gestures:
// add a feed, edit, delete, enable/disable, and per-row manual refresh.
// Feed fetching also runs automatically at every full-pass watch tick;
// the per-row Refresh is the on-demand path admins use to verify a
// freshly configured feed without waiting for the next watch tick.

'use strict';

const Feeds = (() => {
  let _isAdmin = false;
  let _editingID = null; // null = creating, else editing this feed id

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

  function _fmtTS(ts) {
    if (!ts) return '—';
    return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  }

  function _statusPill(status) {
    const cls = {
      ok: 'sev-low',
      fetching: 'sev-medium',
      error: 'sev-critical',
      idle: 'sev-info',
    }[status] || 'sev-info';
    return `<span class="severity-pill ${cls}">${_esc(status || 'idle')}</span>`;
  }

  // ── render ────────────────────────────────────────────────────────────

  async function refresh() {
    let data;
    try {
      data = await _api('/api/feeds');
    } catch (e) {
      const tbody = document.getElementById('feeds-tbody');
      if (tbody) tbody.innerHTML = `<tr><td colspan="8" style="color:var(--fg-bad);text-align:center;padding:12px">Failed to load feeds: ${_esc(e.message)}</td></tr>`;
      return;
    }
    const tbody = document.getElementById('feeds-tbody');
    if (!tbody) return;
    const list = (data && data.feeds) || [];
    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="font-style:italic;color:var(--fg-dim);text-align:center;padding:12px">No feeds configured.</td></tr>';
      return;
    }
    tbody.innerHTML = list.map(f => {
      const statusCol = _statusPill(f.status);
      const enabledMark = f.enabled ? '' : ' <span style="color:var(--fg-dim);font-style:italic">(disabled)</span>';
      const lastErrTitle = f.last_error ? ` title="${_esc(f.last_error)}"` : '';
      const refreshDisabled = f.enabled ? '' : 'disabled';
      const adminCtrls = _isAdmin
        ? `<button class="dlg-btn secondary feeds-row-refresh" data-id="${f.id}" ${refreshDisabled}>Refresh</button>
           <button class="dlg-btn secondary feeds-row-edit" data-id="${f.id}">Edit</button>
           <button class="dlg-btn danger feeds-row-delete" data-id="${f.id}">Delete</button>`
        : '';
      return `<tr${lastErrTitle}>
        <td>${_esc(f.name)}${enabledMark}</td>
        <td>${_esc(f.source_type.toUpperCase())}</td>
        <td>${statusCol}</td>
        <td style="text-align:right">${(f.last_indicator_count || 0).toLocaleString()}</td>
        <td>${_fmtTS(f.last_refresh_at)}</td>
        <td>${_esc(f.refresh_cadence_minutes)} min</td>
        <td>${_esc(f.indicator_aging_days)} d</td>
        <td style="text-align:right">${adminCtrls}</td>
      </tr>`;
    }).join('');
  }

  // ── edit form ─────────────────────────────────────────────────────────

  function _openEditDialog(feed) {
    _editingID = feed ? feed.id : null;
    document.getElementById('feeds-edit-title').textContent = feed ? `Edit feed: ${feed.name}` : 'Add feed';
    document.getElementById('feeds-edit-source-type').value = feed ? feed.source_type : 'misp';
    document.getElementById('feeds-edit-name').value = feed ? feed.name : '';
    document.getElementById('feeds-edit-url').value = feed ? feed.url : '';
    document.getElementById('feeds-edit-apikey').value = '';
    document.getElementById('feeds-edit-keyhint').style.display = feed ? '' : 'none';
    document.getElementById('feeds-edit-cadence').value = feed ? feed.refresh_cadence_minutes : 60;
    document.getElementById('feeds-edit-aging').value = feed ? feed.indicator_aging_days : 30;
    document.getElementById('feeds-edit-enabled').checked = feed ? feed.enabled : true;
    document.getElementById('feeds-edit-tls-skip-verify').checked = feed ? !!feed.tls_skip_verify : false;
    const err = document.getElementById('feeds-edit-error');
    err.style.display = 'none';
    err.textContent = '';
    document.getElementById('feeds-edit-dlg').showModal();
  }

  async function _saveEdit() {
    const errEl = document.getElementById('feeds-edit-error');
    errEl.style.display = 'none';

    const body = {
      source_type:             document.getElementById('feeds-edit-source-type').value,
      name:                    document.getElementById('feeds-edit-name').value.trim(),
      url:                     document.getElementById('feeds-edit-url').value.trim(),
      api_key:                 document.getElementById('feeds-edit-apikey').value,
      refresh_cadence_minutes: parseInt(document.getElementById('feeds-edit-cadence').value, 10) || 0,
      indicator_aging_days:    parseInt(document.getElementById('feeds-edit-aging').value, 10) || 0,
      enabled:                 document.getElementById('feeds-edit-enabled').checked,
      tls_skip_verify:         document.getElementById('feeds-edit-tls-skip-verify').checked,
    };

    try {
      if (_editingID == null) {
        await _api('/api/feeds', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(body),
        });
      } else {
        await _api('/api/feeds/' + _editingID, {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(body),
        });
      }
      document.getElementById('feeds-edit-dlg').close();
      await refresh();
    } catch (e) {
      errEl.textContent = e.message || 'save failed';
      errEl.style.display = '';
    }
  }

  // ── row actions ───────────────────────────────────────────────────────

  async function _onRowClick(ev) {
    const t = ev.target;
    const id = t.dataset && t.dataset.id;
    if (!id) return;
    if (t.classList.contains('feeds-row-refresh')) {
      t.disabled = true;
      const orig = t.textContent;
      t.textContent = 'Refreshing…';
      try {
        const r = await _api('/api/feeds/' + id + '/refresh', {method: 'POST'});
        t.textContent = `+${r.indicators_added || 0} / ~${r.indicators_refreshed || 0}`;
        setTimeout(() => { t.textContent = orig; t.disabled = false; }, 2500);
      } catch (e) {
        t.textContent = 'failed';
        t.title = e.message;
        setTimeout(() => { t.textContent = orig; t.disabled = false; t.title = ''; }, 2500);
      }
      await refresh();
      return;
    }
    if (t.classList.contains('feeds-row-edit')) {
      try {
        const data = await _api('/api/feeds');
        const feed = (data.feeds || []).find(f => String(f.id) === String(id));
        if (!feed) return;
        _openEditDialog(feed);
      } catch (e) { /* swallow */ }
      return;
    }
    if (t.classList.contains('feeds-row-delete')) {
      if (!confirm('Delete this feed and all its indicators?')) return;
      try {
        await _api('/api/feeds/' + id, {method: 'DELETE'});
        await refresh();
      } catch (e) {
        alert('Delete failed: ' + e.message);
      }
    }
  }

  // ── init ──────────────────────────────────────────────────────────────

  function init(isAdmin) {
    _isAdmin = !!isAdmin;
    const btn = document.getElementById('feeds-btn');
    if (!btn) return;
    btn.style.display = '';

    if (_isAdmin) {
      const adminBar = document.getElementById('feeds-admin-bar');
      if (adminBar) adminBar.style.display = '';
    }

    const dlg = document.getElementById('feeds-dialog');
    btn.addEventListener('click', async () => {
      await refresh();
      dlg.showModal();
    });
    document.getElementById('feeds-close').addEventListener('click', () => dlg.close());

    const editDlg = document.getElementById('feeds-edit-dlg');
    const newBtn = document.getElementById('feeds-new-btn');
    if (newBtn) newBtn.addEventListener('click', () => _openEditDialog(null));
    document.getElementById('feeds-edit-cancel').addEventListener('click', () => editDlg.close());
    document.getElementById('feeds-edit-save').addEventListener('click', _saveEdit);

    document.getElementById('feeds-tbody').addEventListener('click', _onRowClick);
  }

  return { init, refresh };
})();
