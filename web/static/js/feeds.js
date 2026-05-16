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
  let _pollTimer = null; // setInterval handle for live-progress polling
  let _pollOn = false;

  function _api(url, opts) {
    return fetch(url, opts || {}).then(r => {
      if (!r.ok) {
        return r.json().catch(() => ({})).then(e => Promise.reject(new Error(e.error || r.statusText)));
      }
      const ct = r.headers.get('content-type') || '';
      return ct.includes('json') ? r.json() : r.text();
    });
  }

  // Canonical strong-_esc — see app.js for the convention notes and
  // the Go-side consistency test. NEW-30.
  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  // Short form for the table cell: "YYYY-MM-DD HH:MM" (no seconds,
  // no "UTC" suffix). Seconds aren't load-bearing for "when did this
  // last refresh" and they cost ~30px of column width on every row.
  // The full ISO timestamp surfaces via _fmtTSFull in the cell title.
  function _fmtTS(ts) {
    if (!ts) return '—';
    return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 16);
  }
  function _fmtTSFull(ts) {
    if (!ts) return 'never';
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
      tbody.innerHTML = '<tr><td colspan="7" style="font-style:italic;color:var(--fg-dim);text-align:center;padding:12px">No feeds configured.</td></tr>';
      return;
    }
    tbody.innerHTML = list.map(f => {
      const statusCol = _statusPill(f.status);
      const enabledMark = f.enabled ? '' : ' <span style="color:var(--fg-dim);font-style:italic">(disabled)</span>';
      const lastErrTitle = f.last_error ? ` title="${_esc(f.last_error)}"` : '';
      const adminCtrls = _isAdmin
        ? `<button class="row-kebab feeds-row-kebab" data-id="${f.id}" data-enabled="${f.enabled ? '1' : '0'}" title="Row actions" aria-label="Row actions">⋮</button>`
        : '';
      const isFetching = f.status === 'fetching';
      const liveCount = (f.live_indicator_count || 0).toLocaleString();
      const settledCount = (f.last_indicator_count || 0).toLocaleString();
      const count = isFetching
        ? `<span title="ingested so far this fetch — climbs while the import runs">${liveCount} <span style="color:var(--fg-dim);font-style:italic">ingesting…</span></span>`
        : settledCount;
      const truncBadge = f.last_fetch_truncated
        ? ` <span title="Last fetch hit the adapter's page-walk cap — upstream has more indicators than were pulled. Consider narrowing the upstream query." style="color:var(--sev-medium);font-weight:600">⚠ truncated</span>`
        : '';
      const lastFull = _fmtTSFull(f.last_full_refresh_at);
      const lastAnyFull = _fmtTSFull(f.last_refresh_at);
      const refreshTip = `Last refresh: ${lastAnyFull}\nLast full sync: ${lastFull}\nIncrementals between fulls only fetch attributes modified since the previous run.`;
      // Aging cell: "<N> d" plus a per-feed "% aged out" line so the
      // window is calibratable instead of blind. last_indicator_count
      // is the post-prune survivor count, so the pre-prune population
      // is pruned + survivors. Gated on aging enabled AND a full
      // refresh having happened — last_pruned_count is stale after an
      // incremental or with aging off, so showing it then would lie.
      const aging = f.indicator_aging_days || 0;
      let agingCell = `${_esc(aging)} d`;
      if (aging > 0 && f.last_full_refresh_at > 0) {
        const pruned = f.last_pruned_count || 0;
        const pre = pruned + (f.last_indicator_count || 0);
        let pctTxt;
        if (pre === 0) {
          pctTxt = '0% aged';
        } else {
          const pct = pruned / pre * 100;
          pctTxt = (pruned > 0 && pct < 0.1)
            ? '<0.1% aged'
            : `${pct.toFixed(pct < 10 ? 1 : 0)}% aged`;
        }
        const agingTip = `${pruned.toLocaleString()} of ${pre.toLocaleString()} indicators aged out at the last full refresh (last_seen older than ${aging} d). Widen the window if this is pruning indicators you still want; tighten it if it never prunes and the feed only grows.`;
        agingCell = `${_esc(aging)} d<div class="feed-aging-pct" title="${_esc(agingTip)}">${pctTxt}</div>`;
      }
      return `<tr${lastErrTitle}>
        <td title="${_esc(f.name)}">${_esc(f.name)}${enabledMark}</td>
        <td>${_esc(f.source_type.toUpperCase())}</td>
        <td>${statusCol}</td>
        <td>${count}${truncBadge}</td>
        <td title="${_esc(refreshTip)}">${_fmtTS(f.last_refresh_at)}</td>
        <td>${agingCell}</td>
        <td>${adminCtrls}</td>
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
    document.getElementById('feeds-edit-aging').value = feed ? feed.indicator_aging_days : 30;
    document.getElementById('feeds-edit-enabled').checked = feed ? feed.enabled : true;
    document.getElementById('feeds-edit-tls-skip-verify').checked = feed ? !!feed.tls_skip_verify : false;
    document.getElementById('feeds-edit-allow-internal').checked = feed ? !!feed.allow_internal : false;
    const err = document.getElementById('feeds-edit-error');
    err.style.display = 'none';
    err.textContent = '';
    document.getElementById('feeds-edit-dlg').showModal();
  }

  async function _saveEdit() {
    const errEl = document.getElementById('feeds-edit-error');
    errEl.style.display = 'none';

    const body = {
      source_type:          document.getElementById('feeds-edit-source-type').value,
      name:                 document.getElementById('feeds-edit-name').value.trim(),
      url:                  document.getElementById('feeds-edit-url').value.trim(),
      api_key:              document.getElementById('feeds-edit-apikey').value,
      indicator_aging_days: parseInt(document.getElementById('feeds-edit-aging').value, 10) || 0,
      enabled:              document.getElementById('feeds-edit-enabled').checked,
      tls_skip_verify:      document.getElementById('feeds-edit-tls-skip-verify').checked,
      allow_internal:       document.getElementById('feeds-edit-allow-internal').checked,
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

  async function _doRefresh(id) {
    try {
      await _api('/api/feeds/' + id + '/refresh', {method: 'POST'});
    } catch (e) {
      alert('Refresh failed: ' + e.message);
    }
    await refresh();
  }

  async function _doEdit(id) {
    try {
      const data = await _api('/api/feeds');
      const feed = (data.feeds || []).find(f => String(f.id) === String(id));
      if (!feed) return;
      _openEditDialog(feed);
    } catch (e) { /* swallow */ }
  }

  async function _doDelete(id) {
    if (!confirm('Delete this feed and all its indicators?')) return;
    try {
      await _api('/api/feeds/' + id, {method: 'DELETE'});
      await refresh();
    } catch (e) {
      alert('Delete failed: ' + e.message);
    }
  }

  function _onRowClick(ev) {
    const btn = ev.target.closest('button.feeds-row-kebab');
    if (!btn) return;
    const id = btn.dataset.id;
    if (!id) return;
    const enabled = btn.dataset.enabled === '1';
    const items = [
      enabled
        ? { label: 'Refresh', onClick: () => _doRefresh(id) }
        : { label: 'Refresh', disabled: true, hint: 'Enable the feed before refreshing' },
      { label: 'Edit',    onClick: () => _doEdit(id) },
      '---',
      { label: 'Delete',  danger: true, onClick: () => _doDelete(id) },
    ];
    RowMenu.open(btn, items);
  }

  // ── live-progress polling ─────────────────────────────────────────────

  function _startPoll() {
    if (_pollOn) return;
    _pollOn = true;
    _pollTimer = setInterval(() => {
      if (!_pollOn) return;
      refresh().catch(() => { /* swallow — next tick retries */ });
    }, 2500);
  }

  function _stopPoll() {
    _pollOn = false;
    if (_pollTimer) {
      clearInterval(_pollTimer);
      _pollTimer = null;
    }
  }

  // open is the public entry point used by both the Feeds button
  // click handler and the bell-notification jump dispatch for
  // Kind=feed alarms.
  async function open() {
    await refresh();
    const dlg = document.getElementById('feeds-dialog');
    if (dlg) dlg.showModal();
    _startPoll();
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
    btn.addEventListener('click', open);
    document.getElementById('feeds-close').addEventListener('click', () => {
      _stopPoll();
      dlg.close();
    });
    dlg.addEventListener('close', _stopPoll);

    const editDlg = document.getElementById('feeds-edit-dlg');
    const newBtn = document.getElementById('feeds-new-btn');
    if (newBtn) newBtn.addEventListener('click', () => _openEditDialog(null));
    document.getElementById('feeds-edit-cancel').addEventListener('click', () => editDlg.close());
    document.getElementById('feeds-edit-save').addEventListener('click', _saveEdit);

    document.getElementById('feeds-tbody').addEventListener('click', _onRowClick);
  }

  return { init, refresh, open };
})();
