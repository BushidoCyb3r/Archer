// sensors.js — Quiver sensor management UI.
//
// Renders three tables in a single modal: enrolled sensors, outstanding
// enrollment tokens, and unauthorized checkin attempts. Admin actions
// (enroll, disenroll, purge, revoke, dismiss) are gated by role; the
// modal is otherwise visible to admins and analysts. Refreshes are
// triggered on open and after every action — no auto-polling, since
// the user veto on heartbeat-style traffic extends to the UI too.

'use strict';

const Sensors = (() => {
  let _isAdmin = false;
  let _info = null; // {tls_fingerprint, sensor_facing_host, effective_host}
  let _diskBySensor = {}; // populated from /api/disk-usage; {<name>: bytes}

  // ── helpers ───────────────────────────────────────────────────────────

  // Module-local fetch wrapper. app.js's api() lives inside its IIFE so
  // we can't reach it from here; re-implementing the failure shape keeps
  // the two callers independent and avoids breaking sensors when app.js
  // tweaks its own wrapper.
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

  // Time format matches the Feeds modal: short "YYYY-MM-DD HH:MM" in
  // the cell, full "YYYY-MM-DD HH:MM:SS UTC" in the cell's title for
  // hover. Both UTC — analyst-local timezone was previously honoured
  // for the Last seen column via watch config, but mixed-basis cells
  // (UTC tooltips on a local cell) made hover ambiguous, so the whole
  // modal renders UTC now.
  function _fmtTS(ts) {
    if (!ts) return '—';
    return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 16);
  }
  function _fmtTSFull(ts) {
    if (!ts) return 'never';
    return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  }

  // _fmtSlotLocal renders the hourly push slot. Under hourly mode the
  // slot is just a minute-of-hour and timezone-independent (every hour
  // at :MM is the same in every timezone), so we show ":MM hourly" to
  // make the cadence explicit without picking a timezone.
  function _fmtSlotLocal(_h, m) {
    const mm = String(m || 0).padStart(2, '0');
    return `:${mm} hourly`;
  }

  // _slotHealth classifies whether the sensor hit its most recent
  // hourly slot. Under hourly mode the cadence is simple: a healthy
  // sensor checks in at least once per hour. Anything past 1h + 30min
  // grace without a checkin is "missed."
  //   ✓ on time — last_seen_at within the last hour
  //   pending   — within grace window of the most recent slot tick
  //   ⚠ missed  — > 1h + grace since last checkin
  //   never     — sensor has never been seen
  // Disenrolled / disenrolling sensors return em-dash.
  function _slotHealth(sn, nowEpoch) {
    if (sn.status !== 'enrolled') return '<span style="color:var(--fg-dim)">—</span>';
    if (!sn.last_seen_at) return '<span style="color:var(--fg-dim);font-size:11px">never</span>';
    const ageSec = nowEpoch - sn.last_seen_at;
    const grace = 1800; // 30 minutes
    if (ageSec <= 3600) {
      return '<span style="color:var(--sev-low);font-size:11px;font-weight:600">✓ on time</span>';
    }
    if (ageSec <= 3600 + grace) {
      return '<span style="color:var(--fg-dim);font-size:11px">pending</span>';
    }
    return '<span style="color:var(--sev-medium);font-size:11px;font-weight:600">⚠ missed</span>';
  }

  function _statusBadge(status) {
    const colors = {
      enrolled:    'var(--accent)',
      disenrolling:'var(--sev-medium)',
      disenrolled: 'var(--fg-dim)',
    };
    return `<span style="color:${colors[status] || 'var(--fg-dim)'};font-size:11px">${_esc(status)}</span>`;
  }

  // Build the install one-liner. We trust the server to tell us the right
  // fingerprint and host; port defaults to 8443 (the docker-compose
  // mapping) when the host doesn't already carry one.
  function _oneLiner(token, info) {
    const fp = info && info.tls_fingerprint ? info.tls_fingerprint : '';
    const adminHost = info && info.sensor_facing_host;
    const effective = info && info.effective_host;
    let host = adminHost || effective || window.location.host;
    // If the URL we used to reach Archer has a port that isn't 8443
    // (typical when admin browses on plain HTTP at :8080), strip it
    // and use the Quiver port instead. An admin-set override that
    // already specifies a port is left alone.
    if (!adminHost && /:\d+$/.test(host)) host = host.replace(/:\d+$/, '');
    if (!/:\d+$/.test(host)) host = host + ':8443';
    return `sudo curl -fsSL -k --pinnedpubkey "sha256//${fp}" https://${host}/quiver/install.sh | sudo bash -s -- ${token}`;
  }

  async function _loadInfo() {
    if (!_isAdmin) { _info = null; return; }
    try { _info = await _api('/api/sensors/info'); } catch (e) { _info = null; }
  }

  // _loadDiskUsage pulls per-sensor sizes from the server-side disk-usage
  // cache so the Sensors modal can render a Size column without each row
  // running its own walk. Failures fall through to an empty map; cells
  // render as "—".
  async function _loadDiskUsage() {
    try {
      const d = await _api('/api/disk-usage');
      const map = {};
      if (d && Array.isArray(d.by_sensor)) {
        d.by_sensor.forEach(s => { if (s && s.name) map[s.name] = s.bytes || 0; });
      }
      _diskBySensor = map;
    } catch (e) { _diskBySensor = {}; }
  }

  // _humanBytes — local copy so this module doesn't depend on app.js's.
  function _humanBytes(n) {
    if (!n) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0, v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
  }

  // ── render ────────────────────────────────────────────────────────────

  function _renderSensors(sensors) {
    const tbody = document.getElementById('sensors-tbody');
    if (!tbody) return;
    if (!sensors || sensors.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="font-style:italic;color:var(--fg-dim);text-align:center;padding:12px">No sensors enrolled yet.</td></tr>';
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    tbody.innerHTML = sensors.map(sn => {
      const kebab = (_isAdmin && (sn.status === 'enrolled' || sn.status === 'disenrolled'))
        ? `<button class="row-kebab sensors-row-kebab" data-id="${sn.id}" data-name="${_esc(sn.name)}" data-status="${_esc(sn.status)}" title="Row actions" aria-label="Row actions">⋮</button>`
        : '';
      const sizeBytes = _diskBySensor[sn.name];
      const sizeCell = (sizeBytes != null)
        ? `<td style="font-size:11px;color:var(--fg-dim);font-family:ui-monospace,monospace">${_humanBytes(sizeBytes)}</td>`
        : `<td style="font-size:11px;color:var(--fg-dim)">—</td>`;
      return `<tr>
        <td style="font-family:monospace" title="${_esc(sn.name)}">${_esc(sn.name)}</td>
        <td style="font-size:11px;color:var(--fg-dim)" title="${_esc(sn.host || '')}">${_esc(sn.host || '—')}</td>
        <td>${_statusBadge(sn.status)}</td>
        <td style="font-family:monospace">${_fmtSlotLocal(sn.schedule_hour, sn.schedule_minute)}</td>
        <td style="font-size:11px" title="${_fmtTSFull(sn.last_seen_at)}">${_fmtTS(sn.last_seen_at)}</td>
        <td>${_slotHealth(sn, now)}</td>
        ${sizeCell}
        <td>${kebab}</td>
      </tr>`;
    }).join('');
  }

  function _renderTokens(tokens) {
    const tbody = document.getElementById('sensors-tokens-tbody');
    if (!tbody) return;
    // "Pending Tokens" is for tokens awaiting enrollment or revocation.
    // Once a token's been consumed it shows up as a row in the Enrolled
    // Sensors table — surfacing it here too just clutters the actionable
    // list.
    const pending = (tokens || []).filter(t => !t.used_at);
    if (pending.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="font-style:italic;color:var(--fg-dim);text-align:center;padding:12px">No outstanding tokens.</td></tr>';
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    tbody.innerHTML = pending.map(t => {
      let status, color;
      if (t.expires_at <= now) { status = 'expired'; color = 'var(--sev-medium)'; }
      else { status = 'fresh'; color = 'var(--accent)'; }
      const kebab = _isAdmin
        ? `<button class="row-kebab tokens-row-kebab" data-id="${t.id}" data-token="${_esc(t.token)}" data-status="${status}" title="Row actions" aria-label="Row actions">⋮</button>`
        : '';
      return `<tr>
        <td style="font-family:monospace;font-size:11px" title="${_esc(t.token)}">${_esc(t.token)}</td>
        <td title="${_esc(t.override_name || '')}">${_esc(t.override_name || '—')}</td>
        <td style="font-size:11px" title="${_fmtTSFull(t.created_at)}">${_fmtTS(t.created_at)}</td>
        <td style="font-size:11px" title="${_fmtTSFull(t.expires_at)}">${_fmtTS(t.expires_at)}</td>
        <td><span style="color:${color};font-size:11px">${status}</span></td>
        <td>${kebab}</td>
      </tr>`;
    }).join('');
  }

  function _renderUnauth(rows) {
    const tbody = document.getElementById('sensors-unauth-tbody');
    if (!tbody) return;
    if (!rows || rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="font-style:italic;color:var(--fg-dim);text-align:center;padding:12px">No unauthorized attempts.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(a => {
      const kebab = _isAdmin
        ? `<button class="row-kebab unauth-row-kebab" data-id="${a.id}" data-name="${_esc(a.name)}" title="Row actions" aria-label="Row actions">⋮</button>`
        : '';
      return `<tr>
        <td style="font-family:monospace" title="${_esc(a.name)}">${_esc(a.name)}</td>
        <td style="font-family:monospace;font-size:11px" title="${_esc(a.source_ip)}">${_esc(a.source_ip)}</td>
        <td style="font-size:11px" title="${_fmtTSFull(a.first_seen)}">${_fmtTS(a.first_seen)}</td>
        <td style="font-size:11px" title="${_fmtTSFull(a.last_seen)}">${_fmtTS(a.last_seen)}</td>
        <td>${a.attempt_count}</td>
        <td>${kebab}</td>
      </tr>`;
    }).join('');
  }

  // ── data refresh ──────────────────────────────────────────────────────

  async function refresh() {
    const [sensors, tokens, unauth] = await Promise.all([
      _api('/api/sensors').catch(() => []),
      _isAdmin ? _api('/api/sensors/tokens').catch(() => []) : Promise.resolve([]),
      _api('/api/sensors/unauthorized').catch(() => []),
    ]);
    _renderSensors(Array.isArray(sensors) ? sensors : []);
    _renderTokens(Array.isArray(tokens) ? tokens : []);
    _renderUnauth(Array.isArray(unauth) ? unauth : []);
  }

  // ── confirm helper ────────────────────────────────────────────────────

  function _confirm(title, body) {
    return new Promise(resolve => {
      const dlg = document.getElementById('sensors-confirm-dlg');
      document.getElementById('sensors-confirm-title').textContent = title;
      document.getElementById('sensors-confirm-body').innerHTML = body;
      const ok     = document.getElementById('sensors-confirm-ok');
      const cancel = document.getElementById('sensors-confirm-cancel');
      const onOk = () => { cleanup(); resolve(true); };
      const onCancel = () => { cleanup(); resolve(false); };
      const cleanup = () => {
        ok.removeEventListener('click', onOk);
        cancel.removeEventListener('click', onCancel);
        dlg.close();
      };
      ok.addEventListener('click', onOk);
      cancel.addEventListener('click', onCancel);
      dlg.showModal();
    });
  }

  // ── action handlers ───────────────────────────────────────────────────

  async function _generateToken() {
    const override = document.getElementById('sensors-token-override').value.trim();
    const errEl = document.getElementById('sensors-token-error');
    errEl.style.display = 'none';
    try {
      const t = await _api('/api/sensors/tokens', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({override_name: override}),
      });
      const line = _oneLiner(t.token, _info);
      document.getElementById('sensors-token-oneliner').value = line;
      document.getElementById('sensors-token-result').style.display = '';
      _setTokenStatus('waiting');
      refresh();
    } catch (e) {
      errEl.textContent = (e && e.message) || String(e);
      errEl.style.display = '';
    }
  }

  // _setTokenStatus drives the small status line under the curl command.
  // 'waiting' is the initial state shown while the admin runs the install
  // on the sensor; 'enrolled' swaps in the confirmation tick when the
  // sensor_enrolled SSE event fires.
  function _setTokenStatus(state, sensor) {
    const el = document.getElementById('sensors-token-status');
    if (!el) return;
    if (state === 'waiting') {
      el.innerHTML = '<span class="pulse-dot"></span> Waiting for sensor to run the install command…';
      el.style.color = 'var(--fg-dim)';
    } else if (state === 'enrolled' && sensor) {
      el.innerHTML = `<span style="color:var(--sev-low);font-weight:700;font-size:14px">✓</span> Enrolled as <code>${_esc(sensor.name)}</code>`;
      el.style.color = 'var(--fg-primary)';
    } else {
      el.innerHTML = '';
    }
  }

  function _copyToken() {
    const ta = document.getElementById('sensors-token-oneliner');
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    if (typeof setStatus === 'function') setStatus('Install command copied');
  }

  async function _doDisenroll(id, name) {
    const ok = await _confirm('Disenroll sensor',
      `Disenroll <code>${_esc(name)}</code>? Its <code>/logs/${_esc(name)}/</code> tree will be moved to <code>/logs/_archived/</code> and findings will be retagged. The sensor will stop pushing on its next checkin (≤24h). Logs and findings remain on Archer.`);
    if (!ok) return;
    await _api('/api/sensors/disenroll', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})});
    refresh();
  }

  async function _doPurge(id, name) {
    const ok = await _confirm('Purge sensor data',
      `Permanently delete <code>${_esc(name)}</code>'s archived logs and all retagged findings? <strong>This cannot be undone.</strong>`);
    if (!ok) return;
    await _api('/api/sensors/purge', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})});
    refresh();
  }

  function _onSensorsTbodyClick(e) {
    const btn = e.target.closest('button.sensors-row-kebab');
    if (!btn) return;
    const id     = parseInt(btn.dataset.id, 10);
    const name   = btn.dataset.name || '';
    const status = btn.dataset.status || '';
    let items;
    if (status === 'enrolled') {
      items = [
        { label: 'Reassign slot', onClick: () => _openScheduleDialog(id) },
        '---',
        { label: 'Disenroll',     danger: true, onClick: () => _doDisenroll(id, name) },
      ];
    } else if (status === 'disenrolled') {
      items = [
        { label: 'Purge data',    danger: true, onClick: () => _doPurge(id, name) },
      ];
    } else {
      return;
    }
    RowMenu.open(btn, items);
  }

  async function _doRevokeToken(id) {
    await _api('/api/sensors/tokens/revoke', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})});
    refresh();
  }

  // _showTokenCommand reopens the enroll dialog in "show existing
  // command" mode for a pending token — admins click this when the
  // sensor operator says "can you send me that curl line again." The
  // create-section (override input + Generate button) is hidden so the
  // dialog just surfaces the one-liner + Copy button. Dialog returns
  // to create mode on close (see init).
  function _showTokenCommand(token) {
    if (!_info) {
      alert('Sensor enrollment info not loaded yet — try opening the modal again.');
      return;
    }
    document.getElementById('sensors-token-header').textContent = 'Sensor Enrollment Command';
    document.getElementById('sensors-token-create-section').style.display = 'none';
    document.getElementById('sensors-token-oneliner').value = _oneLiner(token, _info);
    document.getElementById('sensors-token-result').style.display = '';
    document.getElementById('sensors-token-error').style.display = 'none';
    _setTokenStatus(null);
    document.getElementById('sensors-token-dlg').showModal();
  }

  function _onTokensTbodyClick(e) {
    const btn = e.target.closest('button.tokens-row-kebab');
    if (!btn) return;
    const id = parseInt(btn.dataset.id, 10);
    const token = btn.dataset.token || '';
    const status = btn.dataset.status || '';
    // Expired tokens can't be used to enroll, so the "Show enrollment
    // command" item would be misleading. Only Revoke is offered.
    const items = (status === 'fresh')
      ? [
          { label: 'Show enrollment command', onClick: () => _showTokenCommand(token) },
          '---',
          { label: 'Revoke', danger: true, onClick: () => _doRevokeToken(id) },
        ]
      : [
          { label: 'Revoke', danger: true, onClick: () => _doRevokeToken(id) },
        ];
    RowMenu.open(btn, items);
  }

  async function _doDismissAttempt(id) {
    await _api('/api/sensors/unauthorized/dismiss', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})});
    refresh();
  }

  function _doEnrollThis(name) {
    document.getElementById('sensors-token-header').textContent = 'Enroll a New Sensor';
    document.getElementById('sensors-token-create-section').style.display = '';
    document.getElementById('sensors-token-override').value = name || '';
    document.getElementById('sensors-token-result').style.display = 'none';
    document.getElementById('sensors-token-error').style.display = 'none';
    _setTokenStatus(null);
    document.getElementById('sensors-token-dlg').showModal();
  }

  function _onUnauthTbodyClick(e) {
    const btn = e.target.closest('button.unauth-row-kebab');
    if (!btn) return;
    const id   = parseInt(btn.dataset.id, 10);
    const name = btn.dataset.name || '';
    RowMenu.open(btn, [
      { label: 'Enroll this sensor', onClick: () => _doEnrollThis(name) },
      '---',
      { label: 'Dismiss attempt',    onClick: () => _doDismissAttempt(id) },
    ]);
  }

  function _openScheduleDialog(id) {
    const dlg = document.getElementById('sensors-schedule-dlg');
    const minEl = document.getElementById('sensors-sched-minute');
    minEl.value = '';
    const onSave = async () => {
      const m = parseInt(minEl.value, 10);
      if (isNaN(m)) { return; }
      try {
        // Hour is always 0 under hourly mode; the server keeps the
        // column for legacy daily-mode sensors but the cron line is
        // built without it.
        await _api('/api/sensors/schedule', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({id, hour: 0, minute: m}),
        });
        cleanup();
        refresh();
      } catch (e) {
        // Keep dialog open on validation error
      }
    };
    const onCancel = () => cleanup();
    const cleanup = () => {
      document.getElementById('sensors-sched-save').removeEventListener('click', onSave);
      document.getElementById('sensors-sched-cancel').removeEventListener('click', onCancel);
      dlg.close();
    };
    document.getElementById('sensors-sched-save').addEventListener('click', onSave);
    document.getElementById('sensors-sched-cancel').addEventListener('click', onCancel);
    dlg.showModal();
  }

  // open is the public entry point used by both the Sensors button
  // click handler and the bell-notification jump dispatch for
  // Kind=sensor alarms. Refreshes the data sources the modal reads
  // from, then shows the dialog.
  async function open() {
    await Promise.all([_loadInfo(), _loadDiskUsage()]);
    await refresh();
    const dlg = document.getElementById('sensors-dialog');
    if (dlg) dlg.showModal();
  }

  // ── init ──────────────────────────────────────────────────────────────

  function init(isAdmin) {
    _isAdmin = !!isAdmin;
    const btn = document.getElementById('sensors-btn');
    if (!btn) return;
    btn.style.display = '';

    if (_isAdmin) {
      const adminBar = document.getElementById('sensors-admin-bar');
      if (adminBar) adminBar.style.display = '';
    }

    const dlg = document.getElementById('sensors-dialog');
    btn.addEventListener('click', open);
    document.getElementById('sensors-close').addEventListener('click', () => dlg.close());

    const tokenDlg = document.getElementById('sensors-token-dlg');
    const newTokenBtn = document.getElementById('sensors-new-token-btn');
    if (newTokenBtn) {
      newTokenBtn.addEventListener('click', () => {
        document.getElementById('sensors-token-header').textContent = 'Enroll a New Sensor';
        document.getElementById('sensors-token-create-section').style.display = '';
        document.getElementById('sensors-token-override').value = '';
        document.getElementById('sensors-token-result').style.display = 'none';
        document.getElementById('sensors-token-error').style.display = 'none';
        _setTokenStatus(null);
        tokenDlg.showModal();
      });
    }
    document.getElementById('sensors-token-close').addEventListener('click', () => tokenDlg.close());
    // Refresh the parent Sensors table whenever the enroll dialog closes
    // (button, ESC, anything) so the analyst sees the new sensor row
    // without manually reopening the modal.
    tokenDlg.addEventListener('close', () => { refresh(); });
    document.getElementById('sensors-token-generate').addEventListener('click', _generateToken);
    document.getElementById('sensors-token-copy').addEventListener('click', _copyToken);

    document.getElementById('sensors-tbody').addEventListener('click', _onSensorsTbodyClick);
    document.getElementById('sensors-tokens-tbody').addEventListener('click', _onTokensTbodyClick);
    document.getElementById('sensors-unauth-tbody').addEventListener('click', _onUnauthTbodyClick);

    // Live update the Unauthorized Attempts table whenever the server
    // observes a fresh checkin from a name we don't recognize. We only
    // refresh when the modal is open — refreshing a hidden modal would
    // burn cycles on data the analyst can't see.
    if (typeof SSE !== 'undefined' && SSE.on) {
      SSE.on('unauthorized_attempt', () => {
        if (dlg.open) refresh();
      });
      // When a sensor finishes enrollment: refresh the parent table so
      // the new row appears, and if the enroll dialog is still open
      // swap its "waiting" line for the confirmation tick.
      SSE.on('sensor_enrolled', sensor => {
        if (dlg.open) refresh();
        if (tokenDlg.open) _setTokenStatus('enrolled', sensor);
      });
    }
  }

  return { init, refresh, open };
})();
