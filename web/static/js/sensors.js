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

  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  // Pretty-print a unix timestamp. 0 / undefined become "—" so empty
  // cells don't look like "1969-12-31".
  function _fmtTS(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  }

  function _fmtSlot(h, m) {
    return String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0');
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

  // ── render ────────────────────────────────────────────────────────────

  function _renderSensors(sensors) {
    const tbody = document.getElementById('sensors-tbody');
    if (!tbody) return;
    if (!sensors || sensors.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="font-style:italic;color:var(--fg-dim);text-align:center;padding:12px">No sensors enrolled yet.</td></tr>';
      return;
    }
    tbody.innerHTML = sensors.map(sn => {
      let actions = '';
      if (_isAdmin) {
        if (sn.status === 'enrolled') {
          actions = `<button class="dlg-btn secondary" data-act="schedule" data-id="${sn.id}">Slot</button>
                     <button class="dlg-btn secondary" data-act="disenroll" data-id="${sn.id}" data-name="${_esc(sn.name)}">Disenroll</button>`;
        } else if (sn.status === 'disenrolled') {
          actions = `<button class="dlg-btn danger" data-act="purge" data-id="${sn.id}" data-name="${_esc(sn.name)}">Purge data</button>`;
        }
      }
      return `<tr>
        <td style="font-family:monospace">${_esc(sn.name)}</td>
        <td style="font-size:11px;color:var(--fg-dim)">${_esc(sn.host || '—')}</td>
        <td>${_statusBadge(sn.status)}</td>
        <td style="font-family:monospace">${_fmtSlot(sn.schedule_hour, sn.schedule_minute)}</td>
        <td style="font-size:11px">${_fmtTS(sn.last_seen_at)}</td>
        <td style="text-align:right">${actions}</td>
      </tr>`;
    }).join('');
  }

  function _renderTokens(tokens) {
    const tbody = document.getElementById('sensors-tokens-tbody');
    if (!tbody) return;
    if (!tokens || tokens.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="font-style:italic;color:var(--fg-dim);text-align:center;padding:12px">No outstanding tokens.</td></tr>';
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    tbody.innerHTML = tokens.map(t => {
      let status, color;
      if (t.used_at) { status = 'used'; color = 'var(--fg-dim)'; }
      else if (t.expires_at <= now) { status = 'expired'; color = 'var(--sev-medium)'; }
      else { status = 'fresh'; color = 'var(--accent)'; }
      const trunc = t.token.length > 18 ? t.token.slice(0, 16) + '…' : t.token;
      const actions = (_isAdmin && status !== 'used')
        ? `<button class="dlg-btn secondary" data-act="revoke-token" data-id="${t.id}">Revoke</button>`
        : '';
      return `<tr>
        <td style="font-family:monospace;font-size:11px" title="${_esc(t.token)}">${_esc(trunc)}</td>
        <td>${_esc(t.override_name || '—')}</td>
        <td style="font-size:11px">${_fmtTS(t.created_at)}</td>
        <td style="font-size:11px">${_fmtTS(t.expires_at)}</td>
        <td><span style="color:${color};font-size:11px">${status}</span></td>
        <td style="text-align:right">${actions}</td>
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
      const actions = _isAdmin
        ? `<button class="dlg-btn secondary" data-act="enroll-this" data-name="${_esc(a.name)}">Enroll this</button>
           <button class="dlg-btn secondary" data-act="dismiss-attempt" data-id="${a.id}">Dismiss</button>`
        : '';
      return `<tr>
        <td style="font-family:monospace">${_esc(a.name)}</td>
        <td style="font-family:monospace;font-size:11px">${_esc(a.source_ip)}</td>
        <td style="font-size:11px">${_fmtTS(a.first_seen)}</td>
        <td style="font-size:11px">${_fmtTS(a.last_seen)}</td>
        <td>${a.attempt_count}</td>
        <td style="text-align:right">${actions}</td>
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
      refresh();
    } catch (e) {
      errEl.textContent = (e && e.message) || String(e);
      errEl.style.display = '';
    }
  }

  function _copyToken() {
    const ta = document.getElementById('sensors-token-oneliner');
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    if (typeof setStatus === 'function') setStatus('Install command copied');
  }

  async function _onSensorsTbodyClick(e) {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const act = btn.dataset.act;
    const id  = parseInt(btn.dataset.id, 10);
    const name = btn.dataset.name || '';
    if (act === 'disenroll') {
      const ok = await _confirm('Disenroll sensor',
        `Disenroll <code>${_esc(name)}</code>? Its <code>/logs/${_esc(name)}/</code> tree will be moved to <code>/logs/_archived/</code> and findings will be retagged. The sensor will stop pushing on its next checkin (≤24h). Logs and findings remain on Archer.`);
      if (!ok) return;
      await _api('/api/sensors/disenroll', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})});
      refresh();
    } else if (act === 'purge') {
      const ok = await _confirm('Purge sensor data',
        `Permanently delete <code>${_esc(name)}</code>'s archived logs and all retagged findings? <strong>This cannot be undone.</strong>`);
      if (!ok) return;
      await _api('/api/sensors/purge', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})});
      refresh();
    } else if (act === 'schedule') {
      _openScheduleDialog(id);
    }
  }

  async function _onTokensTbodyClick(e) {
    const btn = e.target.closest('button[data-act="revoke-token"]');
    if (!btn) return;
    const id = parseInt(btn.dataset.id, 10);
    await _api('/api/sensors/tokens/revoke', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})});
    refresh();
  }

  async function _onUnauthTbodyClick(e) {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const act = btn.dataset.act;
    if (act === 'dismiss-attempt') {
      const id = parseInt(btn.dataset.id, 10);
      await _api('/api/sensors/unauthorized/dismiss', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})});
      refresh();
    } else if (act === 'enroll-this') {
      // Pre-fill the override name and open the token dialog.
      document.getElementById('sensors-token-override').value = btn.dataset.name || '';
      document.getElementById('sensors-token-result').style.display = 'none';
      document.getElementById('sensors-token-error').style.display = 'none';
      document.getElementById('sensors-token-dlg').showModal();
    }
  }

  function _openScheduleDialog(id) {
    const dlg = document.getElementById('sensors-schedule-dlg');
    const hourEl = document.getElementById('sensors-sched-hour');
    const minEl  = document.getElementById('sensors-sched-minute');
    hourEl.value = '';
    minEl.value  = '';
    const onSave = async () => {
      const h = parseInt(hourEl.value, 10);
      const m = parseInt(minEl.value, 10);
      if (isNaN(h) || isNaN(m)) { return; }
      try {
        await _api('/api/sensors/schedule', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({id, hour: h, minute: m}),
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
    btn.addEventListener('click', async () => {
      await _loadInfo();
      await refresh();
      dlg.showModal();
    });
    document.getElementById('sensors-close').addEventListener('click', () => dlg.close());

    const tokenDlg = document.getElementById('sensors-token-dlg');
    const newTokenBtn = document.getElementById('sensors-new-token-btn');
    if (newTokenBtn) {
      newTokenBtn.addEventListener('click', () => {
        document.getElementById('sensors-token-override').value = '';
        document.getElementById('sensors-token-result').style.display = 'none';
        document.getElementById('sensors-token-error').style.display = 'none';
        tokenDlg.showModal();
      });
    }
    document.getElementById('sensors-token-close').addEventListener('click', () => tokenDlg.close());
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
    }
  }

  return { init, refresh };
})();
