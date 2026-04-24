// app.js — main application state machine
'use strict';

(async () => {

  // ── State ──────────────────────────────────────────────────────────────────
  let _allFindings     = [];
  let _deltaMode       = false;
  let _selectedFinding = null;
  let _ctxFinding      = null;
  let _watchActive     = false;
  let _tabMode         = 'findings'; // 'findings' | 'ack' | 'esc' | 'ioc'
  let _iocSet          = new Set();  // live cache of IOC list IPs for instant tab overlay
  let _logsDir         = '/logs';
  let _currentUser     = null;

  // ── Helpers ────────────────────────────────────────────────────────────────
  function setStatus(msg) {
    document.getElementById('status-msg').textContent = msg;
  }

  function showToast(msg, duration = 2500) {
    const t = document.getElementById('pcap-toast');
    t.textContent = msg;
    t.style.display = 'block';
    clearTimeout(t._timer);
    t._timer = setTimeout(() => t.style.display = 'none', duration);
  }

  function api(url, opts = {}) {
    return fetch(url, opts).then(r => {
      if (!r.ok) {
        return r.json().catch(() => ({})).then(e => Promise.reject(e.error || r.statusText));
      }
      const ct = r.headers.get('content-type') || '';
      return ct.includes('json') ? r.json() : r.text();
    });
  }

  async function fetchFinding(id) {
    return api(`/api/findings/${id}`);
  }

  // ── Load findings ──────────────────────────────────────────────────────────
  async function loadFindings(params = {}) {
    const qs = new URLSearchParams(params).toString();
    const data = await api('/api/findings' + (qs ? '?' + qs : ''));
    _allFindings = Array.isArray(data) ? data : [];
    Table.populateTypeFilter(_allFindings);
    Campaigns.build(_allFindings);
    _applyTabFilter();
  }

  // Apply the current tab mode filter to the table
  function _applyTabFilter() {
    let shown = _allFindings;
    if (_tabMode === 'ack') {
      shown = _allFindings.filter(f => f.status === 'acknowledged');
    } else if (_tabMode === 'esc') {
      shown = _allFindings.filter(f => f.status === 'escalated');
    } else if (_tabMode === 'ioc') {
      const TI_TYPES = new Set(['Threat Intel Hit', 'Suspicious URL']);
      shown = _allFindings.filter(f => f.ioc_match || TI_TYPES.has(f.type) ||
        (f.src_ip && _iocSet.has(f.src_ip)) || (f.dst_ip && _iocSet.has(f.dst_ip)));
    } else {
      // 'findings' = open only
      shown = _allFindings.filter(f => !f.status || f.status === '');
    }
    if (_deltaMode) shown = shown.filter(f => f.is_new);
    Table.load(shown);
    updateInfoLine();
  }

  function updateInfoLine() {
    let open  = _allFindings.filter(f => !f.status || f.status === '').length;
    let acked = _allFindings.filter(f => f.status === 'acknowledged').length;
    let esc   = _allFindings.filter(f => f.status === 'escalated').length;
    const _TI_TYPES = new Set(['Threat Intel Hit', 'Suspicious URL']);
    let ioc   = _allFindings.filter(f => f.ioc_match || _TI_TYPES.has(f.type) ||
      (f.src_ip && _iocSet.has(f.src_ip)) || (f.dst_ip && _iocSet.has(f.dst_ip))).length;
    const parts = [`${open} open`, `${acked} ack'd`, `${esc} escalated`];
    if (ioc) parts.push(`${ioc} IOC`);
    const newCount = _allFindings.filter(f => f.is_new).length;
    if (newCount) parts.push(`${newCount} new`);
    document.getElementById('info-line').textContent = parts.join('  •  ');
    document.getElementById('findings-count').textContent =
      `${_allFindings.length} total`;
  }

  // Fetch IOC list into _iocSet; re-applies tab filter if IOC tab is active.
  async function _loadIOCList() {
    try {
      const data = await api('/api/ioc');
      _iocSet = new Set(Array.isArray(data) ? data : []);
      if (_tabMode === 'ioc') _applyTabFilter();
      updateInfoLine();
    } catch (_) {}
  }

  // ── Tabs ───────────────────────────────────────────────────────────────────
  function initTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        if (tab === 'findings' || tab === 'ack' || tab === 'esc' || tab === 'ioc') {
          // All four share #tab-findings panel; just change the filter
          document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
          document.getElementById('tab-findings').classList.add('active');
          _tabMode = tab;
          _applyTabFilter();
        } else {
          document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
          const panel = document.getElementById('tab-' + tab);
          if (panel) panel.classList.add('active');
        }
      });
    });
  }

  // ── Filter bar ─────────────────────────────────────────────────────────────
  function initFilterBar() {
    document.getElementById('apply-filter-btn').addEventListener('click', applyFilter);
    document.getElementById('reset-filter-btn').addEventListener('click', () => {
      document.getElementById('filter-search').value = '';
      document.getElementById('filter-sev').value = '';
      document.getElementById('filter-type').value = '';
      document.getElementById('filter-score').value = '0';
      _applyTabFilter();
    });
    document.getElementById('filter-search').addEventListener('keydown', e => {
      if (e.key === 'Enter') applyFilter();
    });
  }

  function applyFilter() {
    const params = {};
    const search = document.getElementById('filter-search').value.trim();
    const sev    = document.getElementById('filter-sev').value;
    const type   = document.getElementById('filter-type').value;
    const score  = parseInt(document.getElementById('filter-score').value) || 0;
    if (search) params.search = search;
    if (sev)    params.severity = sev;
    if (type)   params.type = type;
    if (score > 0) params.min_score = score;
    loadFindings(params);
  }

  // ── Delta mode ─────────────────────────────────────────────────────────────
  function initDeltaBar() {
    document.getElementById('delta-btn').addEventListener('click', () => {
      _deltaMode = true;
      document.getElementById('delta-btn').classList.add('active');
      document.getElementById('show-all-btn').classList.remove('active');
      _applyTabFilter();
    });
    document.getElementById('show-all-btn').addEventListener('click', () => {
      _deltaMode = false;
      document.getElementById('show-all-btn').classList.add('active');
      document.getElementById('delta-btn').classList.remove('active');
      _applyTabFilter();
    });
  }

  // ── Import from /logs volume ────────────────────────────────────────────────
  function _setLogsDirHint(dir) {
    const el = document.getElementById('logs-dir-path');
    if (el) el.textContent = dir || '/logs';
  }

  function initUpload() {
    // Read configured dir on page load — GET is read-only, no scanning side effects
    api('/api/logs/scan')
      .then(r => { _logsDir = r.dir || '/logs'; _setLogsDirHint(_logsDir); refreshFileList(); })
      .catch(() => { _setLogsDirHint('/logs'); refreshFileList(); });

    document.getElementById('import-logs-btn').addEventListener('click', async () => {
      setStatus('Scanning logs directory…');
      try {
        const result = await api('/api/logs/scan', {method: 'POST'});
        const count = result.count || 0;
        const dir   = result.dir  || '/logs';
        _logsDir = dir;
        _setLogsDirHint(dir);
        setStatus(`Imported ${count} file${count !== 1 ? 's' : ''} from ${dir}`);
        await refreshFileList();
      } catch (e) {
        setStatus('Import error: ' + e);
      }
    });

    document.getElementById('clear-files-btn').addEventListener('click', async () => {
      if (!confirm('Clear file list?')) return;
      await api('/api/files/clear', {method: 'POST'});
      await refreshFileList();
    });
  }

  async function refreshFileList() {
    const data = await api('/api/files').catch(() => []);
    const ul = document.getElementById('file-list');
    ul.innerHTML = '';
    const files = Array.isArray(data) ? data : [];

    const dirParts = _logsDir.replace(/\\/g, '/').split('/').filter(Boolean);
    const byDataset = new Map();
    files.forEach(p => {
      const parts    = p.replace(/\\/g, '/').split('/').filter(Boolean);
      const relParts = parts.slice(dirParts.length);
      const dataset  = relParts.length >= 2 ? relParts[0] : '(root)';
      const name     = parts[parts.length - 1];
      if (!byDataset.has(dataset)) byDataset.set(dataset, []);
      byDataset.get(dataset).push({name, path: p});
    });

    if (byDataset.size === 0) {
      const li = document.createElement('li');
      li.textContent = 'No files — click Import';
      li.style.fontStyle = 'italic';
      ul.appendChild(li);
      return;
    }

    byDataset.forEach((entries, dataset) => {
      const hdr = document.createElement('li');
      hdr.textContent = `📁 ${dataset} (${entries.length})`;
      hdr.style.cssText = 'color:var(--fg-text);font-weight:600;margin-top:4px;font-size:10px';
      ul.appendChild(hdr);
    });
  }

  // ── Analyze ────────────────────────────────────────────────────────────────
  function _updateTIStatus() {
    const tiTypes = new Set(['Threat Intel Hit', 'Suspicious URL']);
    const hits = _allFindings.filter(f => tiTypes.has(f.type)).length;
    const el = document.getElementById('ti-status');
    if (hits > 0) {
      el.textContent = `${hits} hit${hits !== 1 ? 's' : ''} found`;
      el.style.color = 'var(--sev-critical)';
    } else {
      el.textContent = 'No hits';
      el.style.color = 'var(--fg-dim)';
    }
  }

  let _paused = false;

  function _setAnalyzing(active) {
    document.getElementById('analyze-btn').disabled = active;
    document.getElementById('analysis-controls').style.display = active ? 'flex' : 'none';
    if (!active) {
      _paused = false;
      document.getElementById('pause-btn').textContent = '⏸ Pause';
    }
  }

  async function _syncAnalyzeState() {
    try {
      const s = await api('/api/analyze/status');
      if (s.running) {
        _setAnalyzing(true);
        if (s.paused) {
          _paused = true;
          document.getElementById('pause-btn').textContent = '▶ Resume';
          setStatus('Analysis paused — click Resume to continue');
        } else {
          setStatus('Analysis in progress…');
        }
      }
    } catch (_) {}
  }

  function initAnalyze() {
    _syncAnalyzeState();

    document.getElementById('analyze-btn').addEventListener('click', async () => {
      _setAnalyzing(true);
      document.getElementById('progress-bar').value = 0;
      document.getElementById('ti-status').textContent = 'Fetching…';
      document.getElementById('ti-status').style.color = 'var(--fg-dim)';
      setStatus('Starting analysis…');
      try {
        await api('/api/analyze', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({}),
        });
      } catch (e) {
        // 409 = analysis already running — keep buttons visible so user can stop it
        if (String(e).includes('already running') || String(e).includes('409')) {
          setStatus('Analysis already running');
        } else {
          setStatus('Analysis failed: ' + e);
          _setAnalyzing(false);
        }
      }
    });

    document.getElementById('stop-btn').addEventListener('click', async () => {
      try { await api('/api/analyze/cancel', {method: 'POST'}); } catch (_) {}
    });

    document.getElementById('pause-btn').addEventListener('click', async () => {
      try {
        if (_paused) {
          await api('/api/analyze/resume', {method: 'POST'});
          _paused = false;
          document.getElementById('pause-btn').textContent = '⏸ Pause';
          setStatus('Analysis resumed…');
        } else {
          await api('/api/analyze/pause', {method: 'POST'});
          _paused = true;
          document.getElementById('pause-btn').textContent = '▶ Resume';
          setStatus('Analysis paused — click Resume to continue');
        }
      } catch (_) {}
    });
  }

  // ── SSE ────────────────────────────────────────────────────────────────────
  function initSSE() {
    SSE.on('progress', evt => {
      document.getElementById('progress-bar').value = evt.pct || 0;
      document.getElementById('analysis-status').textContent = evt.step || '';
      setStatus(evt.step || '');
    });

    SSE.on('status', evt => {
      if (evt.msg) setStatus(evt.msg);
    });

    SSE.on('done', async evt => {
      _setAnalyzing(false);
      document.getElementById('progress-bar').value = evt.cancelled ? 0 : 100;
      setStatus(evt.cancelled
        ? `Analysis stopped — ${evt.count || 0} partial findings`
        : `Analysis complete — ${evt.count || 0} findings (${evt.new_count || 0} new)`);
      document.getElementById('analysis-status').textContent = '';
      await loadFindings();
      _updateTIStatus();
      // Catch any notifications missed if SSE connection dropped during analysis
      fetch('/api/notifications')
        .then(r => r.json())
        .then(data => { if (Array.isArray(data)) data.filter(n => !n.dismissed).forEach(n => Notifications.add(n)); })
        .catch(() => {});
      setTimeout(() => { document.getElementById('progress-bar').value = 0; }, 2000);
      if (!evt.cancelled) {
        const total    = evt.count     || 0;
        const newCount = evt.new_count || 0;
        const msg = newCount > 0
          ? `${newCount} new finding${newCount !== 1 ? 's' : ''} detected\n${total} total`
          : `No new findings\n${total} finding${total !== 1 ? 's' : ''} total`;
        document.getElementById('analysis-alert-msg').textContent = msg;
        document.getElementById('analysis-alert-dlg').showModal();
      }
    });

    SSE.on('notification', n => Notifications.add(n));

    SSE.on('ti_result', evt => {
      const prefix = evt.hit ? '[HIT] ' : '[CLEAN] ';
      showToast(`${prefix}${evt.source}: ${evt.detail}`, 7000);
      // Reload detail pane if the affected finding is currently displayed
      if (_selectedFinding && _selectedFinding.id === evt.finding_id) {
        fetchFinding(evt.finding_id).then(updated => {
          _selectedFinding = updated;
          Detail.render(updated);
          const idx = _allFindings.findIndex(x => x.id === updated.id);
          if (idx >= 0) _allFindings[idx] = updated;
        }).catch(() => {});
      }
    });

    SSE.on('ti_done', evt => {
      const msg = evt.hits > 0
        ? `TI lookup complete — ${evt.hits} hit${evt.hits !== 1 ? 's' : ''} found`
        : 'TI lookup complete — no threats detected';
      setStatus(msg);
      showToast(msg, 6000);
    });

    SSE.connect();

    document.getElementById('analysis-alert-ok').addEventListener('click', () => {
      document.getElementById('analysis-alert-dlg').close();
    });
  }

  // ── Note modal ─────────────────────────────────────────────────────────────
  function promptNote(title) {
    return new Promise(resolve => {
      const dlg = document.getElementById('note-dialog');
      document.getElementById('note-dialog-title').textContent = title;
      const ta  = document.getElementById('note-text');
      ta.value  = '';
      dlg.showModal();
      setTimeout(() => ta.focus(), 50);

      function cleanup() {
        document.getElementById('note-ok').removeEventListener('click', onOk);
        document.getElementById('note-cancel').removeEventListener('click', onCancel);
        dlg.removeEventListener('keydown', onKey);
      }
      function onOk()     { cleanup(); dlg.close(); resolve(ta.value.trim()); }
      function onCancel() { cleanup(); dlg.close(); resolve(null); }
      function onKey(e)   { if (e.key === 'Escape') { cleanup(); dlg.close(); resolve(null); } }

      document.getElementById('note-ok').addEventListener('click', onOk);
      document.getElementById('note-cancel').addEventListener('click', onCancel);
      dlg.addEventListener('keydown', onKey);
    });
  }

  // ── Detail actions ─────────────────────────────────────────────────────────
  function initDetailActions() {
    document.getElementById('ack-btn').addEventListener('click', async () => {
      if (!_selectedFinding) return;
      const f = _selectedFinding;
      const newStatus = f.status === 'acknowledged' ? '' : 'acknowledged';
      const label = newStatus === 'acknowledged' ? 'Acknowledge Finding' : 'Re-open Finding';
      const note = await promptNote(label);
      if (note === null) return; // cancelled
      try {
        await api(`/api/findings/${f.id}`, {
          method: 'PATCH',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({status: newStatus, note}),
        });
        const updated = await fetchFinding(f.id);
        _selectedFinding = updated;
        Detail.render(updated);
        const idx = _allFindings.findIndex(x => x.id === f.id);
        if (idx >= 0) _allFindings[idx] = updated;
        Table.update(updated);
        _applyTabFilter();
      } catch (e) { setStatus('Error: ' + e); }
    });

    // Escalate dialog — built once, reused per click
    const _escDlg     = document.getElementById('escalate-dialog');
    const _escNote    = document.getElementById('esc-note');
    const _escTISection = document.getElementById('esc-ti-section');
    const _escIPOpts  = document.getElementById('esc-ip-options');
    const _escSvcOpts = document.getElementById('esc-svc-options');

    const _mkCheck = (id, label, checked) => {
      const wrap = document.createElement('label');
      wrap.style.cssText = 'display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12px';
      const cb = document.createElement('input');
      cb.type = 'checkbox'; cb.id = id; cb.checked = checked;
      wrap.appendChild(cb);
      wrap.appendChild(document.createTextNode(label));
      return wrap;
    };

    const _checked = id => { const el = document.getElementById(id); return el ? el.checked : false; };

    document.getElementById('esc-btn').addEventListener('click', async () => {
      if (!_selectedFinding) return;
      const f = _selectedFinding;

      // Fetch which services have API keys — fall back to empty if endpoint unavailable
      let svcs = {};
      try { svcs = await api('/api/ti/services'); } catch (_) {}

      const hasService = svcs.vt || svcs.crowdsec || svcs.otx || svcs.abuseipdb;

      // Artifact checkboxes
      _escIPOpts.innerHTML = '';
      if (f.dst_ip) _escIPOpts.appendChild(_mkCheck('esc-ip-dst', `Dst IP (${f.dst_ip})`, true));
      if (f.src_ip) _escIPOpts.appendChild(_mkCheck('esc-ip-src', `Src IP (${f.src_ip})`, !f.dst_ip));

      // Service checkboxes — only shown when key is configured
      _escSvcOpts.innerHTML = '';
      if (svcs.vt)        _escSvcOpts.appendChild(_mkCheck('esc-svc-vt',        'VirusTotal', true));
      if (svcs.crowdsec)  _escSvcOpts.appendChild(_mkCheck('esc-svc-crowdsec',  'CrowdSec',   true));
      if (svcs.otx)       _escSvcOpts.appendChild(_mkCheck('esc-svc-otx',       'OTX',        true));
      if (svcs.abuseipdb) _escSvcOpts.appendChild(_mkCheck('esc-svc-abuseipdb', 'AbuseIPDB',  true));

      _escTISection.style.display = hasService ? '' : 'none';
      _escNote.value = '';
      _escDlg.showModal();

      // Attach confirm handler — replace each time to capture current finding
      document.getElementById('esc-dlg-confirm').onclick = async () => {
        const note = _escNote.value.trim();
        const ips = [];
        if (f.dst_ip && _checked('esc-ip-dst'))  ips.push(f.dst_ip);
        if (f.src_ip && _checked('esc-ip-src'))  ips.push(f.src_ip);
        const services = [];
        if (_checked('esc-svc-vt'))        services.push('vt');
        if (_checked('esc-svc-crowdsec'))  services.push('crowdsec');
        if (_checked('esc-svc-otx'))       services.push('otx');
        if (_checked('esc-svc-abuseipdb')) services.push('abuseipdb');
        _escDlg.close();
        try {
          await api(`/api/findings/${f.id}/escalate`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({note, ips, services}),
          });
          const updated = await fetchFinding(f.id);
          _selectedFinding = updated;
          Detail.render(updated);
          const idx = _allFindings.findIndex(x => x.id === f.id);
          if (idx >= 0) _allFindings[idx] = updated;
          Table.update(updated);
          _applyTabFilter();
          setStatus(ips.length > 0 ? 'Escalated — TI lookup running in background' : 'Escalated');
        } catch (e) { setStatus('Error: ' + e); }
      };
    });

    document.getElementById('esc-dlg-cancel').addEventListener('click', () => _escDlg.close());

    document.getElementById('chart-btn').addEventListener('click', () => {
      if (_selectedFinding) BeaconChart.show(_selectedFinding);
    });

    document.getElementById('add-note-btn').addEventListener('click', async () => {
      if (!_selectedFinding) return;
      const ta   = document.getElementById('inline-note-input');
      const text = ta.value.trim();
      if (!text) return;
      try {
        await api(`/api/findings/${_selectedFinding.id}/notes`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({text}),
        });
        ta.value = '';
        const updated = await fetchFinding(_selectedFinding.id);
        _selectedFinding = updated;
        Detail.render(updated);
        const idx = _allFindings.findIndex(x => x.id === updated.id);
        if (idx >= 0) _allFindings[idx] = updated;
      } catch (e) { setStatus('Error: ' + e); }
    });

    document.getElementById('pcap-btn').addEventListener('click', () => {
      if (_selectedFinding) copyPCAP(_selectedFinding);
    });

    document.getElementById('supp-btn').addEventListener('click', () => {
      if (_selectedFinding) openSuppressDialog(_selectedFinding);
    });
  }

  function copyPCAP(f) {
    if (!f.src_ip || !f.dst_ip) return;
    let filter = `host ${f.src_ip} and host ${f.dst_ip}`;
    if (f.dst_port) filter += ` and tcp port ${f.dst_port}`;
    navigator.clipboard.writeText(filter).catch(() => {});
    showToast('Copied: ' + filter);
  }

  // ── Suppress dialog ────────────────────────────────────────────────────────
  function openSuppressDialog(f) {
    const dlg = document.getElementById('suppress-dialog');
    document.getElementById('suppress-target').textContent =
      `${f.src_ip || ''} → ${f.dst_ip || ''} [${f.type}]`;
    dlg.dataset.target = f.dst_ip || f.src_ip || '';
    dlg.dataset.detail = `${f.type} | ${f.severity} | ${f.src_ip || ''}→${f.dst_ip || ''}:${f.dst_port || ''}`;
    dlg.showModal();
  }

  function initSuppressDialog() {
    const dlg = document.getElementById('suppress-dialog');
    document.querySelectorAll('#suppress-dialog .preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.getElementById('suppress-custom').value = btn.dataset.days;
      });
    });
    document.getElementById('suppress-cancel').addEventListener('click', () => dlg.close());
    document.getElementById('suppress-ok').addEventListener('click', async () => {
      const days   = parseFloat(document.getElementById('suppress-custom').value) || 7;
      const target = dlg.dataset.target;
      if (!target) { dlg.close(); return; }
      try {
        await api('/api/suppressions', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({target, days, detail: dlg.dataset.detail || ''}),
        });
        setStatus(`Suppressed ${target} for ${days} day(s)`);
        loadFindings();
      } catch (e) { setStatus('Suppress error: ' + e); }
      dlg.close();
    });
  }

  // ── Suppressions manager ──────────────────────────────────────────────────
  function initSuppressionsManager() {
    const dlg = document.getElementById('suppressions-dialog');
    document.getElementById('suppressions-close').addEventListener('click', () => dlg.close());

    async function _renderSuppressions() {
      const listEl = document.getElementById('suppressions-list');
      listEl.textContent = 'Loading…';
      let data;
      try { data = await api('/api/suppressions'); } catch(e) { listEl.textContent = 'Error loading suppressions.'; return; }
      if (!Array.isArray(data) || data.length === 0) {
        listEl.innerHTML = '<div style="color:var(--fg-dim);font-size:13px">No active suppressions.</div>';
        return;
      }
      data.sort((a, b) => a.expiry - b.expiry);
      listEl.innerHTML = '';
      data.forEach(s => {
        const expDate = new Date(s.expiry * 1000);
        const expStr  = expDate.toUTCString().replace(' GMT', ' UTC');
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)';
        row.innerHTML = `
          <div style="flex:1;min-width:0">
            <div style="font-family:monospace;font-size:13px">${s.target}</div>
            ${s.detail ? `<div style="font-size:11px;color:var(--fg-dim);margin-top:2px">${s.detail}</div>` : ''}
            <div style="font-size:11px;color:var(--fg-dim);margin-top:2px">Expires ${expStr}</div>
          </div>
          <button class="dlg-btn secondary" style="padding:3px 10px;font-size:12px;flex-shrink:0" data-target="${s.target}">Remove</button>`;
        row.querySelector('button').addEventListener('click', async () => {
          await api(`/api/suppressions/${encodeURIComponent(s.target)}`, {method:'DELETE'}).catch(() => {});
          setStatus(`Unsuppressed ${s.target}`);
          await _renderSuppressions();
          loadFindings();
        });
        listEl.appendChild(row);
      });
    }

    document.getElementById('suppressions-btn').addEventListener('click', async () => {
      await _renderSuppressions();
      dlg.showModal();
    });
  }

  // ── Allowlist / IOC dialogs ────────────────────────────────────────────────
  function initListDialogs() {
    const alDlg = document.getElementById('allowlist-dialog');
    document.getElementById('allowlist-btn').addEventListener('click', async () => {
      const data = await api('/api/allowlist').catch(() => []);
      document.getElementById('allowlist-ta').value = (Array.isArray(data) ? data : []).join('\n');
      alDlg.showModal();
    });
    document.getElementById('allowlist-cancel').addEventListener('click', () => alDlg.close());
    document.getElementById('allowlist-save').addEventListener('click', async () => {
      const lines = document.getElementById('allowlist-ta').value
        .split('\n').map(s => s.trim()).filter(Boolean);
      await api('/api/allowlist', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(lines),
      }).catch(e => setStatus('Error: ' + e));
      setStatus('Allowlist saved');
      alDlg.close();
      loadFindings();
    });

    const iocDlg = document.getElementById('ioc-dialog');
    document.getElementById('ioc-btn').addEventListener('click', async () => {
      const data = await api('/api/ioc').catch(() => []);
      document.getElementById('ioc-ta').value = (Array.isArray(data) ? data : []).join('\n');
      iocDlg.showModal();
    });
    document.getElementById('ioc-cancel').addEventListener('click', () => iocDlg.close());
    document.getElementById('ioc-save').addEventListener('click', async () => {
      const lines = document.getElementById('ioc-ta').value
        .split('\n').map(s => s.trim()).filter(Boolean);
      await api('/api/ioc', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(lines),
      }).catch(e => setStatus('Error: ' + e));
      setStatus('IOC list saved');
      iocDlg.close();
      _loadIOCList();
    });
  }

  // ── Settings dialog ────────────────────────────────────────────────────────
  function initSettings() {
    const dlg = document.getElementById('settings-dialog');
    document.getElementById('settings-btn').addEventListener('click', async () => {
      const cfg = await api('/api/config').catch(() => ({}));
      _populateSettings(cfg);
      dlg.showModal();
    });
    document.getElementById('settings-cancel').addEventListener('click', () => dlg.close());
    document.getElementById('settings-save').addEventListener('click', async () => {
      await api('/api/config', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(_collectSettings()),
      }).catch(e => setStatus('Error: ' + e));
      setStatus('Settings saved');
      dlg.close();
    });
  }

  function _populateSettings(cfg) {
    const set = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };
    set('cfg-beacon-thresh',  cfg.beacon_min_connections);
    set('cfg-strobe-thresh',  cfg.strobe_min_connections);
    set('cfg-longconn',       cfg.long_conn_min_hours);
    set('cfg-exfil',          cfg.exfil_min_bytes_mb);
    set('cfg-nxdomain',       cfg.dns_nxdomain_threshold);
    set('cfg-tunnelbytes',    cfg.dns_tunnel_label_len);
    set('cfg-tunneldiv',      cfg.dns_unique_subdomain_min);
    set('cfg-vt-key',         cfg.virustotal_api_key);
    set('cfg-abuse-key',      cfg.abuseipdb_api_key);
    set('cfg-otx-key',        cfg.otx_api_key);
    set('cfg-crowdsec-key',   cfg.crowdsec_api_key);
  }

  function _collectSettings() {
    const g = id => { const el = document.getElementById(id); return el ? el.value : ''; };
    return {
      beacon_min_connections:   parseInt(g('cfg-beacon-thresh'))  || 10,
      strobe_min_connections:   parseInt(g('cfg-strobe-thresh'))  || 1000,
      long_conn_min_hours:      parseFloat(g('cfg-longconn'))     || 1.0,
      exfil_min_bytes_mb:       parseFloat(g('cfg-exfil'))        || 5.0,
      dns_nxdomain_threshold:   parseInt(g('cfg-nxdomain'))       || 200,
      dns_tunnel_label_len:     parseInt(g('cfg-tunnelbytes'))    || 40,
      dns_unique_subdomain_min: parseInt(g('cfg-tunneldiv'))      || 50,
      virustotal_api_key:       g('cfg-vt-key'),
      abuseipdb_api_key:        g('cfg-abuse-key'),
      otx_api_key:              g('cfg-otx-key'),
      crowdsec_api_key:         g('cfg-crowdsec-key'),
    };
  }

  // ── Watch mode ─────────────────────────────────────────────────────────────
  function _updateWatchUI(cfg) {
    const statusEl = document.getElementById('watch-status-label');
    const btn      = document.getElementById('watch-btn');
    if (!cfg) return;
    _watchActive = !!cfg.enabled;
    if (cfg.enabled) {
      const next = cfg.next_run || '';
      statusEl.textContent = next ? `Enabled — next run ${next}` : 'Enabled';
      statusEl.style.color = 'var(--accent)';
      if (btn) btn.textContent = 'Disable';
    } else {
      statusEl.textContent = 'Disabled';
      statusEl.style.color = 'var(--fg-dim)';
      if (btn) btn.textContent = 'Enable';
    }
    if (btn && cfg.time) {
      const timeInput = document.getElementById('watch-time');
      if (timeInput) timeInput.value = cfg.time;
    }
  }

  function initWatch() {
    const btn = document.getElementById('watch-btn');
    if (btn) {
      btn.addEventListener('click', async () => {
        const timeVal = (document.getElementById('watch-time').value || '').trim();
        const enabling = !_watchActive;
        if (enabling && !timeVal) { setStatus('Enter a time for the daily analysis'); return; }
        try {
          await api('/api/watch', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({time: timeVal, enabled: enabling}),
          });
          const cfg = await api('/api/watch');
          _updateWatchUI(cfg);
          setStatus(enabling ? `Watch enabled — daily analysis at ${timeVal} UTC` : 'Watch disabled');
        } catch(e) { setStatus('Watch error: ' + e); }
      });
    }

    api('/api/watch').then(cfg => _updateWatchUI(cfg)).catch(() => {});
  }

  // ── Context menu ───────────────────────────────────────────────────────────
  function initContextMenu() {
    const menu = document.getElementById('ctx-menu');

    function showMenu(e, f) {
      _ctxFinding = f;
      menu.style.left = Math.min(e.clientX, window.innerWidth - 220) + 'px';
      menu.style.top  = Math.min(e.clientY, window.innerHeight - 200) + 'px';
      menu.classList.remove('hidden');
    }

    document.addEventListener('click', () => menu.classList.add('hidden'));

    document.getElementById('ctx-pivot-src').addEventListener('click', () => {
      if (!_ctxFinding) return;
      document.getElementById('filter-search').value = _ctxFinding.src_ip || '';
      applyFilter();
    });
    document.getElementById('ctx-pivot-dst').addEventListener('click', () => {
      if (!_ctxFinding) return;
      document.getElementById('filter-search').value = _ctxFinding.dst_ip || '';
      applyFilter();
    });
    document.getElementById('ctx-pcap').addEventListener('click', () => {
      if (_ctxFinding) copyPCAP(_ctxFinding);
    });
    document.getElementById('ctx-copy-row').addEventListener('click', () => {
      if (!_ctxFinding) return;
      const f = _ctxFinding;
      navigator.clipboard.writeText(
        [f.score, f.severity, f.type, f.src_ip, f.dst_ip, f.dst_port, f.timestamp].join('\t')
      ).catch(() => {});
      showToast('Row copied');
    });
    document.getElementById('ctx-ack').addEventListener('click', () => {
      if (_ctxFinding) document.getElementById('ack-btn').click();
    });

    document.querySelectorAll('#ctx-supp-sub li[data-days]').forEach(li => {
      li.addEventListener('click', async () => {
        if (!_ctxFinding) return;
        const target = _ctxFinding.dst_ip || _ctxFinding.src_ip || '';
        if (!target) return;
        const detail = `${_ctxFinding.type} | ${_ctxFinding.severity} | ${_ctxFinding.src_ip || ''}→${_ctxFinding.dst_ip || ''}:${_ctxFinding.dst_port || ''}`;
        await api('/api/suppressions', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({target, days: parseFloat(li.dataset.days), detail}),
        }).catch(e => setStatus('Error: ' + e));
        setStatus(`Suppressed ${target} for ${li.dataset.days} day(s)`);
        loadFindings();
      });
    });

    // Add to Allowlist / IOC List
    async function _addToList(endpoint, label, ip, onSuccess) {
      if (!ip) return;
      try {
        const current = await api(endpoint);
        const entries = Array.isArray(current) ? current : [];
        if (entries.includes(ip)) { setStatus(`${ip} already in ${label}`); return; }
        entries.push(ip);
        await api(endpoint, {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(entries),
        });
        setStatus(`Added ${ip} to ${label}`);
        if (onSuccess) onSuccess();
      } catch (e) { setStatus(`Error: ${e}`); }
    }

    document.querySelectorAll('#ctx-allowlist-sub li[data-target]').forEach(li => {
      li.addEventListener('click', () => {
        if (!_ctxFinding) return;
        const ip = li.dataset.target === 'dst' ? _ctxFinding.dst_ip : _ctxFinding.src_ip;
        _addToList('/api/allowlist', 'Allowlist', ip, loadFindings);
      });
    });

    document.querySelectorAll('#ctx-ioc-sub li[data-target]').forEach(li => {
      li.addEventListener('click', () => {
        if (!_ctxFinding) return;
        const ip = li.dataset.target === 'dst' ? _ctxFinding.dst_ip : _ctxFinding.src_ip;
        _addToList('/api/ioc', 'IOC List', ip, _loadIOCList);
      });
    });

    // IOC browser lookups — open in new tab
    const _iocTarget = () => (_ctxFinding && (_ctxFinding.dst_ip || _ctxFinding.src_ip || ''));
    document.getElementById('ctx-vt').addEventListener('click', () => {
      const ioc = _iocTarget(); if (ioc) window.open(`https://www.virustotal.com/gui/search/${encodeURIComponent(ioc)}`, '_blank');
    });
    document.getElementById('ctx-abuseipdb').addEventListener('click', () => {
      const ioc = _iocTarget(); if (ioc) window.open(`https://www.abuseipdb.com/check/${encodeURIComponent(ioc)}`, '_blank');
    });
    document.getElementById('ctx-shodan').addEventListener('click', () => {
      const ioc = _iocTarget(); if (ioc) window.open(`https://www.shodan.io/search?query=${encodeURIComponent(ioc)}`, '_blank');
    });
    document.getElementById('ctx-crowdsec').addEventListener('click', () => {
      const ioc = _iocTarget(); if (ioc) window.open(`https://app.crowdsec.net/cti/${encodeURIComponent(ioc)}`, '_blank');
    });

    return showMenu;
  }

  // ── User management (admin only) ───────────────────────────────────────────
  function initUserManagement() {
    const dlg = document.getElementById('users-dialog');
    document.getElementById('users-btn').addEventListener('click', () => {
      _loadUsers();
      dlg.showModal();
    });
    document.getElementById('users-close').addEventListener('click', () => dlg.close());

    document.getElementById('create-user-btn').addEventListener('click', async () => {
      const firstName = document.getElementById('new-user-first').value.trim();
      const lastName  = document.getElementById('new-user-last').value.trim();
      const email     = document.getElementById('new-user-email').value.trim();
      const password  = document.getElementById('new-user-password').value;
      const role      = document.getElementById('new-user-role').value;
      const errEl     = document.getElementById('users-error');
      errEl.style.display = 'none';
      if (!firstName || !lastName) {
        errEl.textContent = 'First and last name are required.';
        errEl.style.display = 'block';
        return;
      }
      try {
        await api('/api/users', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({email, password, role, first_name: firstName, last_name: lastName}),
        });
        ['new-user-first','new-user-last','new-user-email','new-user-password'].forEach(id => {
          document.getElementById(id).value = '';
        });
        _loadUsers();
      } catch (e) {
        errEl.textContent = e || 'Failed to create user.';
        errEl.style.display = 'block';
      }
    });
  }

  async function _loadUsers() {
    const tbody = document.getElementById('users-tbody');
    tbody.innerHTML = '<tr><td colspan="5" style="color:var(--fg-dim);padding:10px">Loading…</td></tr>';
    try {
      const users = await api('/api/users');
      tbody.innerHTML = '';
      users.forEach(u => {
        const tr = document.createElement('tr');
        const isSelf = _currentUser && u.id === _currentUser.id;
        const roleOpts = ['admin','analyst','viewer'].map(r =>
          `<option value="${r}"${r === u.role ? ' selected' : ''}>${r.charAt(0).toUpperCase()+r.slice(1)}</option>`
        ).join('');
        tr.innerHTML = `
          <td style="font-weight:600">${_esc(u.first_name)} ${_esc(u.last_name)}</td>
          <td style="font-family:monospace;font-size:11px">${_esc(u.email)}</td>
          <td>
            ${isSelf
              ? `<span class="role-badge ${u.role}">${u.role}</span>`
              : `<select class="user-role-select" data-uid="${u.id}">${roleOpts}</select>`}
          </td>
          <td style="font-size:11px;color:var(--fg-dim)">${(u.created_at||'').split(' ')[0]}</td>
          <td>${isSelf ? '' : `<button class="user-delete-btn" data-uid="${u.id}">Delete</button>`}</td>`;
        tbody.appendChild(tr);
      });

      // Role change handlers
      tbody.querySelectorAll('.user-role-select').forEach(sel => {
        sel.addEventListener('change', async () => {
          const uid = parseInt(sel.dataset.uid);
          try {
            await api(`/api/users/${uid}`, {
              method: 'PATCH',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({role: sel.value}),
            });
          } catch (e) { setStatus('Role update failed: ' + e); _loadUsers(); }
        });
      });

      // Delete handlers
      tbody.querySelectorAll('.user-delete-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
          const uid = parseInt(btn.dataset.uid);
          if (!confirm('Delete this user? This cannot be undone.')) return;
          try {
            await api(`/api/users/${uid}`, {method: 'DELETE'});
            _loadUsers();
          } catch (e) { setStatus('Delete failed: ' + e); }
        });
      });
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="5" style="color:var(--sev-critical)">Failed to load users</td></tr>`;
    }
  }

  function _esc(s) {
    return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  // ── Init ───────────────────────────────────────────────────────────────────
  function init() {
    const showMenu = initContextMenu();

    Table.init(
      f => { _selectedFinding = f; Detail.render(f); },
      (e, f) => showMenu(e, f)
    );

    Campaigns.init((e, pseudo) => showMenu(e, pseudo));

    Notifications.init(findingId => {
      const f = _allFindings.find(x => x.id === findingId);
      // Switch to the right tab for this finding's status
      const status = f ? f.status : '';
      let targetTab = 'findings';
      if (status === 'acknowledged') targetTab = 'ack';
      if (status === 'escalated')    targetTab = 'esc';
      document.querySelector(`.tab-btn[data-tab="${targetTab}"]`).click();
      if (f) {
        _selectedFinding = f;
        Detail.render(f);
        Table.jumpTo(f.id);
      }
    });

    // Fetch current user for display, note authorship, and role-gating
    api('/api/me').then(u => {
      _currentUser = u;
      const el = document.getElementById('user-display');
      if (el) el.textContent = u.display || u.email || '';
      if (u.role === 'admin') {
        document.getElementById('users-btn').style.display = '';
        const wac = document.getElementById('watch-admin-controls');
        if (wac) wac.style.display = '';
      }
      // Hide write-only controls for viewers
      if (u.role === 'viewer') {
        ['import-logs-btn','clear-files-btn','analyze-btn','allowlist-btn','ioc-btn','suppressions-btn',
         'ack-btn','esc-btn','supp-btn','add-note-btn'].forEach(id => {
          const el = document.getElementById(id);
          if (el) el.style.display = 'none';
        });
      }
      // Hide settings button and watch controls for non-admins
      if (u.role !== 'admin') {
        const sb = document.getElementById('settings-btn');
        if (sb) sb.style.display = 'none';
      }
    }).catch(() => {});

    initUserManagement();

    BeaconChart.init();
    initTabs();
    initFilterBar();
    initDeltaBar();
    initUpload();
    initAnalyze();
    initDetailActions();
    initSuppressDialog();
    initSuppressionsManager();
    initListDialogs();
    initSettings();
    initWatch();
    initSSE();

    // Init column resizing — use requestAnimationFrame so the browser has
    // rendered the tables and computed their widths before we lock them in
    requestAnimationFrame(() => {
      ColResize.init('findings-table');
      ColResize.init('campaigns-table');
      ColResize.init('hosts-table');
    });

    DlgManager.init();

    _loadIOCList();
    loadFindings()
      .then(() => _updateTIStatus())
      .catch(() => setStatus('Ready — click Import then Analyze'));
    setStatus('Ready');
  }

  init();
})();
