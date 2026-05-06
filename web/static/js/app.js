// app.js — main application state machine
'use strict';

(async () => {

  // ── State ──────────────────────────────────────────────────────────────────
  let _allFindings     = [];
  let _deltaMode       = false;
  let _selectedFinding = null;
  let _ctxFinding      = null;
  let _watchActive     = false;
  let _tabMode         = 'findings'; // 'findings' | 'ack' | 'esc' | 'ioc' (drives findings-table filter)
  let _activeTab       = 'findings'; // 'findings' | 'ack' | 'esc' | 'ioc' | 'campaigns' | 'hosts' (which panel is visible)
  let _iocSet          = new Set();  // live cache of IOC list IPs for instant tab overlay
  let _allowSet        = new Set();  // live cache of allowlist entries — used by the right-click menu's state-aware items
  let _logsDir         = '/logs';
  let _currentUser     = null;
  let _orgCIDRs        = []; // admin-supplied CIDRs that augment the built-in private ranges for the Hosts tab

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

  // navigator.clipboard is only available in secure contexts (HTTPS or
  // localhost). When the UI is reached over plain HTTP on a remote host
  // (common for on-prem deployments), the API is undefined and any direct
  // call throws synchronously — the .catch on the (never-returned) Promise
  // can't swallow it. Try the modern API first, fall back to a hidden
  // textarea + execCommand which works in non-secure contexts.
  function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).catch(() => _legacyCopy(text));
      return true;
    }
    return _legacyCopy(text);
  }

  function _legacyCopy(text) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.top = '0';
      ta.style.left = '0';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      ta.setSelectionRange(0, text.length);
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch (_) { return false; }
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
    _updateSensorFilter(_allFindings);
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

  // Fetch allowlist into _allowSet. Unlike _iocSet which drives a tab
  // filter, _allowSet exists purely so the right-click menu can grey out
  // "Add <IP> to Allowlist" when the target's already on the list.
  async function _loadAllowSet() {
    try {
      const data = await api('/api/allowlist');
      _allowSet = new Set(Array.isArray(data) ? data : []);
    } catch (_) {}
  }

  // ── Tabs ───────────────────────────────────────────────────────────────────
  function initTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        _activeTab = tab;

        const findingsTab = tab === 'findings' || tab === 'ack' || tab === 'esc' || tab === 'ioc';
        if (findingsTab) {
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
      ['filter-search','filter-src','filter-dst','filter-port','filter-from','filter-to'].forEach(id => {
        const el = document.getElementById(id); if (el) el.value = '';
      });
      document.getElementById('filter-sev').value = '';
      document.getElementById('filter-type').value = '';
      document.getElementById('filter-sensor').value = '';
      document.getElementById('filter-score').value = '0';
      _applyTabFilter();
    });
    ['filter-search','filter-src','filter-dst','filter-port','filter-from','filter-to'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('keydown', e => { if (e.key === 'Enter') applyFilter(); });
    });

    // "Export current tab" dispatches on the active tab. Findings-style
    // tabs go through the server (server-side filters apply); Campaigns
    // and Hosts are aggregations built client-side, so we serialize the
    // in-memory rows directly.
    _initExportDropdown('export-current-btn', 'export-current-menu', format => {
      switch (_activeTab) {
        case 'campaigns':
          if (format === 'csv') _downloadCampaignsCSV(Campaigns.getCampaigns());
          else                  _downloadCampaignsJSON(Campaigns.getCampaigns());
          return;
        case 'hosts':
          if (format === 'csv') _downloadHostsCSV(Campaigns.getHosts());
          else                  _downloadHostsJSON(Campaigns.getHosts());
          return;
        default:
          window.location.href = `/api/export/${format}?${_exportQSForCurrentTab()}`;
      }
    });
    _initExportDropdown('export-all-btn', 'export-all-menu', format => {
      window.location.href = `/api/export/${format}`;
    });
    // Close any open export menu when clicking outside it. The button
    // handler's stopPropagation prevents this from firing on its own click.
    document.addEventListener('click', () => {
      document.querySelectorAll('.export-menu').forEach(m => m.classList.add('hidden'));
    });

    // Advanced-filters toggle. Remembered in localStorage so the panel stays
    // in whatever state the analyst left it in across page reloads.
    const advToggle = document.getElementById('filter-advanced-toggle');
    const advPanel  = document.getElementById('filter-bar-advanced');
    const setAdv = open => {
      advPanel.style.display = open ? 'flex' : 'none';
      advToggle.classList.toggle('active', open);
      advToggle.textContent = open ? 'Advanced ▴' : 'Advanced ▾';
      try { localStorage.setItem('archer.filter.advanced', open ? '1' : '0'); } catch (e) {}
    };
    advToggle.addEventListener('click', () => setAdv(advPanel.style.display === 'none'));
    try {
      if (localStorage.getItem('archer.filter.advanced') === '1') setAdv(true);
    } catch (e) {}
  }

  // Build the query string representing the current filter state. Shared by
  // applyFilter (for /api/findings) and the export buttons so the exported
  // file matches the on-screen view exactly.
  function _currentFilterParams() {
    const g = id => (document.getElementById(id) || {}).value || '';
    const params = {};
    const search = g('filter-search').trim();
    if (search) params.search = search;
    const sev = g('filter-sev');   if (sev)  params.severity = sev;
    const type = g('filter-type'); if (type) params.type = type;
    const score = parseInt(g('filter-score')) || 0;
    if (score > 0) params.min_score = score;
    const src = g('filter-src').trim(); if (src) params.src_ip = src;
    const dst = g('filter-dst').trim(); if (dst) params.dst_ip = dst;
    const port = g('filter-port').trim(); if (port) params.dst_port = port;
    const sn  = g('filter-sensor');     if (sn)  params.sensor = sn;
    const from = g('filter-from');      if (from) params.from = from;
    const to   = g('filter-to');        if (to)   params.to   = to;
    return params;
  }

  function _currentFilterQS() {
    const p = _currentFilterParams();
    return Object.keys(p).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(p[k])}`).join('&');
  }

  // Like _currentFilterQS but also adds a tab-aware status / ioc_only filter
  // so "Export current view" matches what the active tab is showing.
  function _exportQSForCurrentTab() {
    const p = _currentFilterParams();
    if (_tabMode === 'ack') p.status = 'acknowledged';
    else if (_tabMode === 'esc') p.status = 'escalated';
    else if (_tabMode === 'ioc') p.ioc_only = 'true';
    else p.status = 'open'; // default 'findings' tab
    if (_deltaMode) p.delta = 'true';
    return Object.keys(p).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(p[k])}`).join('&');
  }

  // ── Client-side export helpers (Campaigns / Hosts) ─────────────────────────
  // CSV escaping per RFC 4180: wrap fields containing comma, quote, CR, or LF
  // in double quotes; double up internal quotes.
  function _csvField(v) {
    const s = v == null ? '' : String(v);
    if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }
  function _csvRow(fields) { return fields.map(_csvField).join(',') + '\r\n'; }

  // Wires up a small dropdown menu next to a trigger button. Each <li>
  // inside the menu carries a data-format attribute; clicking it invokes
  // onSelect(format) — the caller decides whether to navigate to a server
  // URL (for streamed exports via Content-Disposition) or to build the
  // payload client-side and trigger a Blob download. Clicking the trigger
  // toggles the menu and closes any sibling menus that happen to be open.
  function _initExportDropdown(buttonId, menuId, onSelect) {
    const btn = document.getElementById(buttonId);
    const menu = document.getElementById(menuId);
    if (!btn || !menu) return;
    btn.addEventListener('click', e => {
      e.stopPropagation();
      if (btn.disabled) return;
      document.querySelectorAll('.export-menu').forEach(m => {
        if (m !== menu) m.classList.add('hidden');
      });
      menu.classList.toggle('hidden');
    });
    menu.querySelectorAll('li[data-format]').forEach(li => {
      li.addEventListener('click', () => {
        onSelect(li.dataset.format);
        menu.classList.add('hidden');
      });
    });
  }

  function _downloadBlob(filename, mime, content) {
    const blob = new Blob([content], {type: mime + ';charset=utf-8'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function _ts() {
    const d = new Date();
    const z = n => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}${z(d.getUTCMonth()+1)}${z(d.getUTCDate())}_${z(d.getUTCHours())}${z(d.getUTCMinutes())}${z(d.getUTCSeconds())}`;
  }

  function _campaignToRow(c) {
    return {
      destination: c.dst,
      port: c.port,
      hosts: c.srcs.size,
      max_score: c.maxScore,
      source_ips: [...c.srcs].join(' '),
      finding_types: [...c.types].join(' '),
    };
  }

  function _downloadCampaignsCSV(campaigns) {
    const header = ['destination','port','hosts','max_score','source_ips','finding_types'];
    let out = _csvRow(header);
    campaigns.forEach(c => {
      const r = _campaignToRow(c);
      out += _csvRow(header.map(h => r[h]));
    });
    _downloadBlob(`archer_campaigns_${_ts()}.csv`, 'text/csv', out);
  }

  function _downloadCampaignsJSON(campaigns) {
    const out = JSON.stringify({
      archer_version: '3.0.0-go',
      saved_at: new Date().toISOString(),
      campaigns: campaigns.map(_campaignToRow),
    }, null, 2);
    _downloadBlob(`archer_campaigns_${_ts()}.json`, 'application/json', out);
  }

  // Single-campaign export uses an edge-list shape: one row per source IP,
  // with the campaign's destination as the shared target. This is what
  // Gephi Lite and other graph viewers consume directly to render
  // hub-and-spoke topology — the destination becomes the hub node and each
  // source becomes a spoke. Capitalised "Source" / "Target" column names
  // are Gephi's convention; other tools accept them too.
  function _safeFilenamePart(s) {
    return String(s || 'campaign').replace(/[^A-Za-z0-9._-]/g, '_');
  }

  // Two-step graph export. The dropdown picks the format ("png" | "jpeg")
  // and stashes it; a follow-up scope dialog asks current-viewport vs full
  // graph and only then runs the actual cy.png/jpg + download. Splitting it
  // keeps the dropdown menu short and the scope choice deliberate.
  let _pendingGraphExportFormat = null;

  function _exportGraphImage(format) {
    const cy = (typeof Graph !== 'undefined') ? Graph.getCy() : null;
    if (!cy) return;
    _pendingGraphExportFormat = format;
    document.getElementById('graph-export-scope-dlg').showModal();
  }

  function _commitGraphExport(full) {
    const dlg = document.getElementById('graph-export-scope-dlg');
    if (dlg && dlg.open) dlg.close();
    const cy = (typeof Graph !== 'undefined') ? Graph.getCy() : null;
    const type = _pendingGraphExportFormat;
    _pendingGraphExportFormat = null;
    if (!cy || !type) return;
    const isJpeg = type === 'jpeg';
    const ext = isJpeg ? 'jpg' : 'png';
    const opts = {
      output: 'blob',
      // bg is mandatory for JPEG (no alpha channel) and matches the dialog
      // canvas for PNG so transparent regions don't read as washed-out white.
      bg: '#0a0e15',
      full: !!full,
      // 2x scale produces a retina-quality export without bloating the file
      // beyond what's reasonable for the typical campaign graph size.
      scale: 2,
    };
    if (isJpeg) opts.quality = 0.95;
    const blob = isJpeg ? cy.jpg(opts) : cy.png(opts);
    const dst = (typeof Graph !== 'undefined' && Graph.getDstHint()) || 'graph';
    const filename = `archer_graph_${_safeFilenamePart(dst)}_campaign_${_ts()}.${ext}`;
    // Sidestep _downloadBlob — it's tuned for text payloads and appends
    // ;charset=utf-8 to the MIME, which is wrong for image bytes.
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function _downloadCampaignEdgesCSV(campaign) {
    const types = [...campaign.types].join(' ');
    const header = ['Source', 'Target', 'Port', 'MaxScore', 'FindingTypes'];
    let out = _csvRow(header);
    [...campaign.srcs].forEach(src => {
      out += _csvRow([src, campaign.dst, campaign.port, campaign.maxScore, types]);
    });
    _downloadBlob(
      `archer_campaign_${_safeFilenamePart(campaign.dst)}_${_ts()}.csv`,
      'text/csv',
      out,
    );
  }

  function _downloadCampaignEdgesJSON(campaign) {
    // Graphology serialization format consumable by Gephi Lite. Mirrors the
    // canonical sample at gephi/gephi-lite (testGraphs/graphology.json):
    // {attributes, nodes, edges} only — no `options` block, since Gephi
    // Lite's import path doesn't expect it and including it has caused
    // "Graph.import: invalid nodes" errors on import. The destination IP
    // is a single hub node; each source IP is a spoke; one edge per source.
    const types = [...campaign.types].join(' ');
    const dst = String(campaign.dst);
    const port = campaign.port;
    const maxScore = campaign.maxScore;
    const sources = [...campaign.srcs];

    const nodes = [
      {
        key: dst,
        attributes: {
          label: `${dst}:${port}`,
          kind: 'destination',
          max_score: maxScore,
        },
      },
      ...sources.map(src => ({
        key: src,
        attributes: {
          label: src,
          kind: 'source',
        },
      })),
    ];

    const edges = sources.map(src => ({
      key: `${src}->${dst}:${port}`,
      source: src,
      target: dst,
      attributes: {
        port: port,
        max_score: maxScore,
        finding_types: types,
      },
    }));

    const graphology = {
      attributes: {
        name: `Archer Campaign - ${dst}:${port}`,
        destination: dst,
        port: port,
        max_score: maxScore,
        finding_types: types,
        archer_version: '3.0.0-go',
        saved_at: new Date().toISOString(),
      },
      nodes,
      edges,
    };

    _downloadBlob(
      `archer_campaign_${_safeFilenamePart(campaign.dst)}_${_ts()}.json`,
      'application/json',
      JSON.stringify(graphology, null, 2),
    );
  }

  // XML escape used by the GEXF and GraphML emitters. Wraps every value
  // that lands in attribute or text positions; safe for IPs/labels.
  function _xmlEscape(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function _downloadCampaignEdgesGEXF(campaign) {
    const types = [...campaign.types].join(' ');
    const dst = String(campaign.dst);
    const port = campaign.port;
    const maxScore = campaign.maxScore;
    const sources = [...campaign.srcs];
    const today = new Date().toISOString().slice(0, 10);

    const lines = [];
    lines.push('<?xml version="1.0" encoding="UTF-8"?>');
    lines.push('<gexf xmlns="http://gexf.net/1.3" version="1.3">');
    lines.push(`  <meta lastmodifieddate="${today}">`);
    lines.push('    <creator>Archer</creator>');
    lines.push(`    <description>Archer campaign export — ${_xmlEscape(dst)}:${port}</description>`);
    lines.push('  </meta>');
    lines.push('  <graph mode="static" defaultedgetype="directed">');
    lines.push('    <attributes class="node">');
    lines.push('      <attribute id="kind" title="kind" type="string"/>');
    lines.push('    </attributes>');
    lines.push('    <attributes class="edge">');
    lines.push('      <attribute id="port" title="port" type="integer"/>');
    lines.push('      <attribute id="max_score" title="max_score" type="integer"/>');
    lines.push('      <attribute id="finding_types" title="finding_types" type="string"/>');
    lines.push('    </attributes>');
    lines.push('    <nodes>');
    lines.push(`      <node id="${_xmlEscape(dst)}" label="${_xmlEscape(dst + ':' + port)}">`);
    lines.push('        <attvalues>');
    lines.push('          <attvalue for="kind" value="destination"/>');
    lines.push('        </attvalues>');
    lines.push('      </node>');
    sources.forEach(src => {
      lines.push(`      <node id="${_xmlEscape(src)}" label="${_xmlEscape(src)}">`);
      lines.push('        <attvalues>');
      lines.push('          <attvalue for="kind" value="source"/>');
      lines.push('        </attvalues>');
      lines.push('      </node>');
    });
    lines.push('    </nodes>');
    lines.push('    <edges>');
    sources.forEach((src, i) => {
      lines.push(`      <edge id="e${i}" source="${_xmlEscape(src)}" target="${_xmlEscape(dst)}">`);
      lines.push('        <attvalues>');
      lines.push(`          <attvalue for="port" value="${port}"/>`);
      lines.push(`          <attvalue for="max_score" value="${maxScore}"/>`);
      lines.push(`          <attvalue for="finding_types" value="${_xmlEscape(types)}"/>`);
      lines.push('        </attvalues>');
      lines.push('      </edge>');
    });
    lines.push('    </edges>');
    lines.push('  </graph>');
    lines.push('</gexf>');

    _downloadBlob(
      `archer_campaign_${_safeFilenamePart(campaign.dst)}_${_ts()}.gexf`,
      'application/xml',
      lines.join('\n'),
    );
  }

  function _downloadCampaignEdgesGraphML(campaign) {
    const types = [...campaign.types].join(' ');
    const dst = String(campaign.dst);
    const port = campaign.port;
    const maxScore = campaign.maxScore;
    const sources = [...campaign.srcs];

    const lines = [];
    lines.push('<?xml version="1.0" encoding="UTF-8"?>');
    lines.push('<graphml xmlns="http://graphml.graphdrawing.org/xmlns"');
    lines.push('         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"');
    lines.push('         xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">');
    lines.push('  <key id="kind" for="node" attr.name="kind" attr.type="string"/>');
    lines.push('  <key id="label" for="node" attr.name="label" attr.type="string"/>');
    lines.push('  <key id="port" for="edge" attr.name="port" attr.type="int"/>');
    lines.push('  <key id="max_score" for="edge" attr.name="max_score" attr.type="int"/>');
    lines.push('  <key id="finding_types" for="edge" attr.name="finding_types" attr.type="string"/>');
    lines.push('  <graph id="G" edgedefault="directed">');
    lines.push(`    <node id="${_xmlEscape(dst)}">`);
    lines.push('      <data key="kind">destination</data>');
    lines.push(`      <data key="label">${_xmlEscape(dst + ':' + port)}</data>`);
    lines.push('    </node>');
    sources.forEach(src => {
      lines.push(`    <node id="${_xmlEscape(src)}">`);
      lines.push('      <data key="kind">source</data>');
      lines.push(`      <data key="label">${_xmlEscape(src)}</data>`);
      lines.push('    </node>');
    });
    sources.forEach((src, i) => {
      lines.push(`    <edge id="e${i}" source="${_xmlEscape(src)}" target="${_xmlEscape(dst)}">`);
      lines.push(`      <data key="port">${port}</data>`);
      lines.push(`      <data key="max_score">${maxScore}</data>`);
      lines.push(`      <data key="finding_types">${_xmlEscape(types)}</data>`);
      lines.push('    </edge>');
    });
    lines.push('  </graph>');
    lines.push('</graphml>');

    _downloadBlob(
      `archer_campaign_${_safeFilenamePart(campaign.dst)}_${_ts()}.graphml`,
      'application/xml',
      lines.join('\n'),
    );
  }

  function _downloadSingleCampaign(format, campaign) {
    switch (format) {
      case 'csv':              _downloadCampaignEdgesCSV(campaign); break;
      case 'graphology-json':  _downloadCampaignEdgesJSON(campaign); break;
      case 'gexf':             _downloadCampaignEdgesGEXF(campaign); break;
      case 'graphml':          _downloadCampaignEdgesGraphML(campaign); break;
    }
  }

  function _hostToRow(h) {
    return {
      host_ip: h.ip,
      risk_score: h.score,
      findings: h.count,
      severity: h.topSev,
      finding_types: [...h.types].join(' '),
    };
  }

  function _downloadHostsCSV(hosts) {
    const header = ['host_ip','risk_score','findings','severity','finding_types'];
    let out = _csvRow(header);
    hosts.forEach(h => {
      const r = _hostToRow(h);
      out += _csvRow(header.map(c => r[c]));
    });
    _downloadBlob(`archer_hosts_${_ts()}.csv`, 'text/csv', out);
  }

  function _downloadHostsJSON(hosts) {
    const out = JSON.stringify({
      archer_version: '3.0.0-go',
      saved_at: new Date().toISOString(),
      hosts: hosts.map(_hostToRow),
    }, null, 2);
    _downloadBlob(`archer_hosts_${_ts()}.json`, 'application/json', out);
  }

  function applyFilter() {
    loadFindings(_currentFilterParams());
  }

  // Populate the Sensor filter dropdown from the distinct sensors present
  // in the current findings list.
  function _updateSensorFilter(findings) {
    const sel = document.getElementById('filter-sensor');
    if (!sel) return;
    const current = sel.value;
    const sensors = [...new Set((findings || []).map(f => f.sensor).filter(Boolean))].sort();
    while (sel.options.length > 1) sel.remove(1);
    sensors.forEach(s => {
      const o = document.createElement('option');
      o.value = s; o.textContent = s;
      sel.appendChild(o);
    });
    if (sensors.includes(current)) sel.value = current;
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
    const bySensor = new Map();
    files.forEach(p => {
      const parts    = p.replace(/\\/g, '/').split('/').filter(Boolean);
      const relParts = parts.slice(dirParts.length);
      const sensor   = relParts.length >= 2 ? relParts[0] : '(root)';
      const name     = parts[parts.length - 1];
      if (!bySensor.has(sensor)) bySensor.set(sensor, []);
      bySensor.get(sensor).push({name, path: p});
    });

    if (bySensor.size === 0) {
      const li = document.createElement('li');
      li.textContent = 'No files — click Import';
      li.style.fontStyle = 'italic';
      ul.appendChild(li);
      return;
    }

    bySensor.forEach((entries, sensor) => {
      const hdr = document.createElement('li');
      hdr.textContent = `📁 ${sensor} (${entries.length})`;
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
      document.getElementById('pause-btn').textContent = 'Pause';
    }
  }

  async function _syncAnalyzeState() {
    try {
      const s = await api('/api/analyze/status');
      if (s.running) {
        _setAnalyzing(true);
        if (s.paused) {
          _paused = true;
          document.getElementById('pause-btn').textContent = 'Resume';
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
          document.getElementById('pause-btn').textContent = 'Pause';
          setStatus('Analysis resumed…');
        } else {
          await api('/api/analyze/pause', {method: 'POST'});
          _paused = true;
          document.getElementById('pause-btn').textContent = 'Resume';
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
  // Full standard Zeek schema per log type. Columns the record doesn't carry
  // render as blank cells. Analyst can resize any column to read long values
  // (uid, uri, ja3) by dragging the right edge of its header.
  const RAW_COLUMNS = {
    conn: [
      'ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service',
      'duration','orig_bytes','resp_bytes','conn_state','local_orig','local_resp',
      'missed_bytes','history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes',
      'tunnel_parents','community_id','vlan','inner_vlan','_source_file',
    ],
    http: [
      'ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','trans_depth',
      'method','host','uri','referrer','version','user_agent','origin',
      'request_body_len','response_body_len','status_code','status_msg',
      'info_code','info_msg','tags','username','password','proxied',
      'orig_fuids','orig_filenames','orig_mime_types',
      'resp_fuids','resp_filenames','resp_mime_types','_source_file',
    ],
    dns: [
      'ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto',
      'trans_id','rtt','query','qclass','qclass_name','qtype','qtype_name',
      'rcode','rcode_name','AA','TC','RD','RA','Z','answers','TTLs','rejected',
      '_source_file',
    ],
    ssl: [
      'ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','version','cipher',
      'curve','server_name','resumed','last_alert','next_protocol','established',
      'cert_chain_fuids','client_cert_chain_fuids','subject','issuer',
      'client_subject','client_issuer','validation_status','ja3','ja3s',
      '_source_file',
    ],
    x509: [
      'ts','id','certificate.version','certificate.serial','certificate.subject',
      'certificate.issuer','certificate.not_valid_before','certificate.not_valid_after',
      'certificate.key_alg','certificate.sig_alg','certificate.key_type',
      'certificate.key_length','certificate.exponent','certificate.curve',
      'san.dns','san.uri','san.email','san.ip','basic_constraints.ca',
      'basic_constraints.path_len','_source_file',
    ],
    files: [
      'ts','fuid','tx_hosts','rx_hosts','conn_uids','source','depth','analyzers',
      'mime_type','filename','duration','local_orig','is_orig','seen_bytes',
      'total_bytes','missing_bytes','overflow_bytes','timedout','parent_fuid',
      'md5','sha1','sha256','extracted','_source_file',
    ],
    weird: ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','name','addl','notice','peer','_source_file'],
    notice: [
      'ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','fuid','file_mime_type',
      'file_desc','proto','note','msg','sub','src','dst','p','n',
      'peer_descr','actions','suppress_for','_source_file',
    ],
  };
  const RAW_DEFAULT_COLS = ['ts','uid','id.orig_h','id.resp_h','id.resp_p','_source_file'];

  // Per-column starting width in pixels. Anything not listed uses the default.
  const RAW_COL_WIDTH = {
    ts: 110, uid: 150, query: 240, uri: 260, host: 180, user_agent: 260,
    server_name: 200, ja3: 280, ja3s: 280, answers: 260, history: 90,
    'certificate.subject': 280, 'certificate.issuer': 280, filename: 220,
    md5: 280, sha1: 280, sha256: 280, _source_file: 260,
  };
  const RAW_COL_WIDTH_DEFAULT = 120;

  // The currently-loaded raw records, kept in scope so the Export CSV button
  // can serialize them without re-fetching. Reset on every new fetch.
  let _lastRawRecords = [];
  let _lastRawFindingId = null;

  async function _showRawRecords(f) {
    const dlg    = document.getElementById('raw-dialog');
    const title  = document.getElementById('raw-dlg-title');
    const status = document.getElementById('raw-dlg-status');
    const body   = document.getElementById('raw-dlg-table');
    const winSel = document.getElementById('raw-dlg-window');
    title.textContent = `Source Records — ${f.type} — ${f.src_ip} → ${f.dst_ip}`;
    dlg.dataset.findingId = f.id;
    // Open the dialog before fetching so its in-body "Scanning logs…" status
    // is visible immediately during the scan.
    dlg.showModal();
    await _fetchRawRecords(f.id);
  }

  async function _fetchRawRecords(findingId) {
    const status = document.getElementById('raw-dlg-status');
    const body   = document.getElementById('raw-dlg-table');
    const winSel = document.getElementById('raw-dlg-window');
    const exportBtn = document.getElementById('raw-dlg-export');
    const window_hours = winSel ? winSel.value : '6';
    status.textContent = 'Scanning logs…';
    body.innerHTML = '';
    _lastRawRecords = [];
    _lastRawFindingId = findingId;
    if (exportBtn) exportBtn.disabled = true;
    try {
      const resp = await api(`/api/findings/${findingId}/raw?limit=500&window_hours=${encodeURIComponent(window_hours)}`);
      const records  = resp.records || [];
      const logTypes = resp.log_types || [];
      if (records.length === 0) {
        status.textContent = `No matching records in ${logTypes.join(', ')} logs. Source files may have been archived or rotated.`;
        return;
      }
      _lastRawRecords = records;
      if (exportBtn) exportBtn.disabled = false;
      // Group records by log type so the table stays aligned per section
      const byType = {};
      records.forEach(r => {
        const t = r._log_type || 'unknown';
        (byType[t] = byType[t] || []).push(r);
      });
      status.textContent =
        `${records.length} record${records.length === 1 ? '' : 's'} from ${logTypes.join(', ')} ` +
        `log${logTypes.length === 1 ? '' : 's'}${resp.truncated ? ' (truncated at ' + resp.limit + ')' : ''}.`;
      body.innerHTML = '';
      for (const [logType, recs] of Object.entries(byType)) {
        const cols = RAW_COLUMNS[logType] || RAW_DEFAULT_COLS;
        const sec = document.createElement('div');
        sec.style.marginBottom = '14px';
        sec.innerHTML = `<div style="font-weight:bold;margin:6px 0;color:var(--accent)">${logType} — ${recs.length} record(s)</div>`;
        const tbl = _buildRawTable(cols, recs);
        sec.appendChild(tbl);
        body.appendChild(sec);
      }
    } catch (e) {
      status.textContent = 'Error fetching records: ' + e;
    }
  }

  // Flatten all currently-loaded raw records to a single CSV. Different log
  // types have different column sets, so we use the union of every key seen
  // and prepend _log_type so analysts can split the result back out per
  // log type in their tool of choice. RAW_COLUMNS supplies a stable column
  // order per log type — we walk records in their existing grouping so the
  // CSV preserves that ordering naturally.
  function _exportRawRecordsCSV() {
    if (!_lastRawRecords || _lastRawRecords.length === 0) return;
    const seen = new Set();
    const cols = ['_log_type'];
    seen.add('_log_type');
    // Preserve canonical Zeek column order per log type before falling back
    // to whatever else the records contain. Keeps ts/uid/id.* in their usual
    // positions instead of an arbitrary first-seen order.
    const types = new Set(_lastRawRecords.map(r => r._log_type || 'unknown'));
    types.forEach(t => {
      const canon = RAW_COLUMNS[t] || RAW_DEFAULT_COLS;
      canon.forEach(c => { if (!seen.has(c)) { seen.add(c); cols.push(c); } });
    });
    _lastRawRecords.forEach(r => {
      Object.keys(r).forEach(k => { if (!seen.has(k)) { seen.add(k); cols.push(k); } });
    });

    let csv = _csvRow(cols);
    _lastRawRecords.forEach(r => {
      const row = cols.map(c => {
        if (c === '_log_type') return r._log_type || '';
        const v = r[c];
        // Zeek records can carry array fields (e.g. answers, TTLs); join those
        // with comma to keep the cell single-valued.
        if (Array.isArray(v)) return v.join(',');
        return v;
      });
      csv += _csvRow(row);
    });
    const fname = `archer_source_records_${_lastRawFindingId || 'unknown'}_${_ts()}.csv`;
    _downloadBlob(fname, 'text/csv', csv);
  }

  // _buildRawTable renders one log-type section of the Source Records dialog.
  // Each header cell has a right-edge resize handle; dragging sets the <th>'s
  // inline width, which table-layout:fixed honors across the whole column.
  function _buildRawTable(cols, recs) {
    const tbl = document.createElement('table');
    tbl.className = 'raw-table';
    const colgroup = document.createElement('colgroup');
    cols.forEach(c => {
      const col = document.createElement('col');
      col.style.width = (RAW_COL_WIDTH[c] || RAW_COL_WIDTH_DEFAULT) + 'px';
      colgroup.appendChild(col);
    });
    tbl.appendChild(colgroup);

    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    cols.forEach((c, idx) => {
      const th = document.createElement('th');
      th.textContent = c;
      th.title = c;
      const handle = document.createElement('span');
      handle.className = 'col-resizer';
      th.appendChild(handle);
      _attachColumnResize(handle, colgroup.children[idx]);
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    tbl.appendChild(thead);

    const tbody = document.createElement('tbody');
    recs.forEach(r => {
      const tr = document.createElement('tr');
      cols.forEach(c => {
        const v = r[c];
        const text = v == null ? '' : (typeof v === 'object' ? JSON.stringify(v) : String(v));
        const td = document.createElement('td');
        td.textContent = text;
        td.title = text;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    return tbl;
  }

  // Drag a <col> element wider / narrower. Operates on the colgroup entry so
  // both the <th> and every <td> in the column resize together under
  // table-layout:fixed.
  function _attachColumnResize(handle, colEl) {
    handle.addEventListener('mousedown', e => {
      e.preventDefault();
      e.stopPropagation();
      handle.classList.add('resizing');
      const startX = e.pageX;
      const startWidth = colEl.getBoundingClientRect().width;
      const onMove = ev => {
        const w = Math.max(40, startWidth + ev.pageX - startX);
        colEl.style.width = w + 'px';
      };
      const onUp = () => {
        handle.classList.remove('resizing');
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      };
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  }

  function initDetailActions() {
    const rawBtn = document.getElementById('raw-btn');
    if (rawBtn) {
      rawBtn.addEventListener('click', () => {
        if (_selectedFinding) _showRawRecords(_selectedFinding);
      });
    }
    const rawClose = document.getElementById('raw-dlg-close');
    if (rawClose) {
      rawClose.addEventListener('click', () => {
        document.getElementById('raw-dialog').close();
      });
    }
    const rawWin = document.getElementById('raw-dlg-window');
    if (rawWin) {
      rawWin.addEventListener('change', () => {
        const id = document.getElementById('raw-dialog').dataset.findingId;
        if (id) _fetchRawRecords(parseInt(id, 10));
      });
    }
    const rawExport = document.getElementById('raw-dlg-export');
    if (rawExport) {
      rawExport.addEventListener('click', () => _exportRawRecordsCSV());
    }

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

      const hasService = svcs.vt || svcs.crowdsec || svcs.otx || svcs.abuseipdb || svcs.greynoise || svcs.censys;

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
      if (svcs.greynoise) _escSvcOpts.appendChild(_mkCheck('esc-svc-greynoise', 'GreyNoise',  true));
      if (svcs.censys)    _escSvcOpts.appendChild(_mkCheck('esc-svc-censys',    'Censys',     true));

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
        if (_checked('esc-svc-greynoise')) services.push('greynoise');
        if (_checked('esc-svc-censys'))    services.push('censys');
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

    // Export the selected finding's notes as a plain-text file. Pure
    // client-side: notes are already loaded with the finding payload, so
    // no extra round trip and no new endpoint to authenticate.
    const exportBtn = document.getElementById('export-notes-btn');
    if (exportBtn) {
      exportBtn.addEventListener('click', () => {
        if (!_selectedFinding) return;
        _downloadNotesText(_selectedFinding);
      });
    }
  }

  // _downloadNotesText builds a self-contained text file: a finding-context
  // header (so the file is readable on its own without the Archer UI) plus
  // the full notes thread in chronological order.
  function _downloadNotesText(f) {
    const sep = '────────────────────────────────────────────────────────────';
    const dst = f.dst_ip ? (f.dst_ip + (f.dst_port ? ':' + f.dst_port : '')) : '';
    const lines = [
      `Archer Finding #${f.id} — Notes Export`,
      sep,
      `Type:        ${f.type || ''}`,
      `Severity:    ${f.severity || ''}`,
      `Score:       ${f.score == null ? '' : f.score}`,
      `Source:      ${f.src_ip || ''}`,
      `Destination: ${dst}`,
      `Timestamp:   ${f.timestamp || ''} UTC`,
      `Status:      ${f.status || 'open'}`,
      `Sensor:      ${f.sensor || ''}`,
      sep,
      '',
    ];
    const notes = Array.isArray(f.notes) ? f.notes : [];
    if (notes.length === 0) {
      lines.push('(no notes)');
    } else {
      notes.forEach((n, i) => {
        lines.push(`Note ${i + 1} — ${n.author || 'unknown'} • ${n.timestamp || ''}`);
        lines.push(n.text || '');
        lines.push('');
      });
    }
    const blob = new Blob([lines.join('\n')], {type: 'text/plain;charset=utf-8'});
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `archer-finding-${f.id}-notes.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function copyPCAP(f) {
    if (!f.src_ip || !f.dst_ip) return;
    let filter = `host ${f.src_ip} and host ${f.dst_ip}`;
    if (f.dst_port) filter += ` and tcp port ${f.dst_port}`;
    const ok = copyToClipboard(filter);
    showToast((ok ? 'Copied: ' : 'Filter: ') + filter);
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
            <div style="font-family:monospace;font-size:13px">${_esc(s.target)}</div>
            ${s.detail ? `<div style="font-size:11px;color:var(--fg-dim);margin-top:2px">${_esc(s.detail)}</div>` : ''}
            <div style="font-size:11px;color:var(--fg-dim);margin-top:2px">Expires ${expStr}</div>
          </div>
          <button class="dlg-btn secondary" style="padding:3px 10px;font-size:12px;flex-shrink:0">Remove</button>`;
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
      _loadAllowSet();
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
      const [cfg, archive] = await Promise.all([
        api('/api/config').catch(() => ({})),
        api('/api/archive').catch(() => null),
      ]);
      _populateSettings(cfg);
      _populateArchive(archive);
      _refreshDiskUsage(); // populates the Disk Usage row and the warning banner
      dlg.showModal();
    });
    document.getElementById('settings-cancel').addEventListener('click', () => dlg.close());
    document.getElementById('settings-save').addEventListener('click', async () => {
      try {
        const payload = _collectSettings();
        await api('/api/config', {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload),
        });
        await api('/api/archive', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(_collectArchive()),
        });
        // Refresh the in-memory org CIDR list and rebuild the Hosts panel so
        // the new filter is reflected without a page reload.
        _orgCIDRs = Array.isArray(payload.org_internal_cidrs) ? payload.org_internal_cidrs : [];
        Campaigns.build(_allFindings);
        setStatus('Settings saved');
      } catch (e) {
        setStatus('Error: ' + e);
      }
      dlg.close();
    });

    const resetBtn = document.getElementById('reset-analyze-btn');
    const resetStatus = document.getElementById('reset-analyze-status');
    if (resetBtn) {
      resetBtn.addEventListener('click', async () => {
        const ok = window.confirm(
          'Discard ALL findings in the database and re-run analysis from scratch?\n\n' +
          'Analyst notes, statuses, and acknowledgements will be lost. This cannot be undone.'
        );
        if (!ok) return;
        resetBtn.disabled = true;
        resetStatus.textContent = 'Starting…';
        resetStatus.style.color = 'var(--fg-dim)';
        try {
          const res = await api('/api/analyze/reset', {method: 'POST'});
          if (res && res.error) {
            resetStatus.textContent = 'Error: ' + res.error;
            resetStatus.style.color = 'var(--sev-high, #c66)';
          } else {
            resetStatus.textContent = `Cleared ${res.findings_cleared||0} finding(s); analysis started.`;
            resetStatus.style.color = 'var(--accent)';
            dlg.close();
          }
        } catch (e) {
          resetStatus.textContent = 'Error: ' + e;
          resetStatus.style.color = 'var(--sev-high, #c66)';
        }
        resetBtn.disabled = false;
      });
    }

    const runBtn = document.getElementById('archive-run-btn');
    const runStatus = document.getElementById('archive-run-status');
    if (runBtn) {
      runBtn.addEventListener('click', async () => {
        runBtn.disabled = true;
        runStatus.textContent = 'Previewing…';
        runStatus.style.color = 'var(--fg-dim)';
        // Phase 1: preview. Server reports what would be moved/pruned.
        let preview;
        try {
          preview = await api('/api/archive/run', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({dry_run: true}),
          });
        } catch (e) {
          runStatus.textContent = 'Preview failed: ' + e;
          runStatus.style.color = 'var(--sev-high, #c66)';
          runBtn.disabled = false;
          return;
        }
        if (preview && preview.error) {
          runStatus.textContent = 'Error: ' + preview.error;
          runStatus.style.color = 'var(--sev-high, #c66)';
          runBtn.disabled = false;
          return;
        }
        const files = preview.files_archived || 0;
        const bytes = preview.bytes_archived || 0;
        const pruned = preview.findings_pruned || 0;
        if (files === 0 && pruned === 0) {
          runStatus.textContent = 'Nothing to archive — no files older than the cutoff.';
          runStatus.style.color = 'var(--fg-dim)';
          runBtn.disabled = false;
          return;
        }
        const lines = [
          `Would move ${files} file(s) (${_humanBytes(bytes)}).`,
        ];
        if (pruned) lines.push(`Would prune ${pruned} finding(s) (destructive).`);
        lines.push('', 'Continue?');
        if (!window.confirm(lines.join('\n'))) {
          runStatus.textContent = 'Cancelled.';
          runStatus.style.color = 'var(--fg-dim)';
          runBtn.disabled = false;
          return;
        }
        // Phase 2: execute.
        runStatus.textContent = 'Running…';
        try {
          const res = await api('/api/archive/run', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({dry_run: false}),
          });
          if (res && res.error) {
            runStatus.textContent = 'Error: ' + res.error;
            runStatus.style.color = 'var(--sev-high, #c66)';
          } else {
            runStatus.textContent = `Archived ${res.files_archived||0} file(s), ${_humanBytes(res.bytes_archived||0)}${res.findings_pruned ? `, pruned ${res.findings_pruned} finding(s)` : ''}.`;
            runStatus.style.color = 'var(--accent)';
            // Best-effort refresh of just the last-run line so it reflects
            // the run we just did, without disturbing the success message.
            try {
              const fresh = await api('/api/archive');
              _renderArchiveLastRun(fresh);
            } catch (e) { /* ignore */ }
          }
        } catch (e) {
          runStatus.textContent = 'Error: ' + e;
          runStatus.style.color = 'var(--sev-high, #c66)';
        }
        runBtn.disabled = false;
      });
    }

    // ── Scan archive for IOCs ───────────────────────────────────────────
    // Triggers /api/archive/scan, which runs only the IOC + TI-feed phases
    // over /data/archive. Findings flow through the regular SetFindings
    // merge path so analyst state on existing findings is preserved.
    const scanBtn = document.getElementById('archive-scan-btn');
    if (scanBtn) {
      scanBtn.addEventListener('click', async () => {
        // Surface a quick summary of what's about to be scanned. The disk-
        // usage cache already knows the archive size, so the operator sees
        // a credible estimate before kicking off a long-running pass.
        const archiveBytes = (_diskUsage && _diskUsage.archive_total_bytes) || 0;
        const archiveLine = archiveBytes
          ? `Archive contains ~${_humanBytes(archiveBytes)} of logs.`
          : 'Archive size unknown.';
        const msg = [
          archiveLine,
          'Scan will check every archived log against the current IOC list,',
          'Feodo Tracker, URLhaus, and the Suspicious URL list.',
          'Heavy phases (beacon, exfil, lateral, etc.) are skipped.',
          '',
          'Continue?',
        ].join('\n');
        if (!window.confirm(msg)) return;

        scanBtn.disabled = true;
        runStatus.textContent = 'Starting archive scan…';
        runStatus.style.color = 'var(--fg-dim)';
        try {
          const res = await api('/api/archive/scan', {method: 'POST'});
          if (res && res.error) {
            runStatus.textContent = 'Scan error: ' + res.error;
            runStatus.style.color = 'var(--sev-high, #c66)';
          } else {
            runStatus.textContent = `Scanning ${res.files || 0} archived file(s) — progress shown in the analysis status row.`;
            runStatus.style.color = 'var(--accent)';
          }
        } catch (e) {
          runStatus.textContent = 'Scan error: ' + e;
          runStatus.style.color = 'var(--sev-high, #c66)';
        }
        // The scan runs in the background; the existing SSE flow handles
        // progress + done. We re-enable the button immediately so the
        // operator can close Settings and watch the regular UI for results.
        scanBtn.disabled = false;
      });
    }
  }

  function _humanBytes(n) {
    if (!n) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0, v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
  }

  // ── Disk usage ────────────────────────────────────────────────────────────
  // _diskUsage caches the most recent /api/disk-usage response so the
  // Sensors modal and the warning banner can read it without re-fetching.
  let _diskUsage = null;

  // _refreshDiskUsage hits /api/disk-usage, updates the cache, repaints the
  // Settings disk-usage block, and reasserts the low-disk banner. Safe to
  // call from any UI surface that wants fresh numbers.
  async function _refreshDiskUsage() {
    try {
      const data = await api('/api/disk-usage');
      _diskUsage = data || null;
    } catch (_) { _diskUsage = null; }
    _renderDiskUsageBlock();
    _renderDiskWarning();
  }

  function _renderDiskUsageBlock() {
    const el = document.getElementById('disk-usage-content');
    if (!el) return;
    if (!_diskUsage) { el.textContent = 'Disk usage unavailable'; el.style.fontFamily = ''; return; }
    const d = _diskUsage;
    // Use a real DOM tree instead of a flat string so we get proper
    // alignment (name left / size right), section headers, and a section
    // for every sensor without truncation. Inline styles keep this self-
    // contained — the block lives inside the Settings dialog and we don't
    // want to bleed CSS rules elsewhere.
    el.style.fontFamily = '';
    el.innerHTML = '';

    const sectionTitle = txt => {
      const h = document.createElement('div');
      h.style.cssText = 'font-size:11px;color:var(--fg-secondary);text-transform:uppercase;letter-spacing:0.05em;margin-top:10px;margin-bottom:4px';
      h.textContent = txt;
      return h;
    };
    const row = (name, value, opts) => {
      opts = opts || {};
      const r = document.createElement('div');
      // Sizes sit right next to their label with a fixed gap — left-
      // aligned, not pushed to the far right of the panel. Names render
      // in their natural width so the whole row stays compact.
      r.style.cssText = 'display:flex;justify-content:flex-start;align-items:baseline;gap:10px;padding:1px 0;font-size:11px';
      const left  = document.createElement('span');
      left.textContent = name;
      left.style.cssText = (opts.indent ? 'padding-left:14px;' : '') +
                           (opts.muted  ? 'color:var(--fg-dim);'  : 'color:var(--fg-primary);') +
                           'font-family:ui-monospace,monospace;white-space:nowrap';
      const right = document.createElement('span');
      right.textContent = value;
      right.style.cssText = 'font-family:ui-monospace,monospace;color:var(--fg-primary);white-space:nowrap';
      r.appendChild(left);
      r.appendChild(right);
      return r;
    };

    // ── /logs section: total + every enrolled sensor's tree size ────────
    const logsCount = (d.by_sensor && d.by_sensor.length) || 0;
    el.appendChild(sectionTitle(`/logs  (${logsCount} sensor${logsCount === 1 ? '' : 's'})`));
    el.appendChild(row('Total', _humanBytes(d.logs_total_bytes)));
    if (d.by_sensor && d.by_sensor.length) {
      d.by_sensor.forEach(s => {
        el.appendChild(row(s.name, _humanBytes(s.bytes), {indent: true, muted: true}));
      });
    } else {
      const empty = document.createElement('div');
      empty.style.cssText = 'padding-left:14px;font-size:11px;color:var(--fg-dim);font-style:italic';
      empty.textContent = '(no sensor directories found)';
      el.appendChild(empty);
    }

    // ── /data/archive total ─────────────────────────────────────────────
    el.appendChild(sectionTitle('Archive'));
    el.appendChild(row('/data/archive total', _humanBytes(d.archive_total_bytes)));

    // ── Volume free space — combined when /data and /logs share a disk ──
    el.appendChild(sectionTitle('Volumes'));
    const sameVolume = d.logs_volume && d.data_volume &&
                       d.logs_volume.total_bytes === d.data_volume.total_bytes &&
                       d.logs_volume.free_bytes  === d.data_volume.free_bytes;
    const volRow = (label, v) => {
      if (!v || !v.total_bytes) return null;
      const pct = ((v.free_bytes / v.total_bytes) * 100).toFixed(1);
      return row(label, `${_humanBytes(v.free_bytes)} free / ${_humanBytes(v.total_bytes)} (${pct}%)`);
    };
    if (sameVolume) {
      const r = volRow('/data and /logs (same volume)', d.data_volume);
      if (r) el.appendChild(r);
    } else {
      const dr = volRow('/data volume', d.data_volume); if (dr) el.appendChild(dr);
      const lr = volRow('/logs volume', d.logs_volume); if (lr) el.appendChild(lr);
    }

    // Generation timestamp — small footer so a stale cache is obvious.
    if (d.generated_at) {
      const f = document.createElement('div');
      f.style.cssText = 'margin-top:10px;font-size:10px;color:var(--fg-dim);font-style:italic';
      f.textContent = `Generated ${d.generated_at}`;
      el.appendChild(f);
    }
  }

  // _renderDiskWarning surfaces a top-of-page banner when free space on
  // the data or logs volume drops below 10%. It clears itself when the
  // condition resolves so the operator gets immediate feedback after
  // running an archive sweep.
  function _renderDiskWarning() {
    const el = document.getElementById('disk-warning-banner');
    if (!el) return;
    if (!_diskUsage) { el.style.display = 'none'; return; }
    const threshold = 0.10;
    const lows = [];
    const data = _diskUsage.data_volume;
    if (data && data.total_bytes && (data.free_bytes / data.total_bytes) < threshold) {
      lows.push(`/data has only ${_humanBytes(data.free_bytes)} free`);
    }
    const logs = _diskUsage.logs_volume;
    // Avoid double-counting when /logs and /data sit on the same volume.
    if (logs && logs.total_bytes && (!data || logs.total_bytes !== data.total_bytes)
        && (logs.free_bytes / logs.total_bytes) < threshold) {
      lows.push(`/logs has only ${_humanBytes(logs.free_bytes)} free`);
    }
    if (!lows.length) { el.style.display = 'none'; el.textContent = ''; return; }
    el.textContent = '⚠ Low disk space — ' + lows.join('; ') + '. Consider running archive or moving the archive to cold storage.';
    el.style.display = '';
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
    set('cfg-greynoise-key',  cfg.greynoise_api_key);
    // Censys's two halves render as a single split-field control: the ID
    // half is plaintext (it's an identifier, not a credential by itself)
    // and the secret half is masked. Backend persistence stays as two
    // separate fields so HTTP Basic auth can call SetBasicAuth(id, secret)
    // without parsing on every lookup.
    set('cfg-censys-id',      cfg.censys_api_id);
    set('cfg-censys-secret',  cfg.censys_api_secret);
    const cidrEl = document.getElementById('cfg-org-cidrs');
    if (cidrEl) cidrEl.value = Array.isArray(cfg.org_internal_cidrs) ? cfg.org_internal_cidrs.join('\n') : '';
  }

  function _populateArchive(a) {
    if (!a) a = {};
    const en = document.getElementById('cfg-archive-enabled');
    const af = document.getElementById('cfg-archive-after');
    const pr = document.getElementById('cfg-archive-prune');
    const rs = document.getElementById('archive-run-status');
    if (en) en.checked = !!a.enabled;
    if (af) af.value = a.after_days || 30;
    if (pr) pr.checked = !!a.prune_findings_on_archive;
    if (rs) rs.textContent = '';
    _renderArchiveLastRun(a);
  }

  function _renderArchiveLastRun(a) {
    const lr = document.getElementById('archive-last-run');
    if (!lr) return;
    if (!a || !a.last_run_at) {
      lr.textContent = 'Last run: never';
      return;
    }
    const parts = [
      `Last run: ${a.last_run_at}`,
      `${a.last_files_archived || 0} file(s) moved`,
      _humanBytes(a.last_bytes_archived || 0),
    ];
    if (a.last_findings_pruned) parts.push(`${a.last_findings_pruned} finding(s) pruned`);
    if (a.last_triggered_by) parts.push(`by ${_esc(a.last_triggered_by)}`);
    lr.textContent = parts.join(' — ');
  }

  function _collectSettings() {
    const g = id => { const el = document.getElementById(id); return el ? el.value : ''; };
    const cidrs = g('cfg-org-cidrs')
      .split('\n')
      .map(s => s.trim())
      .filter(s => s.length > 0);
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
      greynoise_api_key:        g('cfg-greynoise-key'),
      censys_api_id:            g('cfg-censys-id').trim(),
      censys_api_secret:        g('cfg-censys-secret').trim(),
      org_internal_cidrs:       cidrs,
    };
  }

  function _collectArchive() {
    const g  = id => document.getElementById(id);
    const en = g('cfg-archive-enabled');
    const af = g('cfg-archive-after');
    const pr = g('cfg-archive-prune');
    return {
      enabled: !!(en && en.checked),
      after_days: parseInt(af && af.value) || 30,
      prune_findings_on_archive: !!(pr && pr.checked),
    };
  }

  // ── Watch mode ─────────────────────────────────────────────────────────────
  function _updateWatchUI(cfg) {
    const statusEl = document.getElementById('watch-status-label');
    const btn      = document.getElementById('watch-btn');
    if (!cfg) return;
    _watchActive = !!cfg.enabled;
    if (cfg.enabled) {
      statusEl.textContent = 'Enabled';
      statusEl.style.color = 'var(--accent)';
      if (btn) btn.textContent = 'Disable';
    } else {
      statusEl.textContent = 'Disabled';
      statusEl.style.color = 'var(--fg-dim)';
      if (btn) btn.textContent = 'Enable';
    }

    const tzInput = document.getElementById('watch-tz');
    if (tzInput) tzInput.value = cfg.timezone || '';
    const intervalInput = document.getElementById('watch-interval');
    if (intervalInput) {
      // Server reports interval_hours; 0 (or 24) means daily.
      const v = (cfg.interval_hours === 24) ? 0 : (cfg.interval_hours || 0);
      intervalInput.value = String(v);
    }

    // Reflect the saved HH:MM into whichever control matches the cadence.
    const timeInput = document.getElementById('watch-time');
    const minInput  = document.getElementById('watch-minute');
    if (cfg.time && timeInput) timeInput.value = cfg.time;
    if (cfg.time && minInput) {
      const mm = cfg.time.split(':')[1];
      const m  = parseInt(mm, 10);
      minInput.value = isNaN(m) ? 0 : m;
    }

    _renderWatchTimeControl();
    _renderWatchSchedulePreview(cfg);
  }

  // _renderWatchTimeControl swaps the visible input and updates the label
  // to match the current cadence. Hourly hides the H half (it's ignored
  // server-side); every other cadence keeps the full HH:MM picker.
  function _renderWatchTimeControl() {
    const interval  = parseInt((document.getElementById('watch-interval') || {}).value, 10) || 0;
    const labelEl   = document.getElementById('watch-time-label');
    const timeInput = document.getElementById('watch-time');
    const minInput  = document.getElementById('watch-minute');
    if (!labelEl || !timeInput || !minInput) return;

    if (interval === 1) {
      labelEl.textContent = 'Minute of hour';
      timeInput.style.display = 'none';
      minInput.style.display  = '';
    } else if (interval === 0) {
      labelEl.textContent = 'Run at';
      timeInput.style.display = '';
      minInput.style.display  = 'none';
    } else {
      labelEl.textContent = 'First run at';
      timeInput.style.display = '';
      minInput.style.display  = 'none';
    }
  }

  // _renderWatchSchedulePreview shows the resulting schedule in plain
  // English (cadence + anchor + timezone + next-run) so the user doesn't
  // have to mentally combine three fields. Always reflects what the
  // server reported, never what the form currently holds.
  function _renderWatchSchedulePreview(cfg) {
    const el = document.getElementById('watch-schedule-preview');
    if (!el) return;
    if (!cfg || !cfg.enabled) { el.textContent = ''; return; }
    const interval = (cfg.interval_hours === 24) ? 0 : (cfg.interval_hours || 0);
    const tzLabel  = cfg.timezone || 'UTC';
    const time     = cfg.time || '';
    const mm       = time.split(':')[1] || '00';
    let head;
    if (interval === 1)       head = `Hourly at :${mm}`;
    else if (interval === 0)  head = `Daily at ${time}`;
    else                      head = `Every ${interval}h starting ${time}`;
    const next = cfg.next_run ? ` — next ${cfg.next_run}` : '';
    el.textContent = `${head} ${tzLabel}${next}`;
  }

  function initWatch() {
    // Populate the IANA list from the browser's own zoneinfo. Modern Chromium
    // and Firefox expose ~600 zones via Intl.supportedValuesOf; fallback is a
    // free-text input — server validates with time.LoadLocation either way.
    const dl = document.getElementById('watch-tz-list');
    if (dl && typeof Intl.supportedValuesOf === 'function') {
      try {
        Intl.supportedValuesOf('timeZone').forEach(z => {
          const opt = document.createElement('option');
          opt.value = z;
          dl.appendChild(opt);
        });
      } catch (e) {}
    }

    const btn = document.getElementById('watch-btn');
    if (btn) {
      btn.addEventListener('click', async () => {
        const tzVal       = (document.getElementById('watch-tz').value       || '').trim();
        const intervalVal = parseInt(document.getElementById('watch-interval').value, 10) || 0;
        const timeVal     = _readWatchTimeForCadence(intervalVal);
        const enabling    = !_watchActive;
        if (enabling && !timeVal) { setStatus('Enter a time for the analysis schedule'); return; }
        try {
          await api('/api/watch', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({time: timeVal, timezone: tzVal, enabled: enabling, interval_hours: intervalVal}),
          });
          const cfg = await api('/api/watch');
          _updateWatchUI(cfg);
          const tzLabel  = tzVal || 'UTC';
          const cadence  = _watchCadenceLabel(intervalVal);
          setStatus(enabling ? `Watch enabled — ${cadence} at minute :${timeVal.split(':')[1] || '00'} ${tzLabel}` : 'Watch disabled');
        } catch(e) { setStatus('Watch error: ' + e); }
      });
    }

    // Cadence dropdown auto-saves the same way the timezone field does —
    // no need to toggle Enable/Disable to commit a new interval. Also
    // re-renders the time control because the active input depends on it.
    const intervalEl = document.getElementById('watch-interval');
    if (intervalEl) {
      intervalEl.addEventListener('change', async () => {
        const tzVal       = (document.getElementById('watch-tz').value   || '').trim();
        const intervalVal = parseInt(intervalEl.value, 10) || 0;
        _renderWatchTimeControl();
        const timeVal = _readWatchTimeForCadence(intervalVal);
        try {
          await api('/api/watch', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({time: timeVal, timezone: tzVal, enabled: _watchActive, interval_hours: intervalVal}),
          });
          // Re-fetch so the next-run preview updates immediately.
          const cfg = await api('/api/watch');
          _updateWatchUI(cfg);
          setStatus(`Cadence saved: ${_watchCadenceLabel(intervalVal)}`);
        } catch (e) { setStatus('Cadence error: ' + e); }
      });
    }

    // Time + minute inputs auto-save on change so the schedule preview
    // stays truthful and a typed-in value isn't lost if the user never
    // toggles Enable/Disable. Server treats the post as a full replace.
    ['watch-time', 'watch-minute'].forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener('change', async () => {
        const tzVal       = (document.getElementById('watch-tz').value || '').trim();
        const intervalVal = parseInt(document.getElementById('watch-interval').value, 10) || 0;
        const timeVal     = _readWatchTimeForCadence(intervalVal);
        if (!timeVal) return;
        try {
          await api('/api/watch', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({time: timeVal, timezone: tzVal, enabled: _watchActive, interval_hours: intervalVal}),
          });
          const cfg = await api('/api/watch');
          _updateWatchUI(cfg);
        } catch (e) { setStatus('Watch error: ' + e); }
      });
    });

    // Persist the timezone independently of the Enable/Disable toggle.
    // The watch endpoint is single-write (time + enabled + timezone in
    // one POST), so we re-send the current time + enabled state with
    // the new TZ. Without this, an admin who changes the TZ but never
    // toggles watch mode would lose the value on the next page load —
    // which also breaks the Sensors modal that renders timestamps in
    // whatever TZ this widget reports. Findings stay UTC; only modal
    // and sensor-facing UI follow the configured zone.
    const tzInputEl = document.getElementById('watch-tz');
    if (tzInputEl) {
      tzInputEl.addEventListener('change', async () => {
        const tzVal       = (tzInputEl.value || '').trim();
        const timeVal     = (document.getElementById('watch-time').value || '').trim();
        const intervalVal = parseInt(document.getElementById('watch-interval').value, 10) || 0;
        try {
          await api('/api/watch', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({time: timeVal, timezone: tzVal, enabled: _watchActive, interval_hours: intervalVal}),
          });
          setStatus(tzVal ? `Timezone saved: ${tzVal}` : 'Timezone saved (UTC)');
        } catch (e) { setStatus('Timezone error: ' + e); }
      });
    }

    api('/api/watch').then(cfg => _updateWatchUI(cfg)).catch(() => {});
  }

  // _watchCadenceLabel renders the interval dropdown's value as a short
  // human label for status toasts.
  function _watchCadenceLabel(h) {
    if (!h || h === 24) return 'daily';
    if (h === 1) return 'hourly';
    return `every ${h} hours`;
  }

  // _readWatchTimeForCadence reads HH:MM from the active control: the
  // minute-only input under Hourly (server only uses MM there), the full
  // HH:MM picker otherwise. Returns "" when the relevant input is empty.
  function _readWatchTimeForCadence(interval) {
    if (interval === 1) {
      const m = parseInt((document.getElementById('watch-minute') || {}).value, 10);
      if (isNaN(m) || m < 0 || m > 59) return '';
      return '00:' + String(m).padStart(2, '0');
    }
    return ((document.getElementById('watch-time') || {}).value || '').trim();
  }

  // ── Context menu ───────────────────────────────────────────────────────────
  function initContextMenu() {
    const menu = document.getElementById('ctx-menu');
    let _ctxTarget = '';      // resolved IP for the right-clicked column (Src or Dst), or '' on neutral cells
    let _ctxTargetCol = null; // 'src' | 'dst' | null — drives label text and visibility

    // _disable applies the muted "this action doesn't apply right now"
    // treatment to a menu item. Used by state-aware logic so e.g. an
    // already-acknowledged finding doesn't offer Acknowledge as a no-op.
    function _disable(id, on, why) {
      const el = document.getElementById(id);
      if (!el) return;
      el.classList.toggle('ctx-disabled', !!on);
      if (on && why) el.title = why; else el.removeAttribute('title');
    }

    function showMenu(e, f) {
      _ctxFinding = f;

      // Resolve the column under the cursor. table.js / campaigns.js mark
      // the Src/Dst cells with `class="src-ip"` / `class="dst-ip"` so we
      // can tell which IP the analyst is acting on without parsing text.
      const td = e.target && e.target.closest && e.target.closest('td');
      _ctxTargetCol = null;
      _ctxTarget = '';
      if (td) {
        if (td.classList.contains('src-ip')) {
          _ctxTargetCol = 'src';
          _ctxTarget = (f && f.src_ip) || '';
        } else if (td.classList.contains('dst-ip')) {
          _ctxTargetCol = 'dst';
          _ctxTarget = (f && f.dst_ip) || '';
        }
      }

      // Header — names the right-clicked finding so item labels read
      // unambiguously even when a campaign row aggregates many findings.
      const hdr = document.getElementById('ctx-header');
      if (hdr) {
        const sev  = (f && f.severity) || '';
        const type = (f && f.type) || '';
        const src  = (f && f.src_ip) || '';
        const dst  = (f && f.dst_ip) || '';
        const port = (f && f.dst_port) ? `:${f.dst_port}` : '';
        const sevPart = sev ? `[${sev}] ` : '';
        const arrow   = (src && dst) ? `${src} → ${dst}${port}` : (src || dst || '');
        hdr.textContent = `${sevPart}${type}${type && arrow ? ' — ' : ''}${arrow}`;
      }

      // Column-aware section: hide entirely on cells that aren't Src or Dst.
      // The user explicitly asked for non-IP cells to show only row-level
      // actions, so Pivot / Allowlist / IOC / Lookup all collapse here.
      const showColAware = !!_ctxTarget;
      document.querySelectorAll('.ctx-target-aware').forEach(el => {
        el.style.display = showColAware ? '' : 'none';
      });

      // Update labels with the resolved IP so the menu reads as a sentence.
      if (showColAware) {
        document.getElementById('ctx-pivot').textContent     = `Pivot to ${_ctxTarget}`;
        document.getElementById('ctx-allowlist').firstChild.nodeValue = `Add ${_ctxTarget} to Allowlist`;
        document.getElementById('ctx-ioc-add').firstChild.nodeValue   = `Add ${_ctxTarget} to IOC List`;
        document.getElementById('ctx-lookup').firstChild.nodeValue    = `Lookup ${_ctxTarget} ↗ `;
      }

      // Role gate: viewers can't perform any write action, so hide them
      // entirely instead of letting the user click into a 403.
      const role = (_currentUser && _currentUser.role) || 'viewer';
      const isViewer = role === 'viewer';
      document.querySelectorAll('.ctx-write').forEach(el => {
        // Only hide for viewers; analyst+ keeps the items, possibly disabled by state-aware logic below.
        if (isViewer) el.style.display = 'none';
        else if (!el.classList.contains('ctx-target-aware') || showColAware) el.style.display = '';
      });

      // State-aware: don't offer actions that no longer apply.
      const status = (f && f.status) || 'open';
      _disable('ctx-ack',
        status === 'acknowledged' || status === 'escalated',
        status === 'escalated' ? 'Already escalated' : 'Already acknowledged');
      _disable('ctx-escalate',
        status === 'escalated',
        'Already escalated');
      if (showColAware) {
        _disable('ctx-allowlist', _allowSet.has(_ctxTarget), 'Already on allowlist');
        _disable('ctx-ioc-add',   _iocSet.has(_ctxTarget),   'Already on IOC list');
      }

      // Beacon Chart only matters for findings carrying timeseries data.
      // The detail-pane button uses the same gate (see chart-btn enable logic).
      const chartItem = document.getElementById('ctx-chart');
      const hasChart = !!(f && Array.isArray(f.ts_data) && f.ts_data.length > 0);
      if (chartItem) chartItem.style.display = hasChart ? '' : 'none';

      // Campaign-only items: revealed when campaigns.js attached _campaign.
      const showCampaign = !!(f && f._campaign);
      document.querySelectorAll('.ctx-campaign-only').forEach(el => {
        el.style.display = showCampaign ? '' : 'none';
      });

      menu.style.left = Math.min(e.clientX, window.innerWidth - 220) + 'px';
      menu.style.top  = Math.min(e.clientY, window.innerHeight - 200) + 'px';
      menu.classList.remove('hidden');
    }

    document.addEventListener('click', () => menu.classList.add('hidden'));

    // Block clicks on disabled items so state-aware greyed-out entries
    // don't fall through to their handlers.
    menu.addEventListener('click', e => {
      const li = e.target.closest('li');
      if (li && li.classList.contains('ctx-disabled')) {
        e.stopImmediatePropagation();
        e.preventDefault();
      }
    }, true);

    // ── Column-aware items ──────────────────────────────────────────────
    document.getElementById('ctx-pivot').addEventListener('click', () => {
      if (!_ctxTarget) return;
      document.getElementById('filter-search').value = _ctxTarget;
      applyFilter();
    });

    document.getElementById('ctx-pcap').addEventListener('click', () => {
      if (_ctxFinding) copyPCAP(_ctxFinding);
    });
    document.getElementById('ctx-copy-row').addEventListener('click', () => {
      if (!_ctxFinding) return;
      const f = _ctxFinding;
      const row = [f.score, f.severity, f.type, f.src_ip, f.dst_ip, f.dst_port, f.timestamp].join('\t');
      const ok = copyToClipboard(row);
      showToast(ok ? 'Row copied' : 'Copy failed');
    });

    // Each of these delegates to the matching detail-pane button so the
    // exact same code path runs whether the analyst clicks the button or
    // the menu item. Keeps escalation, source-records, and chart logic
    // single-sourced.
    document.getElementById('ctx-ack').addEventListener('click', () => {
      if (_ctxFinding) document.getElementById('ack-btn').click();
    });
    document.getElementById('ctx-escalate').addEventListener('click', () => {
      if (_ctxFinding) document.getElementById('esc-btn').click();
    });
    document.getElementById('ctx-source-records').addEventListener('click', () => {
      if (_ctxFinding) document.getElementById('raw-btn').click();
    });
    document.getElementById('ctx-chart').addEventListener('click', () => {
      if (_ctxFinding) document.getElementById('chart-btn').click();
    });

    document.querySelectorAll('#ctx-supp-sub li[data-days]').forEach(li => {
      li.addEventListener('click', async () => {
        if (!_ctxFinding) return;
        // Suppress acts on the IP under the cursor when a Src/Dst column
        // was clicked; otherwise it falls back to dst-then-src like before.
        const target = _ctxTarget || _ctxFinding.dst_ip || _ctxFinding.src_ip || '';
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

    // Add to Allowlist / IOC List — single click each, target derived from
    // the column under the cursor. The cache refresh keeps state-awareness
    // current so a second right-click on the same IP reflects the change.
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

    document.getElementById('ctx-allowlist').addEventListener('click', () => {
      if (!_ctxTarget) return;
      _addToList('/api/allowlist', 'Allowlist', _ctxTarget, () => {
        _loadAllowSet();
        loadFindings();
      });
    });
    document.getElementById('ctx-ioc-add').addEventListener('click', () => {
      if (!_ctxTarget) return;
      _addToList('/api/ioc', 'IOC List', _ctxTarget, _loadIOCList);
    });

    // External-service lookups — open in a new tab. URL templates chosen
    // for direct-link compatibility: VT/AbuseIPDB/Shodan/CrowdSec/OTX work
    // for IPs and most domains; URLscan distinguishes ip vs domain in its
    // path, so we infer from a quick "looks like an IP" check. Censys and
    // GreyNoise free tiers require an account; the link still lands the
    // analyst on the right page once signed in.
    const _looksLikeIP = s => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/.test(s);
    const _open = url => window.open(url, '_blank');
    document.getElementById('ctx-vt').addEventListener('click', () => {
      if (_ctxTarget) _open(`https://www.virustotal.com/gui/search/${encodeURIComponent(_ctxTarget)}`);
    });
    document.getElementById('ctx-abuseipdb').addEventListener('click', () => {
      if (_ctxTarget) _open(`https://www.abuseipdb.com/check/${encodeURIComponent(_ctxTarget)}`);
    });
    document.getElementById('ctx-shodan').addEventListener('click', () => {
      if (_ctxTarget) _open(`https://www.shodan.io/search?query=${encodeURIComponent(_ctxTarget)}`);
    });
    document.getElementById('ctx-crowdsec').addEventListener('click', () => {
      if (_ctxTarget) _open(`https://app.crowdsec.net/cti/${encodeURIComponent(_ctxTarget)}`);
    });
    document.getElementById('ctx-censys').addEventListener('click', () => {
      if (_ctxTarget) _open(`https://search.censys.io/hosts/${encodeURIComponent(_ctxTarget)}`);
    });
    document.getElementById('ctx-greynoise').addEventListener('click', () => {
      if (_ctxTarget) _open(`https://viz.greynoise.io/ip/${encodeURIComponent(_ctxTarget)}`);
    });
    document.getElementById('ctx-urlscan').addEventListener('click', () => {
      if (!_ctxTarget) return;
      const path = _looksLikeIP(_ctxTarget) ? 'ip' : 'domain';
      _open(`https://urlscan.io/${path}/${encodeURIComponent(_ctxTarget)}`);
    });
    document.getElementById('ctx-otx').addEventListener('click', () => {
      if (!_ctxTarget) return;
      const path = _looksLikeIP(_ctxTarget) ? 'IPv4' : 'domain';
      _open(`https://otx.alienvault.com/indicator/${path}/${encodeURIComponent(_ctxTarget)}`);
    });

    document.querySelectorAll('#ctx-export-campaign-sub li[data-format]').forEach(li => {
      li.addEventListener('click', () => {
        if (_ctxFinding && _ctxFinding._campaign) {
          _downloadSingleCampaign(li.dataset.format, _ctxFinding._campaign);
        }
      });
    });

    // Open a campaign in the in-app graph. The findings list is filtered down
    // to those participating in this campaign so node/edge severities reflect
    // the real data rather than a synthesised default.
    document.getElementById('ctx-graph-campaign').addEventListener('click', () => {
      if (!_ctxFinding || !_ctxFinding._campaign) return;
      const c = _ctxFinding._campaign;
      const srcs = c.srcs instanceof Set ? c.srcs : new Set(c.srcs || []);
      const port = String(c.port || '');
      const findings = _allFindings.filter(f =>
        f.dst_ip === c.dst &&
        String(f.dst_port || '') === port &&
        srcs.has(f.src_ip)
      );
      Graph.showFindings(findings, `${c.dst}:${c.port} · ${srcs.size} hosts`, c.dst);
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
    tbody.innerHTML = '<tr><td colspan="6" style="color:var(--fg-dim);padding:10px">Loading…</td></tr>';
    try {
      const users = await api('/api/users');
      _setPendingBadge(users.filter(u => u.status === 'pending').length);
      tbody.innerHTML = '';
      users.forEach(u => {
        const tr = document.createElement('tr');
        const isSelf  = _currentUser && u.id === _currentUser.id;
        const pending = u.status === 'pending';
        const roleOpts = ['admin','analyst','viewer'].map(r =>
          `<option value="${r}"${r === u.role ? ' selected' : ''}>${r.charAt(0).toUpperCase()+r.slice(1)}</option>`
        ).join('');
        const status = u.status || 'active';
        const actions = [];
        if (pending) actions.push(`<button class="user-approve-btn" data-uid="${u.id}">Approve</button>`);
        if (!isSelf) actions.push(`<button class="user-delete-btn" data-uid="${u.id}">Delete</button>`);
        tr.innerHTML = `
          <td style="font-weight:600">${_esc(u.first_name)} ${_esc(u.last_name)}</td>
          <td style="font-family:monospace;font-size:11px">${_esc(u.email)}</td>
          <td>
            ${isSelf
              ? `<span class="role-badge ${u.role}">${u.role}</span>`
              : `<select class="user-role-select" data-uid="${u.id}">${roleOpts}</select>`}
          </td>
          <td><span class="status-badge ${status}">${status}</span></td>
          <td style="font-size:11px;color:var(--fg-dim)">${(u.created_at||'').split(' ')[0]}</td>
          <td style="white-space:nowrap">${actions.join(' ')}</td>`;
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

      // Approve handlers
      tbody.querySelectorAll('.user-approve-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
          const uid = parseInt(btn.dataset.uid);
          try {
            await api(`/api/users/${uid}`, {
              method: 'PATCH',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({status: 'active'}),
            });
            _loadUsers();
          } catch (e) { setStatus('Approval failed: ' + e); }
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
      tbody.innerHTML = `<tr><td colspan="6" style="color:var(--sev-critical)">Failed to load users</td></tr>`;
    }
  }

  function _esc(s) {
    return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  // ── Org-IP predicate (drives the Hosts tab filter) ─────────────────────────
  // _isOrgIP returns true if `ip` is a host this organisation owns:
  // either it falls inside a built-in private range (RFC 1918, IPv4
  // link-local, IPv6 ULA, IPv6 link-local) or it matches an admin-supplied
  // CIDR/IP from `_orgCIDRs`. Used to keep public source IPs and the
  // synthetic "(TI)" src out of the Hosts panel.
  function _isOrgIP(ip) {
    if (!ip) return false;
    if (_isBuiltinPrivate(ip)) return true;
    for (const entry of _orgCIDRs) {
      if (_ipInCIDR(ip, entry)) return true;
    }
    return false;
  }

  function _isBuiltinPrivate(ip) {
    // IPv4
    if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
      const p = ip.split('.').map(Number);
      if (p.some(n => Number.isNaN(n) || n < 0 || n > 255)) return false;
      if (p[0] === 10) return true;
      if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
      if (p[0] === 192 && p[1] === 168) return true;
      if (p[0] === 169 && p[1] === 254) return true;
      return false;
    }
    // IPv6 — simple prefix match on the lowercased address. fc00::/7
    // matches first byte 0xfc or 0xfd; fe80::/10 matches first 10 bits
    // 1111111010xxxxxx, i.e. bytes fe80..febf.
    const lower = ip.toLowerCase();
    if (/[a-f0-9:]/.test(lower) === false) return false; // not IPv6-shaped
    if (/^f[cd][0-9a-f]{0,2}:/.test(lower) || lower === 'fc' || lower === 'fd') return true;
    if (/^fe[89ab][0-9a-f]?:/.test(lower)) return true;
    return false;
  }

  // _ipInCIDR matches an IPv4 address against a CIDR or single IP. IPv6
  // CIDR matching is intentionally out of scope; admins who need to pin a
  // specific IPv6 host can list the literal address (it'll match exactly).
  function _ipInCIDR(ip, entry) {
    if (!entry) return false;
    entry = entry.trim();
    if (!entry) return false;
    // Exact-match path covers both IPv4 with no slash and any IPv6 literal.
    if (!entry.includes('/')) return ip === entry;
    const [base, prefixStr] = entry.split('/');
    const prefix = parseInt(prefixStr, 10);
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip) || !/^\d+\.\d+\.\d+\.\d+$/.test(base)) return false;
    if (Number.isNaN(prefix) || prefix < 0 || prefix > 32) return false;
    const toInt = s => s.split('.').reduce((a, b) => (a << 8) | parseInt(b, 10), 0) >>> 0;
    const ipN = toInt(ip);
    const baseN = toInt(base);
    const mask = prefix === 0 ? 0 : ((~0) << (32 - prefix)) >>> 0;
    return (ipN & mask) === (baseN & mask);
  }

  async function _refreshPendingBadge() {
    try {
      const users = await api('/api/users');
      _setPendingBadge(users.filter(u => u.status === 'pending').length);
    } catch (e) { /* badge is best-effort */ }
  }

  function _setPendingBadge(n) {
    const el = document.getElementById('pending-badge');
    if (!el) return;
    if (n > 0) {
      el.textContent = String(n);
      el.title = `${n} account${n === 1 ? '' : 's'} awaiting approval`;
      el.style.display = '';
    } else {
      el.style.display = 'none';
    }
  }

  // ── Init ───────────────────────────────────────────────────────────────────
  function init() {
    const showMenu = initContextMenu();

    Table.init(
      f => { _selectedFinding = f; Detail.render(f); },
      (e, f) => showMenu(e, f)
    );

    Campaigns.init((e, pseudo) => showMenu(e, pseudo), _isOrgIP);

    // Clicking a graph node looks up the first finding involving that IP and
    // jumps the table to it — so the graph doubles as a navigation surface.
    Graph.init({
      onNodeClick: ip => {
        const f = _allFindings.find(x => x.src_ip === ip || x.dst_ip === ip);
        if (f) {
          _selectedFinding = f;
          Detail.render(f);
          Table.jumpTo(f.id);
        }
      },
    });

    // Graph image export dropdown — PNG or JPEG. After the format is
    // picked, the scope dialog asks current-viewport vs full graph before
    // running the actual export. Cytoscape returns a real Blob from
    // cy.png/jpg; bypass the text-oriented _downloadBlob so we don't pollute
    // the image MIME with a ;charset=utf-8 suffix.
    _initExportDropdown('graph-export-btn', 'graph-export-menu', _exportGraphImage);
    const _scopeView   = document.getElementById('graph-export-scope-view');
    const _scopeFull   = document.getElementById('graph-export-scope-full');
    const _scopeCancel = document.getElementById('graph-export-scope-cancel');
    if (_scopeView)   _scopeView.addEventListener('click', () => _commitGraphExport(false));
    if (_scopeFull)   _scopeFull.addEventListener('click', () => _commitGraphExport(true));
    if (_scopeCancel) _scopeCancel.addEventListener('click', () => {
      _pendingGraphExportFormat = null;
      document.getElementById('graph-export-scope-dlg').close();
    });

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
        _refreshPendingBadge();
      }
      // Sensors menu is visible to admin + analyst; only admins get the
      // enroll/disenroll/purge buttons (Sensors.init takes the gate).
      if (u.role === 'admin' || u.role === 'analyst') {
        Sensors.init(u.role === 'admin');
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
    _loadAllowSet();
    _loadOrgCIDRs(); // populate the Hosts-tab filter list before findings render

    // Disk-usage telemetry — poll every 5 minutes so the warning banner can
    // surface without the user having to open Settings. The endpoint itself
    // caches identically, so this is essentially free after the first call.
    _refreshDiskUsage();
    setInterval(_refreshDiskUsage, 5 * 60 * 1000);
    loadFindings()
      .then(() => _updateTIStatus())
      .catch(() => setStatus('Ready — click Import then Analyze'));
    setStatus('Ready');
  }

  async function _loadOrgCIDRs() {
    try {
      const cfg = await api('/api/config');
      _orgCIDRs = Array.isArray(cfg.org_internal_cidrs) ? cfg.org_internal_cidrs : [];
    } catch (_) { /* keep current list on failure */ }
  }

  init();
})();
