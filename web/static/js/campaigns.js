// campaigns.js — campaigns and hosts tab builders
'use strict';

const Campaigns = (() => {
  let _onCtx = null;
  let _onHostClick = null;     // app.js hook: clicking a Hosts row opens the host-pivot panel
  let _onCampaignClick = null; // app.js hook: clicking a Campaigns row opens the campaign-pivot panel
  let _campaigns = []; // exposed via getCampaigns() for export
  let _hosts = [];     // exposed via getHosts() for export

  // Sort state mirrors the findings table: -1 = desc, 1 = asc. Each table
  // owns its own pair so toggling on Campaigns doesn't affect Hosts.
  let _campSort  = { col: 'score',  dir: -1 };
  let _hostsSort = { col: 'score',  dir: -1 };
  // Most recent paginated render args, kept so a sort click can re-render
  // the same window without app.js having to thread offset/limit through.
  let _lastCampPage  = { offset: 0, limit: Infinity };
  let _lastHostsPage = { offset: 0, limit: Infinity };
  // Severity ordering for the Hosts severity column. Lower number = worse,
  // so a desc sort lands CRITICAL at the top.
  const _SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, IOC_HIT: 5 };

  // isOrgIP is accepted for call-site compatibility but unused — org-internal
  // filtering now happens server-side in the /api/hosts roll-up.
  function init(onCtx, isOrgIP, onHostClick, onCampaignClick) {
    _onCtx = onCtx;
    if (typeof onHostClick === 'function') _onHostClick = onHostClick;
    if (typeof onCampaignClick === 'function') _onCampaignClick = onCampaignClick;
    _wireSortHeaders();
  }

  function _wireSortHeaders() {
    document.querySelectorAll('#campaigns-table thead th[data-col]').forEach(th => {
      th.addEventListener('click', () => _sortCampaigns(th.dataset.col));
    });
    document.querySelectorAll('#hosts-table thead th[data-col]').forEach(th => {
      th.addEventListener('click', () => _sortHosts(th.dataset.col));
    });
    _updateSortHeaders();
  }

  function _sortCampaigns(col) {
    if (_campSort.col === col) _campSort.dir *= -1;
    else _campSort = { col, dir: -1 };
    _applyCampaignsSort();
    _updateSortHeaders();
    renderCampaignsPage(_lastCampPage.offset, _lastCampPage.limit);
  }
  function _sortHosts(col) {
    if (_hostsSort.col === col) _hostsSort.dir *= -1;
    else _hostsSort = { col, dir: -1 };
    _applyHostsSort();
    _updateSortHeaders();
    renderHostsPage(_lastHostsPage.offset, _lastHostsPage.limit);
  }

  function _applyCampaignsSort() {
    const dir = _campSort.dir;
    const col = _campSort.col;
    _campaigns.sort((a, b) => {
      let av, bv;
      switch (col) {
        case 'score': av = a.maxScore;       bv = b.maxScore;       break;
        case 'dst':   av = a.dst || '';      bv = b.dst || '';      break;
        case 'port':  av = parseInt(a.port, 10) || 0; bv = parseInt(b.port, 10) || 0; break;
        case 'hosts': av = a.srcs.size;      bv = b.srcs.size;      break;
        default:      av = a.maxScore;       bv = b.maxScore;
      }
      if (typeof av === 'string') return dir * av.localeCompare(bv);
      return dir * (av - bv);
    });
  }

  function _applyHostsSort() {
    const dir = _hostsSort.dir;
    const col = _hostsSort.col;
    _hosts.sort((a, b) => {
      let av, bv;
      switch (col) {
        case 'ip':       av = a.ip || '';                  bv = b.ip || '';                  break;
        case 'score':    av = a.score;                     bv = b.score;                     break;
        case 'count':    av = a.count;                     bv = b.count;                     break;
        case 'beacon':   av = a.beaconCount;               bv = b.beaconCount;               break;
        case 'severity': av = _SEV_ORDER[a.topSev] ?? 99;  bv = _SEV_ORDER[b.topSev] ?? 99;  break;
        default:         av = a.score;                     bv = b.score;
      }
      if (typeof av === 'string') return dir * av.localeCompare(bv);
      return dir * (av - bv);
    });
  }

  function _updateSortHeaders() {
    document.querySelectorAll('#campaigns-table thead th[data-col]').forEach(th => {
      th.classList.remove('sort-asc', 'sort-desc');
      if (th.dataset.col === _campSort.col) {
        th.classList.add(_campSort.dir === 1 ? 'sort-asc' : 'sort-desc');
      }
    });
    document.querySelectorAll('#hosts-table thead th[data-col]').forEach(th => {
      th.classList.remove('sort-asc', 'sort-desc');
      if (th.dataset.col === _hostsSort.col) {
        th.classList.add(_hostsSort.dir === 1 ? 'sort-asc' : 'sort-desc');
      }
    });
  }

  // setData ingests the server-side roll-ups (/api/campaigns, /api/hosts) and
  // renders the requested page window. It replaces the former build(findings),
  // which aggregated the whole findings corpus in the browser — the reduce now
  // happens server-side. The in-memory object shape is preserved exactly
  // (srcs / types as Sets) so the sort, render, export, graph, and
  // context-menu consumers are unchanged; only the data source moved.
  function setData(campaigns, hosts, opts) {
    opts = opts || {};
    _campaigns = (campaigns || []).map(c => ({
      dst: c.dst,
      port: c.port || '',
      srcs: new Set(c.srcs || []),
      maxScore: c.max_score | 0,
      types: new Set(c.types || []),
    }));
    _hosts = (hosts || []).map(h => ({
      ip: h.ip,
      score: h.score | 0,
      count: h.count | 0,
      beaconCount: h.beacon_count | 0,
      types: new Set(h.types || []),
      topSev: h.top_sev || 'INFO',
    }));
    _applyCampaignsSort();
    _applyHostsSort();
    const cOff = opts.campaignsOffset | 0;
    const cLim = opts.campaignsLimit  || Infinity;
    const hOff = opts.hostsOffset     | 0;
    const hLim = opts.hostsLimit      || Infinity;
    renderCampaignsPage(cOff, cLim);
    renderHostsPage(hOff, hLim);
  }

  function getCampaigns() { return _campaigns; }
  function getHosts() { return _hosts; }

  function renderCampaignsPage(offset, limit) {
    const off = offset | 0;
    const lim = limit || Infinity;
    _lastCampPage = { offset: off, limit: lim };
    const tbody = document.getElementById('campaigns-tbody');
    tbody.innerHTML = '';
    if (_campaigns.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:var(--fg-dim);padding:12px">No campaign patterns detected</td></tr>';
      return;
    }
    const slice = _campaigns.slice(off, off + lim);
    slice.forEach(e => {
      const tr = document.createElement('tr');
      // maxScore and srcs.size are integers; _scoreColor returns
      // from a fixed CSS-var enum. Every other interpolation routes
      // through _esc. The ", " join happens before escape so the
      // commas inside escaped IPs don't get double-escaped.
      const srcsText = [...e.srcs].join(', ');
      tr.innerHTML = `
        <td style="color:${_scoreColor(e.maxScore)};font-weight:700;text-align:center">${e.maxScore | 0}</td>
        <td class="dst-ip" title="${_esc(e.dst)}">${_esc(e.dst)}</td>
        <td>${_esc(e.port)}</td>
        <td class="hosts">${e.srcs.size | 0}</td>
        <td style="font-family:monospace;font-size:11px;word-break:break-all">${_esc(srcsText)}</td>`;
      tr.style.cursor = 'pointer';
      tr.addEventListener('click', () => {
        if (_onCampaignClick) _onCampaignClick(e.dst, e.port);
      });
      tr.addEventListener('contextmenu', ev => {
        ev.preventDefault();
        // The pseudo-finding gives the existing context-menu items what they
        // need (Pivot Src/Dst, Allowlist, IOC, lookups). _campaign carries
        // the full aggregation so the campaign-only export items can act on
        // it without re-deriving from the DOM.
        if (_onCtx) _onCtx(ev, {
          dst_ip: e.dst,
          src_ip: [...e.srcs][0] || '',
          dst_port: e.port,
          _campaign: e,
        });
      });
      tbody.appendChild(tr);
    });
  }

  function renderHostsPage(offset, limit) {
    const off = offset | 0;
    const lim = limit || Infinity;
    _lastHostsPage = { offset: off, limit: lim };
    const tbody = document.getElementById('hosts-tbody');
    tbody.innerHTML = '';
    if (_hosts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="color:var(--fg-dim);padding:12px">No host data</td></tr>';
      return;
    }
    const slice = _hosts.slice(off, off + lim);
    slice.forEach(e => {
      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';
      // Same defense as the Campaigns row above — _isOrgIP routes
      // SrcIP through a CIDR-membership check, but a string like
      // "192.168.1.1<script>" containing a private IP substring
      // could plausibly slip through depending on _isOrgIP's
      // implementation. _esc covers that and any future change.
      const typesText = [...e.types].slice(0, 4).join(', ');
      tr.innerHTML = `
        <td class="score" style="color:${_scoreColor(e.score)}">${e.score | 0}</td>
        <td class="src-ip dst-ip" style="font-family:monospace">${_esc(e.ip)}</td>
        <td style="text-align:center">${e.count | 0}</td>
        <td style="text-align:center;${e.beaconCount > 0 ? 'color:var(--sev-high);font-weight:700' : 'color:var(--fg-dim)'}">${e.beaconCount | 0}</td>
        <td style="color:${_sevColor(e.topSev)};font-weight:700">${_esc(e.topSev)}</td>
        <td style="font-size:11px;color:var(--fg-dim)">${_esc(typesText)}</td>`;
      tr.addEventListener('click', () => {
        if (_onHostClick) _onHostClick(e.ip);
      });
      tr.addEventListener('contextmenu', ev => {
        ev.preventDefault();
        if (_onCtx) _onCtx(ev, {dst_ip: e.ip, src_ip: e.ip, dst_port: ''});
      });
      tbody.appendChild(tr);
    });
  }

  function _scoreColor(s) {
    if (s >= 80) return 'var(--sev-critical)';
    if (s >= 60) return 'var(--sev-high)';
    if (s >= 40) return 'var(--sev-medium)';
    return 'var(--fg-text)';
  }

  function _sevColor(sev) {
    const map = {CRITICAL:'var(--sev-critical)', HIGH:'var(--sev-high)', MEDIUM:'var(--sev-medium)', LOW:'var(--fg-text)', INFO:'var(--fg-dim)', IOC_HIT:'var(--ioc-color)'};
    return map[sev] || 'var(--fg-text)';
  }

  // Canonical strong-_esc — see app.js for the convention notes and
  // the Go-side consistency test. Audit 2026-05-10 NEW-27 / NEW-30.
  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  return { init, setData, getCampaigns, getHosts, renderCampaignsPage, renderHostsPage };
})();
