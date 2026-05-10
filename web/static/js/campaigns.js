// campaigns.js — campaigns and hosts tab builders
'use strict';

const Campaigns = (() => {
  let _onCtx = null;
  let _onHostClick = null; // app.js hook: clicking a Hosts row opens the per-host roll-up finding's detail
  let _isOrgIP = () => true; // predicate set by app.js; default to "everything is internal" so the panel works before init runs
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

  function init(onCtx, isOrgIP, onHostClick) {
    _onCtx = onCtx;
    if (typeof isOrgIP === 'function') _isOrgIP = isOrgIP;
    if (typeof onHostClick === 'function') _onHostClick = onHostClick;
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

  // build computes the campaigns + hosts arrays. App.js calls
  // renderCampaignsPage(offset, limit) and renderHostsPage(offset, limit)
  // to render a specific page window without recomputing.
  function build(findings, opts) {
    opts = opts || {};
    _computeCampaigns(findings);
    _computeHosts(findings);
    const cOff = opts.campaignsOffset | 0;
    const cLim = opts.campaignsLimit  || Infinity;
    const hOff = opts.hostsOffset     | 0;
    const hLim = opts.hostsLimit      || Infinity;
    renderCampaignsPage(cOff, cLim);
    renderHostsPage(hOff, hLim);
  }

  function getCampaigns() { return _campaigns; }
  function getHosts() { return _hosts; }

  function _computeCampaigns(findings) {
    const map = new Map(); // dst_ip:dst_port → {srcs, maxScore, type}
    findings.forEach(f => {
      const dst = f.dst_ip || f.domain || '';
      // "(network)" is a synthetic destination the analyzer uses for findings
      // that target the network as a whole (e.g., NXDOMAIN flood, lateral
      // sweeps). It's expected that many hosts "talk to" the network, so it
      // would otherwise dominate the campaigns view with a non-actionable row.
      if (dst === '(network)') return;
      const key = `${dst}:${f.dst_port || ''}`;
      if (!key.startsWith(':')) {
        if (!map.has(key)) map.set(key, {dst: dst, port: f.dst_port || '', srcs: new Set(), maxScore: 0, types: new Set()});
        const e = map.get(key);
        if (f.src_ip) e.srcs.add(f.src_ip);
        if (f.score > e.maxScore) e.maxScore = f.score;
        e.types.add(f.type || '');
      }
    });

    // Filter: ≥ 2 distinct source IPs. Sort with the active column;
    // _campSort defaults to score desc to match prior behaviour.
    _campaigns = [...map.values()].filter(e => e.srcs.size >= 2);
    _applyCampaignsSort();
  }

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

  function _computeHosts(findings) {
    const map = new Map(); // src_ip → {score, findings, types, topSev}
    const SEV_ORDER = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4, IOC_HIT:5};
    findings.forEach(f => {
      if (!f.src_ip) return;
      // Only build rows for hosts that belong to the user's organisation
      // (built-in private ranges + admin-supplied CIDRs). Public src IPs,
      // the "(TI)" placeholder from threat-intel hits, and anything else
      // not owned by the org are noise in this view.
      if (!_isOrgIP(f.src_ip)) return;
      if (!map.has(f.src_ip)) map.set(f.src_ip, {ip: f.src_ip, score: 0, count: 0, types: new Set(), topSev: 'INFO'});
      const e = map.get(f.src_ip);
      e.count++;
      e.types.add(f.type || '');
      if (f.score > e.score) e.score = f.score;
      if ((SEV_ORDER[f.severity] ?? 99) < (SEV_ORDER[e.topSev] ?? 99)) e.topSev = f.severity;
    });

    _hosts = [...map.values()];
    _applyHostsSort();
  }

  function renderHostsPage(offset, limit) {
    const off = offset | 0;
    const lim = limit || Infinity;
    _lastHostsPage = { offset: off, limit: lim };
    const tbody = document.getElementById('hosts-tbody');
    tbody.innerHTML = '';
    if (_hosts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:var(--fg-dim);padding:12px">No host data</td></tr>';
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

  // _esc handles both HTML text and attribute contexts. The codebase
  // convention is one _esc per IIFE-scoped module — see detail.js,
  // feeds.js, notifications.js for the same shape. Pre-fix the dst,
  // srcs, and ip interpolations rendered server-supplied strings
  // directly into innerHTML, including in title="${e.dst}" attribute
  // context where a " breaks out of the attribute. Audit 2026-05-10
  // NEW-27. Reachable via TI Hit (Domain) findings whose dst_ip
  // carried a malicious indicator from a feed; the feed-ingest
  // validation in NEW-28 closes the upstream, this is defense-in-
  // depth.
  function _esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  return { init, build, getCampaigns, getHosts, renderCampaignsPage, renderHostsPage };
})();
