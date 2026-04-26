// campaigns.js — campaigns and hosts tab builders
'use strict';

const Campaigns = (() => {
  let _onCtx = null;
  let _isOrgIP = () => true; // predicate set by app.js; default to "everything is internal" so the panel works before init runs
  let _campaigns = []; // exposed via getCampaigns() for export
  let _hosts = [];     // exposed via getHosts() for export

  function init(onCtx, isOrgIP) {
    _onCtx = onCtx;
    if (typeof isOrgIP === 'function') _isOrgIP = isOrgIP;
  }

  function build(findings) {
    _buildCampaigns(findings);
    _buildHosts(findings);
  }

  function getCampaigns() { return _campaigns; }
  function getHosts() { return _hosts; }

  function _buildCampaigns(findings) {
    const map = new Map(); // dst_ip:dst_port → {srcs, maxScore, type}
    findings.forEach(f => {
      const key = `${f.dst_ip || f.domain || ''}:${f.dst_port || ''}`;
      if (!key.startsWith(':')) {
        if (!map.has(key)) map.set(key, {dst: f.dst_ip || f.domain || '', port: f.dst_port || '', srcs: new Set(), maxScore: 0, types: new Set()});
        const e = map.get(key);
        if (f.src_ip) e.srcs.add(f.src_ip);
        if (f.score > e.maxScore) e.maxScore = f.score;
        e.types.add(f.type || '');
      }
    });

    // Filter: ≥ 2 distinct source IPs
    _campaigns = [...map.values()].filter(e => e.srcs.size >= 2)
      .sort((a, b) => b.maxScore - a.maxScore);

    const tbody = document.getElementById('campaigns-tbody');
    tbody.innerHTML = '';
    if (_campaigns.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:var(--fg-dim);padding:12px">No campaign patterns detected</td></tr>';
      return;
    }
    _campaigns.forEach(e => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="color:${_scoreColor(e.maxScore)};font-weight:700;text-align:center">${e.maxScore}</td>
        <td title="${e.dst}">${e.dst}</td>
        <td>${e.port}</td>
        <td class="hosts">${e.srcs.size}</td>
        <td style="font-family:monospace;font-size:11px;word-break:break-all">${[...e.srcs].join(', ')}</td>`;
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

  function _buildHosts(findings) {
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

    _hosts = [...map.values()].sort((a, b) => b.score - a.score);
    const tbody = document.getElementById('hosts-tbody');
    tbody.innerHTML = '';
    if (_hosts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:var(--fg-dim);padding:12px">No host data</td></tr>';
      return;
    }
    _hosts.forEach(e => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:monospace">${e.ip}</td>
        <td class="score" style="color:${_scoreColor(e.score)}">${e.score}</td>
        <td style="text-align:center">${e.count}</td>
        <td style="color:${_sevColor(e.topSev)};font-weight:700">${e.topSev}</td>
        <td style="font-size:11px;color:var(--fg-dim)">${[...e.types].slice(0,4).join(', ')}</td>`;
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

  return { init, build, getCampaigns, getHosts };
})();
