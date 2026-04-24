// campaigns.js — campaigns and hosts tab builders
'use strict';

const Campaigns = (() => {
  let _onCtx = null;

  function init(onCtx) {
    _onCtx = onCtx;
  }

  function build(findings) {
    _buildCampaigns(findings);
    _buildHosts(findings);
  }

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
    const campaigns = [...map.values()].filter(e => e.srcs.size >= 2)
      .sort((a, b) => b.maxScore - a.maxScore);

    const tbody = document.getElementById('campaigns-tbody');
    tbody.innerHTML = '';
    if (campaigns.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:var(--fg-dim);padding:12px">No campaign patterns detected</td></tr>';
      return;
    }
    campaigns.forEach(e => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td title="${e.dst}">${e.dst}</td>
        <td>${e.port}</td>
        <td class="hosts">${e.srcs.size}</td>
        <td style="color:${_scoreColor(e.maxScore)};font-weight:700">${e.maxScore}</td>
        <td style="font-family:monospace;font-size:10px">${[...e.srcs].join(', ')}</td>`;
      tr.addEventListener('contextmenu', ev => {
        ev.preventDefault();
        if (_onCtx) _onCtx(ev, {dst_ip: e.dst, src_ip: [...e.srcs][0] || '', dst_port: e.port});
      });
      tbody.appendChild(tr);
    });
  }

  function _buildHosts(findings) {
    const map = new Map(); // src_ip → {score, findings, types, topSev}
    const SEV_ORDER = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4, IOC_HIT:5};
    findings.forEach(f => {
      if (!f.src_ip) return;
      if (!map.has(f.src_ip)) map.set(f.src_ip, {ip: f.src_ip, score: 0, count: 0, types: new Set(), topSev: 'INFO'});
      const e = map.get(f.src_ip);
      e.count++;
      e.types.add(f.type || '');
      if (f.score > e.score) e.score = f.score;
      if ((SEV_ORDER[f.severity] ?? 99) < (SEV_ORDER[e.topSev] ?? 99)) e.topSev = f.severity;
    });

    const hosts = [...map.values()].sort((a, b) => b.score - a.score);
    const tbody = document.getElementById('hosts-tbody');
    tbody.innerHTML = '';
    if (hosts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:var(--fg-dim);padding:12px">No host data</td></tr>';
      return;
    }
    hosts.forEach(e => {
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

  return { init, build };
})();
