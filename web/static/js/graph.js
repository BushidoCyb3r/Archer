// graph.js — Cytoscape.js network graph for findings and campaigns
//
// Cytoscape itself is a ~365KB blob, so the library is loaded lazily on first
// open: the dialog opens, shows a "Loading…" overlay, fetches the script, then
// builds the graph. Subsequent opens reuse the loaded module instantly.
//
// Elements model:
//   - One node per unique IP (src or dst) seen across the input findings.
//   - One edge per (src, dst) pair, with `weight` = number of findings on that
//     edge. Without aggregation, repeated connections produce a hairball.
//   - Node colour reflects the highest severity finding it participates in;
//     edge colour reflects the highest severity finding on that edge.
'use strict';

const Graph = (() => {
  let _cyLoaded = false;
  let _cyLoading = null;
  let _cy = null;
  let _onNodeClick = null;
  let _onEdgeClick = null;
  let _lastDstHint = '';

  // Load /static/js/cytoscape.min.js exactly once. Concurrent calls share the
  // same in-flight promise so we don't issue duplicate requests.
  function _loadCytoscape() {
    if (_cyLoaded) return Promise.resolve();
    if (_cyLoading) return _cyLoading;
    _cyLoading = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = '/static/js/cytoscape.min.js';
      s.onload  = () => { _cyLoaded = true; resolve(); };
      s.onerror = () => reject(new Error('Failed to load cytoscape.min.js'));
      document.head.appendChild(s);
    });
    return _cyLoading;
  }

  // Severity rank for max-aggregation across findings on the same edge/node.
  const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  function _maxSev(a, b) {
    return (SEV_RANK[a] ?? -1) >= (SEV_RANK[b] ?? -1) ? a : b;
  }

  function _isInternalIP(ip) {
    if (!ip) return false;
    const low = String(ip).toLowerCase();
    if (low === '::1' || low.startsWith('fe80:') || low.startsWith('fc') || low.startsWith('fd')) return true;
    const m = low.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return false;
    const a = +m[1], b = +m[2];
    if (a === 10 || a === 127) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }

  function _nodeLabel(ip, count) {
    return count >= 10 ? ip + ' · ' + count : ip;
  }

  // Build Cytoscape elements from a list of findings. Returns
  // {nodes:[], edges:[], stats:{...}}.
  function _buildElements(findings) {
    const nodes = new Map(); // ip -> {ip, severity, count}
    const edges = new Map(); // "src|dst" -> {src, dst, weight, severity}

    findings.forEach(f => {
      const src = f.src_ip;
      const dst = f.dst_ip;
      if (!src || !dst) return;

      [src, dst].forEach(ip => {
        const cur = nodes.get(ip);
        if (!cur) {
          nodes.set(ip, { ip, severity: f.severity || 'INFO', count: 1 });
        } else {
          cur.count += 1;
          cur.severity = _maxSev(cur.severity, f.severity || 'INFO');
        }
      });

      const key = src + '|' + dst;
      const cur = edges.get(key);
      if (!cur) {
        edges.set(key, { src, dst, weight: 1, severity: f.severity || 'INFO' });
      } else {
        cur.weight += 1;
        cur.severity = _maxSev(cur.severity, f.severity || 'INFO');
      }
    });

    let haloId = null, haloRank = -1;
    nodes.forEach(n => {
      if (_isInternalIP(n.ip)) return;
      const r = SEV_RANK[n.severity] ?? -1;
      if (r > haloRank) { haloRank = r; haloId = n.ip; }
    });

    const cyNodes = [];
    nodes.forEach(n => {
      const el = {
        data: {
          id: n.ip,
          label: _nodeLabel(n.ip, n.count),
          severity: n.severity,
          count: n.count,
          internal: _isInternalIP(n.ip) ? 1 : 0,
        },
      };
      if (n.ip === haloId && haloRank >= SEV_RANK.HIGH) {
        el.classes = haloRank === SEV_RANK.CRITICAL ? 'halo-crit' : 'halo-high';
      }
      cyNodes.push(el);
    });
    const cyEdges = [];
    let edgeId = 0;
    edges.forEach(e => {
      cyEdges.push({
        data: {
          id: 'e' + (edgeId++),
          source: e.src,
          target: e.dst,
          weight: Math.min(8, 1 + Math.log2(e.weight)),
          count: e.weight,
          severity: e.severity,
        },
      });
    });

    return {
      nodes: cyNodes,
      edges: cyEdges,
      stats: { nodes: cyNodes.length, edges: cyEdges.length, findings: findings.length },
    };
  }

  // cose is O(n^2) per tick; past a few hundred nodes a high fan-in campaign
  // graph wedges the layout. 200 keeps the hub-and-top-talkers structure
  // legible while staying well inside cose's comfortable range. Global
  // calibration constant, not an operator setting.
  const MAX_GRAPH_NODES = 200;

  // Reduce a built node/edge set to at most `cap` nodes, preserving the most
  // structurally significant ones: rank by node degree (incident edge count),
  // tie-break by finding count, and always keep the scoped dst hub if present.
  // Any edge touching a dropped node is removed so no dangling edges remain.
  function _capElements(cyNodes, cyEdges, dstHint, cap) {
    if (cyNodes.length <= cap) {
      return { nodes: cyNodes, edges: cyEdges, total: cyNodes.length, truncated: false };
    }
    const degree = new Map();
    cyEdges.forEach(e => {
      degree.set(e.data.source, (degree.get(e.data.source) || 0) + 1);
      degree.set(e.data.target, (degree.get(e.data.target) || 0) + 1);
    });
    const ranked = cyNodes.slice().sort((a, b) => {
      const da = degree.get(a.data.id) || 0, db = degree.get(b.data.id) || 0;
      if (db !== da) return db - da;
      return (b.data.count || 0) - (a.data.count || 0);
    });
    const keep = new Set();
    if (dstHint && cyNodes.some(n => n.data.id === dstHint)) keep.add(dstHint);
    for (let i = 0; i < ranked.length && keep.size < cap; i++) {
      keep.add(ranked[i].data.id);
    }
    return {
      nodes: cyNodes.filter(n => keep.has(n.data.id)),
      edges: cyEdges.filter(e => keep.has(e.data.source) && keep.has(e.data.target)),
      total: cyNodes.length,
      truncated: true,
    };
  }

  // Resolve a theme token to its computed value. Cytoscape paints to a canvas,
  // which can't read CSS vars, so the style array is built from live token
  // values each render and re-applied on archer:themechange.
  function _tok(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  // Style array — built from the active skin's tokens. Severity-coloured
  // nodes/edges so analysts can spot critical infrastructure at a glance
  // without expanding labels.
  function _buildStyle() {
    const crit = _tok('--sev-critical'), high = _tok('--sev-high'),
          med = _tok('--sev-medium'), low = _tok('--sev-low'),
          accent = _tok('--accent');
    return [
      {
        selector: 'node',
        style: {
          'background-color': accent,
          'background-opacity': 0.3,
          'border-width': 2,
          'border-color': accent,
          'shape': 'ellipse',
          'min-zoomed-font-size': 8,
          'label': 'data(label)',
          'color': _tok('--fg-primary'),
          'font-size': '10px',
          'font-family': 'ui-monospace, "SF Mono", Menlo, Monaco, Consolas, monospace',
          'text-valign': 'bottom',
          'text-halign': 'center',
          'text-margin-y': 4,
          'text-background-color': _tok('--bg-base'),
          'text-background-opacity': 0.7,
          'text-background-padding': '2px',
          'text-background-shape': 'roundrectangle',
          'width': 'mapData(count, 1, 50, 22, 60)',
          'height': 'mapData(count, 1, 50, 22, 60)',
        },
      },
      { selector: 'node[severity="CRITICAL"]', style: { 'background-color': crit, 'border-color': crit } },
      { selector: 'node[severity="HIGH"]',     style: { 'background-color': high, 'border-color': high } },
      { selector: 'node[severity="MEDIUM"]',   style: { 'background-color': med, 'border-color': med } },
      { selector: 'node[severity="LOW"]',      style: { 'background-color': low, 'border-color': low } },
      { selector: 'node[internal = 1]', style: { 'shape': 'round-rectangle' } },
      { selector: 'node:selected', style: {
        'border-color': _tok('--accent-hover'),
        'border-width': 3,
      }},
      { selector: '.halo-crit', style: { 'underlay-color': crit, 'underlay-opacity': 0.12, 'underlay-padding': 12 } },
      { selector: '.halo-high', style: { 'underlay-color': high, 'underlay-opacity': 0.12, 'underlay-padding': 12 } },
      { selector: '.dimmed',  style: { 'opacity': 0.15, 'text-opacity': 0.1 } },
      { selector: '.hovered', style: { 'min-zoomed-font-size': 0 } },
      {
        selector: 'edge',
        style: {
          'width': 'data(weight)',
          'line-color': _tok('--fg-faint'),
          'target-arrow-color': _tok('--fg-faint'),
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'line-cap': 'round',
          'opacity': 0.5,
          'arrow-scale': 0.8,
        },
      },
      { selector: 'edge[severity="CRITICAL"]', style: { 'line-color': crit, 'target-arrow-color': crit, 'opacity': 0.85 } },
      { selector: 'edge[severity="HIGH"]',     style: { 'line-color': high, 'target-arrow-color': high, 'opacity': 0.8 } },
      { selector: 'edge[severity="MEDIUM"]',   style: { 'line-color': med, 'target-arrow-color': med, 'opacity': 0.75 } },
      { selector: 'edge:selected', style: { 'line-color': accent, 'target-arrow-color': accent, 'opacity': 1, 'width': 4 } },
    ];
  }

  // Cytoscape's bundled `cose` layout produces decent force-directed results
  // with no extra dependencies. Positions are computed synchronously;
  // animate:'end' animates only the final placement into view. Reduced-motion
  // keeps animate:false entirely.
  const LAYOUT = {
    name: 'cose',
    animate: false,
    nodeRepulsion: 8000,
    idealEdgeLength: 90,
    nodeOverlap: 12,
    fit: true,
    padding: 30,
  };

  function _reducedMotion() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function _layoutOpts() {
    return Object.assign({}, LAYOUT, _reducedMotion()
      ? {}
      : { animate: 'end', animationDuration: 400, animationEasing: 'ease-out' });
  }

  function _renderGraph(elements) {
    const container = document.getElementById('graph-canvas');
    if (!container) return;
    if (_cy) { _cy.destroy(); _cy = null; }
    const capped = _capElements(elements.nodes, elements.edges, _lastDstHint, MAX_GRAPH_NODES);
    _cy = window.cytoscape({
      container,
      elements: [...capped.nodes, ...capped.edges],
      style: _buildStyle(),
      layout: _layoutOpts(),
      wheelSensitivity: 0.2,
      minZoom: 0.1,
      maxZoom: 4,
    });
    _cy.on('tap', 'node', evt => {
      if (_onNodeClick) _onNodeClick(evt.target.id());
    });
    _cy.on('tap', 'edge', evt => {
      if (_onEdgeClick) _onEdgeClick(evt.target.data('source'), evt.target.data('target'));
    });
    _cy.on('mouseover', 'node', evt => {
      _cy.batch(() => {
        evt.target.addClass('hovered');
        _cy.elements().difference(evt.target.closedNeighborhood()).addClass('dimmed');
      });
    });
    _cy.on('mouseout', 'node', () => {
      _cy.batch(() => {
        _cy.elements().removeClass('dimmed hovered');
      });
    });
    const shownNodes = capped.truncated ? capped.nodes.length : elements.stats.nodes;
    const shownEdges = capped.truncated ? capped.edges.length : elements.stats.edges;
    let info = `${shownNodes} nodes · ${shownEdges} edges · ${elements.stats.findings} findings`;
    if (capped.truncated) {
      info += ` · showing top ${shownNodes} of ${capped.total} nodes`;
    }
    document.getElementById('graph-info').textContent = info;
  }

  async function _open(findings, subtitle) {
    const dlg = document.getElementById('graph-dialog');
    if (!dlg) return;
    document.getElementById('graph-dlg-subtitle').textContent = subtitle || '';
    document.getElementById('graph-info').textContent = '';
    const overlay = document.getElementById('graph-loading');
    overlay.classList.add('visible');
    dlg.showModal();
    try {
      await _loadCytoscape();
      const elements = _buildElements(findings);
      _renderGraph(elements);
    } catch (e) {
      document.getElementById('graph-info').textContent = 'Error: ' + e.message;
    } finally {
      overlay.classList.remove('visible');
    }
  }

  function showFindings(findings, subtitle, dstHint) {
    _lastDstHint = dstHint || '';
    _open(findings || [], subtitle);
  }

  // Exposed so the dropdown wiring in app.js can drive PNG/JPEG export.
  // Returning the live cy lets the caller pick its own scale, full-vs-view,
  // and quality without us re-implementing those knobs here.
  function getCy() { return _cy; }
  function getDstHint() { return _lastDstHint; }

  function init(opts) {
    opts = opts || {};
    _onNodeClick = opts.onNodeClick || null;
    _onEdgeClick = opts.onEdgeClick || null;

    const closeBtn = document.getElementById('graph-dlg-close');
    if (closeBtn) closeBtn.addEventListener('click', () => {
      document.getElementById('graph-dialog').close();
    });
    const fitBtn = document.getElementById('graph-fit');
    if (fitBtn) fitBtn.addEventListener('click', () => {
      if (_cy) _cy.animate({ fit: { padding: 30 } }, { duration: _reducedMotion() ? 0 : 400, easing: 'ease-out' });
    });
    const relayoutBtn = document.getElementById('graph-relayout');
    if (relayoutBtn) relayoutBtn.addEventListener('click', () => {
      if (_cy) _cy.layout(_layoutOpts()).run();
    });
    // Re-skin a live graph without relayout if the theme changes while open.
    window.addEventListener('archer:themechange', () => {
      if (_cy) _cy.style(_buildStyle());
    });
  }

  return { init, showFindings, getCy, getDstHint };
})();
