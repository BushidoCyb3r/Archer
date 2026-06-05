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

    const cyNodes = [];
    nodes.forEach(n => {
      cyNodes.push({
        data: {
          id: n.ip,
          label: n.ip,
          severity: n.severity,
          count: n.count,
        },
      });
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
          'border-width': 1,
          'border-color': _tok('--border-strong'),
          'width': 'mapData(count, 1, 50, 22, 60)',
          'height': 'mapData(count, 1, 50, 22, 60)',
        },
      },
      { selector: 'node[severity="CRITICAL"]', style: { 'background-color': crit } },
      { selector: 'node[severity="HIGH"]',     style: { 'background-color': high } },
      { selector: 'node[severity="MEDIUM"]',   style: { 'background-color': med } },
      { selector: 'node[severity="LOW"]',      style: { 'background-color': low } },
      { selector: 'node:selected', style: {
        'border-color': _tok('--accent-hover'),
        'border-width': 3,
      }},
      {
        selector: 'edge',
        style: {
          'width': 'data(weight)',
          'line-color': _tok('--fg-faint'),
          'target-arrow-color': _tok('--fg-faint'),
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'opacity': 0.6,
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
  // with no extra dependencies. animate:false avoids a layout animation that
  // wastes CPU on big graphs and looks dizzying.
  const LAYOUT = {
    name: 'cose',
    animate: false,
    nodeRepulsion: 8000,
    idealEdgeLength: 90,
    nodeOverlap: 12,
    fit: true,
    padding: 30,
  };

  function _renderGraph(elements) {
    const container = document.getElementById('graph-canvas');
    if (!container) return;
    if (_cy) { _cy.destroy(); _cy = null; }
    _cy = window.cytoscape({
      container,
      elements: [...elements.nodes, ...elements.edges],
      style: _buildStyle(),
      layout: LAYOUT,
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
    document.getElementById('graph-info').textContent =
      `${elements.stats.nodes} nodes · ${elements.stats.edges} edges · ${elements.stats.findings} findings`;
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
      if (_cy) _cy.fit(undefined, 30);
    });
    const relayoutBtn = document.getElementById('graph-relayout');
    if (relayoutBtn) relayoutBtn.addEventListener('click', () => {
      if (_cy) _cy.layout(LAYOUT).run();
    });
    // Re-skin a live graph without relayout if the theme changes while open.
    window.addEventListener('archer:themechange', () => {
      if (_cy) _cy.style(_buildStyle());
    });
  }

  return { init, showFindings, getCy, getDstHint };
})();
