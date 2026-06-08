// app.js — main application state machine
'use strict';

(async () => {

  // ── State ──────────────────────────────────────────────────────────────────
  let _allFindings     = [];
  let _deltaMode       = false;
  let _selectedFinding = null;
  let _pivotCtx        = null; // {type:'host'|'campaign', label, hrs?, findings[]}
  let _ctxFinding      = null;
  let _watchActive     = false;
  let _tabMode         = 'findings'; // 'findings' | 'ack' | 'esc' | 'ioc' | 'dismissed' (drives findings-table filter)
  let _activeTab       = 'findings'; // 'findings' | 'ack' | 'esc' | 'ioc' | 'dismissed' | 'campaigns' | 'hosts' (which panel is visible)
  let _iocSet          = new Set();  // live cache of IOC list IPs for instant tab overlay
  let _allowSet        = new Set();  // live cache of allowlist entries — used by the right-click menu's state-aware items
  let _logsDir         = '/logs';
  let _currentUser     = null;
  let _orgCIDRs        = []; // admin-supplied CIDRs that augment the built-in private ranges for the Hosts tab

  // Per-tab state. Each findings-style tab (findings / ack / esc / ioc)
  // keeps its own loaded findings, pagination position, and total count.
  // Tab switches read from cache when loaded=true (instant), fetch when
  // loaded=false (first visit) or when a global invalidation has set
  // loaded back to false (filter change, delta toggle, SSE done event).
  // Page size is shared across tabs — it's a per-session display
  // preference, not per-tab.
  function _newTabState() {
    return {
      findings: [],
      offset:   0,
      total:    0,
      hasMore:  false,
      loaded:   false,
    };
  }
  const _tabState = {
    findings:  _newTabState(),
    ack:       _newTabState(),
    esc:       _newTabState(),
    ioc:       _newTabState(),
    dismissed: _newTabState(),
  };
  function _curTab() { return _tabState[_tabMode] || _tabState.findings; }
  function _invalidateAllTabs() {
    Object.values(_tabState).forEach(t => {
      t.loaded   = false;
      t.findings = [];
      t.offset   = 0;
      t.total    = 0;
      t.hasMore  = false;
    });
    _invalidateAggregate();
    _countsLoaded = false;
  }
  let _pageSize = 100;

  // Aggregate cache: findings within the current time range used to
  // power roll-up views (Campaigns / Hosts top-level, plus
  // Dismissed > Campaigns sub-tab). The `mode` field tracks which
  // tab's filter the cache was built for — top-level Campaigns/Hosts
  // fetch with no status filter; Dismissed > Campaigns fetches with
  // status=dismissed. Switching between modes invalidates the cache
  // so the next _ensureAggregate refetches with the right scope.
  let _aggregateState = { findings: [], loaded: false, mode: null };
  // Per-tab render-pagination state for the aggregate tabs. offset is the
  // 0-based start index of the current page in the full _campaigns /
  // _hosts arrays; total is the full aggregated row count. Independent
  // per tab so paging on Campaigns doesn't affect Hosts.
  const _aggTabState = {
    campaigns: { offset: 0, total: 0 },
    hosts:     { offset: 0, total: 0 },
  };
  // _aggTabKey maps an aggregate tab mode to the offset/total record in
  // _aggTabState. Dismissed > Campaigns shares the campaigns record since
  // it renders into the same panel — the aggregate cache invalidates on
  // mode switch, so the offset doesn't need to persist across modes.
  function _aggTabKey(mode) {
    return mode === 'dismissed-campaigns' ? 'campaigns' : mode;
  }
  function _invalidateAggregate() {
    _aggregateState = { findings: [], loaded: false, mode: null };
    _aggTabState.campaigns = { offset: 0, total: 0 };
    _aggTabState.hosts     = { offset: 0, total: 0 };
  }
  let _countsLoaded = false;

  // Show-Dismissed toggle state. When true the Dismissed tab is
  // visible in the tab strip and its count surfaces in the info line.
  // When false the tab is hidden entirely (an analyst who hasn't
  // dismissed anything yet shouldn't see an extra navigation slot).
  // Persisted in localStorage so the analyst's preference survives
  // reload — same pattern the dock collapse state uses.
  let _showDismissed = false;
  // _dismissedSubTab tracks which sub-view of the Dismissed tab is
  // active: 'findings' (flat list of dismissed findings) or
  // 'campaigns' (campaigns rolled up over only dismissed findings).
  // Persists in localStorage so the analyst's choice survives reload.
  // Hosts is intentionally absent — bulk dismissal over a host's
  // findings would erase the host's risk story.
  let _dismissedSubTab = 'findings';
  function _setDismissedSubTab(name) {
    if (name !== 'findings' && name !== 'campaigns') name = 'findings';
    _dismissedSubTab = name;
    try { localStorage.setItem('archer:dismissed-subtab', name); } catch (_) {}
    document.querySelectorAll('.sub-tab-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.dismissedSub === name);
    });
  }
  function _initDismissedSubTabs() {
    try {
      const stored = localStorage.getItem('archer:dismissed-subtab');
      if (stored) _dismissedSubTab = stored;
    } catch (_) {}
    document.querySelectorAll('.sub-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        _setDismissedSubTab(btn.dataset.dismissedSub);
        // If we're already on the Dismissed top-level tab, re-route
        // immediately to the new sub-view.
        if (_activeTab === 'dismissed') _routeDismissedSubTab();
      });
    });
    _setDismissedSubTab(_dismissedSubTab);
  }
  // _routeDismissedSubTab swaps which panel is visible based on the
  // active Dismissed sub-tab. findings sub-tab → #tab-findings with
  // status=dismissed (existing flat-list behavior). campaigns sub-tab
  // → #tab-campaigns rebuilt from dismissed-only aggregate.
  async function _routeDismissedSubTab() {
    if (_activeTab !== 'dismissed') return;
    if (_dismissedSubTab === 'campaigns') {
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      const panel = document.getElementById('tab-campaigns');
      if (panel) panel.classList.add('active');
      _tabMode = 'dismissed-campaigns';
      await _ensureAggregate();
    } else {
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      const panel = document.getElementById('tab-findings');
      if (panel) panel.classList.add('active');
      _tabMode = 'dismissed';
      _showCurrentTab();
    }
  }
  function _applyShowDismissed(on) {
    _showDismissed = !!on;
    const btn = document.getElementById('dismissed-view-btn');
    const tog = document.getElementById('show-dismissed-btn');
    if (btn) btn.style.display = on ? '' : 'none';
    // Toggle chip lives in the query-chips row, right of "+ more": accent
    // blue (like Run) when on, the default chip look when off.
    if (tog) {
      tog.classList.toggle('chip-on', on);
      tog.setAttribute('aria-pressed', on ? 'true' : 'false');
    }
    // If the analyst hides the Dismissed view while it's active, route
    // them back to Findings so they don't end up staring at an invisible
    // view.
    if (!on && _activeTab === 'dismissed') {
      const def = document.querySelector('.view-btn[data-tab="findings"]');
      if (def) def.click();
    }
    updateInfoLine();
  }
  function _initShowDismissedToggle() {
    try {
      const stored = localStorage.getItem('archer:show-dismissed');
      _applyShowDismissed(stored === 'true');
    } catch (_) {
      _applyShowDismissed(false);
    }
    const tog = document.getElementById('show-dismissed-btn');
    if (!tog) return;
    tog.addEventListener('click', () => {
      const next = !_showDismissed;
      try { localStorage.setItem('archer:show-dismissed', String(next)); } catch (_) {}
      _applyShowDismissed(next);
    });
  }

  // Dock state — which tab is active inside the findings detail pane
  // (Detail / Notes / TI Results) and whether the dock is collapsed.
  // Both persist in localStorage so the analyst's last view shape
  // survives reload. `dock-tab` lives separately from the main tab
  // (Findings/Ack/Esc/Dismissed/...) so flipping main tabs doesn't
  // reset which dock tab the analyst was reading from.
  let _dockTab = 'detail'; // 'detail' | 'notes' | 'ti'
  function _setDockTab(name) {
    if (name !== 'detail' && name !== 'notes' && name !== 'ti') name = 'detail';
    _dockTab = name;
    try { localStorage.setItem('archer:dock-tab', name); } catch (_) {}
    document.querySelectorAll('.dock-tab-btn').forEach(b => {
      const on = b.dataset.dockTab === name;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('.dock-tab-panel').forEach(p => {
      const on = p.id === 'dock-panel-' + name;
      p.classList.toggle('active', on);
      if (on) p.removeAttribute('hidden');
      else p.setAttribute('hidden', '');
    });
  }
  function _initDockTabs() {
    try {
      const stored = localStorage.getItem('archer:dock-tab');
      if (stored) _dockTab = stored;
    } catch (_) {}
    _setDockTab(_dockTab);
    document.querySelectorAll('.dock-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => _setDockTab(btn.dataset.dockTab));
    });
  }
  // Dock collapse: hides tabs/body/footer so the table claims the
  // vertical space the dock was taking. Clicking a row auto-expands
  // because seeing detail is the point of clicking — keeping the
  // dock collapsed when an analyst actively asks for content would
  // be hostile UX.
  function _isDockCollapsed() {
    const pane = document.getElementById('detail-pane');
    return pane && pane.getAttribute('data-collapsed') === 'true';
  }
  // persist=true on the explicit toggle button so the operator's choice
  // sticks across reloads; persist=false on the row-click auto-expand
  // so a transient "show me this row" doesn't overwrite a standing
  // "keep the dock collapsed" preference.
  function _setDockCollapsed(on, persist = true) {
    const pane = document.getElementById('detail-pane');
    if (!pane) return;
    if (on) pane.setAttribute('data-collapsed', 'true');
    else pane.removeAttribute('data-collapsed');
    const btn = document.getElementById('dock-collapse-btn');
    if (btn) {
      btn.setAttribute('aria-expanded', on ? 'false' : 'true');
      btn.title = on ? 'Expand details pane' : 'Collapse details pane';
    }
    if (persist) {
      try { localStorage.setItem('archer:dock-collapsed', on ? 'true' : 'false'); } catch (_) {}
    }
  }
  function _initDockCollapse() {
    let collapsed = false;
    try { collapsed = localStorage.getItem('archer:dock-collapsed') === 'true'; } catch (_) {}
    _setDockCollapsed(collapsed);
    const btn = document.getElementById('dock-collapse-btn');
    if (btn) btn.addEventListener('click', () => _setDockCollapsed(!_isDockCollapsed()));
  }
  // Drag-to-resize: grab the top edge of the dock and pull. Sets a
  // --dock-height CSS variable on #detail-pane that the .css file
  // consumes via height: var(--dock-height, auto). Clamping bounds the
  // result so the operator can't accidentally drag the dock to a sliver
  // or push the table off-screen. Persists on mouseup so the operator's
  // last height survives reloads, mirroring the collapse preference.
  const DOCK_HEIGHT_MIN = 120;
  function _dockHeightMax() { return Math.floor(window.innerHeight * 0.8); }
  function _setDockHeight(px, persist) {
    const pane = document.getElementById('detail-pane');
    if (!pane) return;
    const clamped = Math.max(DOCK_HEIGHT_MIN, Math.min(_dockHeightMax(), Math.round(px)));
    pane.style.setProperty('--dock-height', clamped + 'px');
    if (persist) {
      try { localStorage.setItem('archer:dock-height', String(clamped)); } catch (_) {}
    }
  }
  function _initDockResize() {
    const handle = document.getElementById('dock-resize-handle');
    const pane = document.getElementById('detail-pane');
    if (!handle || !pane) return;
    try {
      const stored = parseInt(localStorage.getItem('archer:dock-height'), 10);
      if (Number.isFinite(stored)) _setDockHeight(stored, false);
    } catch (_) {}
    let dragging = false;
    handle.addEventListener('mousedown', e => {
      if (_isDockCollapsed()) return;
      dragging = true;
      document.body.classList.add('dock-resizing');
      e.preventDefault();
    });
    document.addEventListener('mousemove', e => {
      if (!dragging) return;
      // Pane sits at the bottom of the viewport; height = viewport bottom
      // minus current mouse Y. Drag up → pane grows; drag down → shrinks.
      _setDockHeight(window.innerHeight - e.clientY, false);
    });
    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      document.body.classList.remove('dock-resizing');
      const cur = pane.style.getPropertyValue('--dock-height');
      const px = parseInt(cur, 10);
      if (Number.isFinite(px)) {
        try { localStorage.setItem('archer:dock-height', String(px)); } catch (_) {}
      }
    });
    // Viewport shrink can push the dock past 80% — re-clamp so the
    // operator doesn't end up with the table squashed off-screen.
    window.addEventListener('resize', () => {
      const cur = parseInt(pane.style.getPropertyValue('--dock-height'), 10);
      if (Number.isFinite(cur)) _setDockHeight(cur, false);
    });
  }
  // Keyboard shortcuts: 1/2/3 flip the dock tabs when the focus
  // isn't inside a text input. Lets the analyst rapid-triage with
  // one keystroke per tab during the back-and-forth workflow.
  function _initDockKeyboardShortcuts() {
    document.addEventListener('keydown', e => {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const t = e.target;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
      if (e.key === '1') { _setDockTab('detail'); }
      else if (e.key === '2') { _setDockTab('notes'); }
      else if (e.key === '3') { _setDockTab('ti'); }
    });
  }

  // Cached Archer version metadata fetched from /api/version. Populated by
  // _loadVersion() during init so JSON exports and the statusbar/About dialog
  // all read from a single source of truth instead of literal strings.
  // Defaults match internal/version/version.go for the case where the fetch
  // hasn't completed yet (rare — exports are always user-initiated).
  let _archerVersion   = { version: 'v0.1.0', commit: 'unknown', build_time: 'unknown' };

  // Host Risk Score is the per-host roll-up the analyzer emits at the end
  // of every run (composite of the per-host detection types). The Findings
  // tab is for discrete network events; this score belongs in the Hosts
  // tab, where the row is reachable by clicking the host's IP. Filtering
  // here keeps the counts, type dropdown, and notification jumps consistent.
  const HOST_FINDING_TYPES = new Set(['Host Risk Score']);
  function _isHostFinding(f) { return HOST_FINDING_TYPES.has(f.type); }
  function _networkFindings(arr) { return arr.filter(f => !_isHostFinding(f)); }

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

  // showQueryError drops a red toast in from the top of the page when the
  // findings query is rejected (bad syntax, unknown field, unknown type).
  // The ".show" class drives the slide-in; hideQueryError retracts it the
  // moment a valid query lands so a stale error never lingers over results.
  function showQueryError(msg, duration = 6000) {
    const t = document.getElementById('query-toast');
    if (!t) return;
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(t._timer);
    t._timer = setTimeout(() => t.classList.remove('show'), duration);
  }

  function hideQueryError() {
    const t = document.getElementById('query-toast');
    if (!t) return;
    clearTimeout(t._timer);
    t.classList.remove('show');
  }

  // _surfaceQueryError inspects a failed findings fetch: when it's the 400 a
  // rejected query produces, it shows the red toast and returns true so the
  // caller can stop. Every query-bearing endpoint (list, aggregate roll-up,
  // counts) routes its !r.ok path through this, so no submission path can let
  // a bad query fail silently — the bug was that only the list view toasted,
  // leaving the Campaigns/Hosts tabs quiet.
  async function _surfaceQueryError(r) {
    if (r.status !== 400) return false;
    const e = await r.json().catch(() => ({}));
    showQueryError(e.error || r.statusText);
    return true;
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
  // Pagination is Findings-tab-only — the other tabs (Ack / Esc / IOC)
  // hold tiny result sets that fit comfortably in a single fetch, and
  // the per-page selector + Load More button only make sense for the
  // big slab. Non-Findings tabs request limit=50000 (server cap) which
  // returns the entire matching set in one round-trip.
  // Findings/Ack/Esc/IOC paginate server-side via /api/findings; each tab
  // owns its own offset/total/loaded state in _tabState. Campaigns and
  // Hosts paginate client-side over _aggregateState (the full unfiltered
  // set) by slicing the rendered output — see _renderCampaignsPage /
  // _renderHostsPage. _isPaginatedTab is true for both groups; the
  // pagination footer shows for every tab.
  const _findingsTabs = new Set(['findings', 'ack', 'esc', 'ioc', 'dismissed']);
  const _aggregateTabs = new Set(['campaigns', 'hosts', 'dismissed-campaigns']);
  function _isPaginatedTab(tab) { return _findingsTabs.has(tab) || _aggregateTabs.has(tab); }
  function _isFindingsTab(tab)  { return _findingsTabs.has(tab); }
  function _isAggregateTab(tab) { return _aggregateTabs.has(tab); }
  const _FULL_FETCH_LIMIT = 50000;

  // loadFindings fetches one page of findings for the active tab and
  // replaces ts.findings with the result. Page selection is offset-based:
  // pass opts.gotoOffset to navigate to a specific page (used by the
  // first/back/next/last buttons). The default (no opts) loads page 1.
  async function loadFindings(params = {}, opts = {}) {
    const ts = _curTab();
    const paginated = _isFindingsTab(_tabMode);
    if (typeof opts.gotoOffset === 'number') {
      ts.offset = Math.max(0, opts.gotoOffset);
    } else {
      ts.offset = 0;
    }

    const merged = Object.assign({}, params, {
      limit:  String(paginated ? _pageSize : _FULL_FETCH_LIMIT),
      offset: String(paginated ? ts.offset : 0),
    });
    const qs = new URLSearchParams(merged).toString();
    const r = await fetch('/api/findings' + (qs ? '?' + qs : ''));
    if (!r.ok) {
      // A bad query (unknown field, malformed syntax, unknown finding type)
      // is the only 400 this endpoint returns. Surface it as a red toast and
      // keep the prior results on screen rather than throwing an unhandled
      // rejection that leaves the analyst with no feedback.
      if (await _surfaceQueryError(r)) return;
      throw (r.statusText);
    }
    hideQueryError();
    const page = await r.json();
    ts.total   = parseInt(r.headers.get('X-Total-Count') || '0', 10) || 0;
    ts.findings = Array.isArray(page) ? page : [];
    ts.loaded = true;

    _allFindings = ts.findings;
    _renderCurrentTab({ preserveScroll: opts.preserveScroll });
  }

  // _renderCurrentTab paints whatever the current tab's cache holds.
  // The findings table view excludes Host Risk Score rows — those are
  // a per-host roll-up surfaced through the Hosts tab, not a network
  // event. Status / ioc_only / delta / date filters were already
  // applied server-side via _currentFilterParams.
  function _renderCurrentTab(opts) {
    const ts = _curTab();
    _allFindings = ts.findings;
    _updatePaginationFooter();
    const networkOnly = _networkFindings(ts.findings);
    // Type and sensor dropdowns are populated by _loadFacets from a
    // dedicated /api/findings/facets call so they reflect every
    // distinct value across the dataset — not just what's on the
    // current paginated page.
    Table.load(networkOnly, opts);
    updateInfoLine();
  }

  // _ensureAggregate fetches every finding within the current time
  // range (no status / ioc_only filter, no pagination beyond the
  // server's 50k cap) and rebuilds the Campaigns + Hosts roll-ups.
  // Cached for the rest of the session until something invalidates it.
  // Each aggregate tab maintains its own page offset in _aggTabState;
  // build() renders the current page slice for both tables, and the
  // first/back/next/last buttons drive _renderAggregatePage to advance.
  async function _ensureAggregate() {
    const mode = _tabMode; // 'campaigns' | 'hosts' | 'dismissed-campaigns'
    if (!_aggregateState.loaded || _aggregateState.mode !== mode) {
      const params = _currentFilterParams();
      delete params.status;
      delete params.ioc_only;
      delete params.delta;
      params.limit = String(_FULL_FETCH_LIMIT);
      params.offset = '0';
      // Top-level Campaigns/Hosts: no status filter (existing
      // behavior — dismissed findings are excluded by the backend's
      // default-exclude rule). Dismissed > Campaigns: status=dismissed
      // so the roll-up covers only the dismissed bucket.
      if (mode === 'dismissed-campaigns') params.status = 'dismissed';
      const qs = new URLSearchParams(params).toString();
      try {
        const r = await fetch('/api/findings' + (qs ? '?' + qs : ''));
        if (!r.ok) { await _surfaceQueryError(r); return; }
        hideQueryError();
        const all = await r.json();
        _aggregateState.findings = Array.isArray(all) ? all : [];
        _aggregateState.loaded = true;
        _aggregateState.mode = mode;
      } catch (e) { /* swallow — stale cache is OK */ return; }
    }
    Campaigns.build(_aggregateState.findings, {
      campaignsOffset: _aggTabState.campaigns.offset,
      campaignsLimit:  _pageSize,
      hostsOffset:     _aggTabState.hosts.offset,
      hostsLimit:      _pageSize,
    });
    _aggTabState.campaigns.total = Campaigns.getCampaigns().length;
    _aggTabState.hosts.total     = Campaigns.getHosts().length;
    _clampAggOffset(_aggTabState.campaigns);
    _clampAggOffset(_aggTabState.hosts);
    _updatePaginationFooter();
    _updateViewBadges();
  }

  // _clampAggOffset keeps an aggregate tab's offset within [0, total).
  // Page-size changes or filter shifts can leave a stale offset past the
  // last page; this snaps it to the last full page.
  function _clampAggOffset(state) {
    if (state.total <= 0) { state.offset = 0; return; }
    const lastPageOffset = Math.max(0, Math.floor((state.total - 1) / _pageSize) * _pageSize);
    if (state.offset > lastPageOffset) state.offset = lastPageOffset;
    if (state.offset < 0) state.offset = 0;
  }

  // _renderAggregatePage re-renders just the active aggregate tab from
  // the cached _campaigns / _hosts arrays. Used by the page-nav buttons
  // so navigation doesn't recompute the aggregation.
  function _renderAggregatePage() {
    if (_tabMode === 'campaigns' || _tabMode === 'dismissed-campaigns') {
      Campaigns.renderCampaignsPage(_aggTabState.campaigns.offset, _pageSize);
    } else if (_tabMode === 'hosts') {
      Campaigns.renderHostsPage(_aggTabState.hosts.offset, _pageSize);
    }
    _updatePaginationFooter();
  }

  // _loadFacets populates the Type and Sensor filter dropdowns with
  // *every* distinct value across the dataset (subject to the
  // non-dropdown filters — search, severity, score, src/dst, port,
  // time). Without this the dropdowns showed only the values present
  // on the current paginated page, which let an analyst miss types
  // that existed elsewhere in the dataset. Called on init and after
  // every analysis completes; refresh-on-filter-change is intentionally
  // omitted so the dropdowns don't reshape under the cursor.
  async function _loadFacets() {
    try {
      // The Type chip lists every type in the corpus, not just those
      // matching the current query — narrowing it by `q` would make a type
      // vanish from the menu the moment you picked it. So no params.
      const r = await fetch('/api/findings/facets');
      if (!r.ok) return;
      const data = await r.json();
      _populateTypeChip(Array.isArray(data.types) ? data.types : []);
    } catch (e) { /* swallow — a stale chip menu is acceptable */ }
  }

  // _populateTypeChip rebuilds the Type chip menu from the facet list.
  // Picking an item upserts a type: token into the query box; multi-word
  // types are quoted so they parse as a single value.
  function _populateTypeChip(types) {
    const menu = document.getElementById('chip-menu-type');
    if (!menu) return;
    const items = [];
    // Synthetic beacon-family selector. Server-side the query maps
    // type:beacons to model.IsBeaconType, scoping to every beacon type.
    items.push({value: 'beacons', label: 'Beacons (all types)'});
    types.forEach(t => {
      // Host Risk Score is a per-host roll-up surfaced through the Hosts
      // view — not a network event the Type chip should expose.
      if (HOST_FINDING_TYPES.has(t)) return;
      items.push({value: t, label: t});
    });
    menu.innerHTML = '';
    items.forEach(it => {
      const li = document.createElement('li');
      li.textContent = it.label;
      li.addEventListener('click', () => {
        const v = /\s/.test(it.value) ? `"${it.value}"` : it.value;
        _setQueryToken('type', v);
        applyFilter();
        menu.classList.add('hidden');
      });
      menu.appendChild(li);
    });
    const clear = document.createElement('li');
    clear.className = 'chip-clear';
    clear.textContent = 'Clear type';
    clear.addEventListener('click', () => { _setQueryToken('type', ''); applyFilter(); menu.classList.add('hidden'); });
    menu.appendChild(clear);
  }

  // _loadCounts fetches the per-status totals for the info line so the
  // tab counters ("23 open • 1 ack'd • 0 escalated") are accurate
  // without requiring a visit to each tab. Cheap server-side aggregation.
  async function _loadCounts() {
    const params = _currentFilterParams();
    delete params.status;
    delete params.ioc_only;
    params.limit = '1';
    params.offset = '0';
    const qs = new URLSearchParams(params).toString();
    try {
      const r = await fetch('/api/findings/counts' + (qs ? '?' + qs : ''));
      if (!r.ok) { await _surfaceQueryError(r); return; }
      const c = await r.json();
      _tabState.findings.total  = c.open || 0;
      _tabState.ack.total       = c.ack  || 0;
      _tabState.esc.total       = c.esc  || 0;
      _tabState.ioc.total       = c.ioc  || 0;
      _tabState.dismissed.total = c.dis  || 0;
      _countsLoaded = true;
      // Per-tab `loaded` is reserved for "findings rows fetched". The
      // counts endpoint only populates totals; the row data arrives on
      // first visit. updateInfoLine reads totals directly from the
      // counts response.
      updateInfoLine();
    } catch (e) { /* swallow */ }
  }

  // _showCurrentTab is the entry point for tab clicks. Renders from the
  // tab's cache when it's already loaded; fetches on first visit.
  async function _showCurrentTab(opts) {
    const ts = _curTab();
    if (ts.loaded) {
      _renderCurrentTab(opts);
    } else {
      await loadFindings(_currentFilterParams(), opts);
    }
  }

  // _updatePaginationFooter updates the "Showing X–Y of Z", "Page N of M",
  // and the four page-nav buttons' enabled state for the active tab.
  // The shown range is offset+1 .. offset+slice.length so the analyst
  // sees what window of the full set is currently rendered.
  function _updatePaginationFooter() {
    const wrap = document.getElementById('findings-pagination');
    const paginated = _isPaginatedTab(_tabMode);
    if (wrap) wrap.style.display = paginated ? '' : 'none';
    if (!paginated) return;

    let offset, total, sliceLen;
    if (_isAggregateTab(_tabMode)) {
      const a = _aggTabState[_aggTabKey(_tabMode)];
      offset = a.offset;
      total  = a.total;
      sliceLen = Math.min(_pageSize, Math.max(0, total - offset));
    } else {
      const ts = _curTab();
      offset = ts.offset;
      total  = ts.total;
      sliceLen = ts.findings.length;
    }

    const shownEl = document.getElementById('page-shown');
    const totalEl = document.getElementById('page-total');
    const curEl   = document.getElementById('page-current');
    const lastEl  = document.getElementById('page-last-num');
    const first   = document.getElementById('page-first');
    const prev    = document.getElementById('page-prev');
    const next    = document.getElementById('page-next');
    const last    = document.getElementById('page-last');

    const start = total === 0 ? 0 : offset + 1;
    const end   = offset + sliceLen;
    if (shownEl) shownEl.textContent = total === 0 ? '0' : `${start.toLocaleString()}–${end.toLocaleString()}`;
    if (totalEl) totalEl.textContent = total.toLocaleString();

    const totalPages   = Math.max(1, Math.ceil(total / _pageSize));
    const currentPage  = total === 0 ? 1 : Math.floor(offset / _pageSize) + 1;
    if (curEl)  curEl.textContent  = currentPage.toLocaleString();
    if (lastEl) lastEl.textContent = totalPages.toLocaleString();

    const atFirst = currentPage <= 1;
    const atLast  = currentPage >= totalPages;
    if (first) first.disabled = atFirst;
    if (prev)  prev.disabled  = atFirst;
    if (next)  next.disabled  = atLast;
    if (last)  last.disabled  = atLast;
  }

  // _currentPageNumber returns the 1-based page index for the active
  // tab — derived from offset / _pageSize for findings tabs and from
  // _aggTabState for aggregate tabs.
  function _currentPageNumber() {
    if (_isAggregateTab(_tabMode)) {
      const a = _aggTabState[_aggTabKey(_tabMode)];
      return a.total === 0 ? 1 : Math.floor(a.offset / _pageSize) + 1;
    }
    const ts = _curTab();
    return ts.total === 0 ? 1 : Math.floor(ts.offset / _pageSize) + 1;
  }
  function _totalPagesForActiveTab() {
    if (_isAggregateTab(_tabMode)) {
      return Math.max(1, Math.ceil(_aggTabState[_aggTabKey(_tabMode)].total / _pageSize));
    }
    const ts = _curTab();
    return Math.max(1, Math.ceil(ts.total / _pageSize));
  }

  // _gotoPage navigates the active tab to a specific 1-based page.
  // Findings tabs trigger a server-side fetch; aggregate tabs re-render
  // the cached slice. Out-of-range pages clamp to the valid window.
  async function _gotoPage(page) {
    if (_isAggregateTab(_tabMode)) {
      const a = _aggTabState[_aggTabKey(_tabMode)];
      const totalPages = Math.max(1, Math.ceil(a.total / _pageSize));
      const p = Math.min(Math.max(1, page | 0), totalPages);
      a.offset = (p - 1) * _pageSize;
      _renderAggregatePage();
    } else {
      const ts = _curTab();
      const totalPages = Math.max(1, Math.ceil(ts.total / _pageSize));
      const p = Math.min(Math.max(1, page | 0), totalPages);
      const targetOffset = (p - 1) * _pageSize;
      try {
        await loadFindings(_currentFilterParams(), { gotoOffset: targetOffset });
      } catch (e) {
        console.error('page navigation failed', e);
      }
    }
  }

  // Apply the current tab mode filter to the table. All four tab modes
  // operate on network events only — Host Risk Score is excluded up front
  // and surfaced through the Hosts tab instead.
  // _applyTabFilter is a back-compat shim — every existing call site
  // ultimately wants "render the current tab". With per-tab caches it's
  // just a render trigger; client-side filtering is gone because the
  // server returns exactly the tab's slice.
  function _applyTabFilter(opts) {
    _showCurrentTab(opts);
  }

  function updateInfoLine() {
    // Counts come from /api/findings/counts populated by _loadCounts —
    // accurate even before any tab's row data has been fetched. Until
    // counts have loaded the first time, fall back to dashes.
    const fmt = n => _countsLoaded ? n.toLocaleString() : '—';
    const ts  = _tabState;
    const parts = [
      `${fmt(ts.findings.total)} open`,
      `${fmt(ts.ack.total)} ack'd`,
      `${fmt(ts.esc.total)} escalated`,
    ];
    if (_countsLoaded && ts.ioc.total > 0) parts.push(`${fmt(ts.ioc.total)} IOC`);
    // Surface dismissed count only when the operator has enabled the
    // Show Dismissed toggle; otherwise the count stays out of the
    // info line so dismissed-by-choice items don't add noise.
    if (_countsLoaded && _showDismissed && ts.dismissed.total > 0) {
      parts.push(`${fmt(ts.dismissed.total)} dismissed`);
    }
    document.getElementById('info-line').textContent = parts.join('  •  ');

    // findings-count reflects the active tab — what's currently rendered.
    const cur = _curTab();
    document.getElementById('findings-count').textContent =
      cur.loaded ? `${cur.total.toLocaleString()} total` : '';

    _updateViewBadges();
  }

  // _updateViewBadges paints the count next to each sidebar view button.
  // The five status views read straight from the counts endpoint totals;
  // Campaigns and Hosts read from the aggregate cache once it's loaded
  // (dash until then, since those counts aren't in the counts endpoint).
  function _updateViewBadges() {
    const set = (id, val) => {
      const el = document.getElementById('view-count-' + id);
      if (el) el.textContent = val;
    };
    const ts = _tabState;
    const fmt = n => _countsLoaded ? Number(n || 0).toLocaleString() : '—';
    set('findings', fmt(ts.findings.total));
    set('ack', fmt(ts.ack.total));
    set('esc', fmt(ts.esc.total));
    set('ioc', fmt(ts.ioc.total));
    set('dismissed', fmt(ts.dismissed.total));
    try {
      const camps = (typeof Campaigns !== 'undefined' && Campaigns.getCampaigns) ? Campaigns.getCampaigns() : null;
      const hosts = (typeof Campaigns !== 'undefined' && Campaigns.getHosts) ? Campaigns.getHosts() : null;
      set('campaigns', camps && camps.length ? camps.length.toLocaleString() : (camps ? '0' : '—'));
      set('hosts', hosts && hosts.length ? hosts.length.toLocaleString() : (hosts ? '0' : '—'));
    } catch (_) { /* aggregate not built yet */ }
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

  // ── Views (left-sidebar navigation) ─────────────────────────────────────────
  // Each view button in the sidebar carries data-tab; the dispatch below
  // mirrors the old horizontal tab strip. The findings-style views
  // (findings/ack/esc/ioc) share the #tab-findings panel and differ only in
  // the server-side status scoping _currentFilterParams emits.
  const VIEW_META = {
    findings:  {title: 'Findings',     subtitle: 'Open findings awaiting triage'},
    ack:       {title: 'Acknowledged', subtitle: "Findings you've acknowledged"},
    esc:       {title: 'Escalated',    subtitle: 'Findings escalated for follow-up'},
    ioc:       {title: 'IOC Hits',     subtitle: 'Findings whose IP matches an IOC list entry'},
    campaigns: {title: 'Campaigns',    subtitle: 'Destinations grouped across the hosts beaconing to them'},
    hosts:     {title: 'Hosts',        subtitle: 'Per-host risk roll-up across all findings'},
    dismissed: {title: 'Dismissed',    subtitle: 'Findings removed from active triage'},
  };
  // _setViewActive moves the active highlight to the named view button,
  // toggles the Dismissed sub-tabs, and updates the main-column header. It
  // does NOT fetch — callers that need a load (the click handler, pivots,
  // the bell-jump) drive that themselves.
  function _setViewActive(tab) {
    document.querySelectorAll('.view-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    _activeTab = tab;
    const subTabs = document.getElementById('dismissed-subtabs');
    if (subTabs) subTabs.style.display = tab === 'dismissed' ? 'flex' : 'none';
    const meta = VIEW_META[tab] || VIEW_META.findings;
    const title = document.getElementById('view-title');
    const sub   = document.getElementById('view-subtitle');
    if (title) title.textContent = meta.title;
    if (sub)   sub.textContent   = meta.subtitle;
  }
  function _activateView(tab) {
    _setViewActive(tab);
    const findingsView = tab === 'findings' || tab === 'ack' || tab === 'esc' || tab === 'ioc';
    if (findingsView) {
      // All four share #tab-findings panel; just change the cache slot.
      // Cached views render instantly; first-visit views fetch their own
      // page with the right server-side filter.
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      document.getElementById('tab-findings').classList.add('active');
      _tabMode = tab;
      _showCurrentTab();
    } else if (tab === 'dismissed') {
      // Dismissed routes through the sub-tab dispatch so the analyst lands
      // on Findings or Campaigns view as they last chose.
      _routeDismissedSubTab();
    } else {
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      const panel = document.getElementById('tab-' + tab);
      if (panel) panel.classList.add('active');
      // Campaigns / Hosts are roll-ups — they need every finding in the
      // time range, not whatever's loaded for the current findings view.
      // Lazy-fetch the aggregate cache on first visit.
      if (tab === 'campaigns' || tab === 'hosts') {
        _tabMode = tab;
        _ensureAggregate();
      }
    }
  }
  function initViews() {
    document.querySelectorAll('.view-btn').forEach(btn => {
      btn.addEventListener('click', () => _activateView(btn.dataset.tab));
    });
  }

  // ── Query bar ──────────────────────────────────────────────────────────────
  function initFilterBar() {
    const queryInput = document.getElementById('filter-query');
    document.getElementById('run-query-btn').addEventListener('click', applyFilter);
    document.getElementById('reset-filter-btn').addEventListener('click', () => {
      _resetFilterUI();
      applyFilter();
    });
    if (queryInput) {
      // Enter runs the query; Shift+Enter inserts a newline so a long
      // expression can be split across lines. The box grows downward to
      // fit whatever it holds, so the full query is always visible.
      queryInput.addEventListener('keydown', e => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); applyFilter(); }
      });
      queryInput.addEventListener('input', () => _autoGrowQuery());
      _autoGrowQuery();
    }
    // Recent-queries dropdown: reopens any of the last 10 distinct queries.
    const histBtn = document.getElementById('query-history-btn');
    const histMenu = document.getElementById('query-history-menu');
    if (histBtn && histMenu) {
      histBtn.addEventListener('click', e => {
        e.stopPropagation();
        document.querySelectorAll('.export-menu, .chip-menu, .logs-menu, .query-history-menu').forEach(m => { if (m !== histMenu) m.classList.add('hidden'); });
        _renderQueryHistoryMenu();
        histMenu.classList.toggle('hidden');
      });
      histMenu.addEventListener('click', e => e.stopPropagation());
    }
    _initQueryChips();

    // Pagination footer wiring. Page-size dropdown resets to page 1
    // and re-fetches; Load More appends the next page in place.
    const pageSizeSel = document.getElementById('page-size-select');
    if (pageSizeSel) {
      pageSizeSel.value = String(_pageSize);
      pageSizeSel.addEventListener('change', () => {
        const v = parseInt(pageSizeSel.value, 10);
        if (v > 0) {
          _pageSize = v;
          // Page-size shifts which page contains the analyst's current
          // window. Snap every tab back to page 1 — staying on a stale
          // mid-set offset would surface arbitrary rows. Cheaper than
          // computing a "keep the first row visible" mapping per tab.
          _invalidateAllTabs();
          _loadCounts();
          if (_isAggregateTab(_tabMode)) {
            _ensureAggregate();
          } else {
            loadFindings(_currentFilterParams());
          }
        }
      });
    }
    // Page-nav buttons (« ‹ › »). Findings/Ack/Esc/IOC navigate via a
    // server fetch with the new offset; Campaigns/Hosts re-slice the
    // cached aggregate. Disabled state is driven from the footer
    // updater based on current/total page.
    const pageFirst = document.getElementById('page-first');
    const pagePrev  = document.getElementById('page-prev');
    const pageNext  = document.getElementById('page-next');
    const pageLast  = document.getElementById('page-last');
    if (pageFirst) pageFirst.addEventListener('click', () => _gotoPage(1));
    if (pagePrev)  pagePrev .addEventListener('click', () => {
      const cur = _currentPageNumber();
      _gotoPage(cur - 1);
    });
    if (pageNext)  pageNext .addEventListener('click', () => {
      const cur = _currentPageNumber();
      _gotoPage(cur + 1);
    });
    if (pageLast)  pageLast .addEventListener('click', () => {
      const totalPages = _totalPagesForActiveTab();
      _gotoPage(totalPages);
    });

    // "Export current tab" dispatches on the active tab. Findings-style
    // tabs go through the server (server-side filters apply); Campaigns
    // and Hosts are aggregations built client-side, so we serialize the
    // in-memory rows directly.
    _initExportDialog();
    // Logs preview pill: toggles its popover, closing any sibling menu.
    const logsBtn = document.getElementById('logs-preview-btn');
    const logsMenu = document.getElementById('logs-menu');
    if (logsBtn && logsMenu) {
      logsBtn.addEventListener('click', e => {
        e.stopPropagation();
        document.querySelectorAll('.export-menu, .chip-menu, .logs-menu, .query-history-menu').forEach(m => { if (m !== logsMenu) m.classList.add('hidden'); });
        logsMenu.classList.toggle('hidden');
      });
      // Clicks inside the popover (expanding a sensor's dates) must not
      // bubble to the document handler that closes it.
      logsMenu.addEventListener('click', e => e.stopPropagation());
    }
    // Close any open export, chip, or logs menu when clicking outside it.
    // Each trigger's stopPropagation prevents this from firing on its own click.
    document.addEventListener('click', () => {
      document.querySelectorAll('.export-menu, .chip-menu, .logs-menu, .query-history-menu').forEach(m => m.classList.add('hidden'));
    });
  }

  // ── Query chips ──────────────────────────────────────────────────────────
  // Chips are shortcut menus that write canonical field tokens into the
  // query box. The query text is the single source of truth: selecting a
  // chip value upserts (or, for a "clear" item, removes) one field token;
  // typing in the box directly is equally valid. No chip holds hidden state.
  function _initQueryChips() {
    // Each chip button toggles its own menu and closes siblings.
    document.querySelectorAll('.chip').forEach(btn => {
      const menu = document.getElementById('chip-menu-' + btn.id.replace('chip-', ''));
      if (!menu) return;
      btn.addEventListener('click', e => {
        e.stopPropagation();
        document.querySelectorAll('.export-menu, .chip-menu, .logs-menu, .query-history-menu').forEach(m => { if (m !== menu) m.classList.add('hidden'); });
        menu.classList.toggle('hidden');
      });
    });
    const close = menu => menu.classList.add('hidden');

    const sevMenu = document.getElementById('chip-menu-severity');
    sevMenu.querySelectorAll('li').forEach(li => li.addEventListener('click', () => {
      _setQueryToken('severity', li.dataset.sev); applyFilter(); close(sevMenu);
    }));

    const scoreMenu = document.getElementById('chip-menu-score');
    scoreMenu.querySelectorAll('li').forEach(li => li.addEventListener('click', () => {
      _setQueryToken('score', li.dataset.score === '' ? '' : '>=' + li.dataset.score);
      applyFilter(); close(scoreMenu);
    }));

    const timeMenu = document.getElementById('chip-menu-time');
    timeMenu.querySelectorAll('li').forEach(li => li.addEventListener('click', () => {
      _setQueryToken('ts', _tsTokenForRange(li.dataset.range)); applyFilter(); close(timeMenu);
    }));

    // +more inserts a field token template the analyst completes, or a
    // ready-made boolean token. Templates focus the box with the cursor
    // after the colon; nothing fetches until the analyst hits Run/Enter.
    const moreMenu = document.getElementById('chip-menu-more');
    moreMenu.querySelectorAll('li').forEach(li => li.addEventListener('click', () => {
      if (li.dataset.token) { _appendQueryToken(li.dataset.token); applyFilter(); }
      else if (li.dataset.field) { _insertQueryTemplate(li.dataset.field); }
      close(moreMenu);
    }));

    // Hunts: each item carries a complete query. Unlike the other chips
    // (which upsert one token onto the current expression), a hunt is an
    // alternative lens, so it replaces the whole box and runs immediately.
    // The non-query section headers carry no data-query and are inert.
    const huntsMenu = document.getElementById('chip-menu-hunts');
    huntsMenu.querySelectorAll('li[data-query]').forEach(li => li.addEventListener('click', () => {
      _setFullQuery(li.dataset.query); applyFilter(); close(huntsMenu);
    }));
  }

  // _setFullQuery replaces the entire query box with q. Used by the Hunts
  // chip, where each item is a complete expression rather than a token.
  function _setFullQuery(q) {
    const box = document.getElementById('filter-query');
    if (!box) return;
    box.value = q;
    _autoGrowQuery();
  }

  // _tsTokenForRange turns a preset key into the value half of a ts token
  // (e.g. ">=2026-05-26"), or '' for "all time" which clears the ts filter.
  // The boundary date is computed in UTC to line up with the UTC timestamps
  // the findings table displays.
  function _tsTokenForRange(key) {
    if (key === 'all' || !key) return '';
    const day = 24 * 60 * 60 * 1000;
    const offsets = {
      '1d':  1 * day,
      '7d':  7 * day,
      '1mo': 30 * day,
      '3mo': 91 * day,
      '6mo': 182 * day,
    };
    const off = offsets[key];
    if (!off) return '';
    return '>=' + new Date(Date.now() - off).toISOString().slice(0, 10);
  }

  // _queryTokenRE builds a matcher for an existing `field:<value>` token in
  // the query text, where the value may be a quoted phrase, a [lo TO hi]
  // range, or a bare run (which itself may carry a comparison operator).
  function _queryTokenRE(field) {
    return new RegExp('(^|\\s)' + field + ':(?:"[^"]*"|\\[[^\\]]*\\]|\\S+)', 'i');
  }

  // _autoGrowQuery sizes the elastic query box to its content so the whole
  // expression stays visible. Called on user input and after every
  // programmatic write (chip insert, reset, pivot). Reset-to-auto first so
  // the box shrinks back when a long query is cleared.
  function _autoGrowQuery() {
    const box = document.getElementById('filter-query');
    if (!box) return;
    box.style.height = 'auto';
    box.style.height = box.scrollHeight + 'px';
  }

  // _setQueryToken upserts `field:value` into the query box, replacing any
  // existing token for the same field. An empty value removes the field's
  // token entirely. The query box stays the one source of truth. The grammar
  // requires an explicit operator between terms, so an appended token is
  // joined with AND and a removed token takes its adjacent operator with it.
  function _setQueryToken(field, value) {
    const box = document.getElementById('filter-query');
    if (!box) return;
    let q = box.value;
    const re = _queryTokenRE(field);
    if (value === '' || value == null) {
      q = _removeQueryToken(q, field);
    } else {
      const token = field + ':' + value;
      if (re.test(q)) q = q.replace(re, (m, lead) => lead + token);
      else q = _joinQueryTerm(q, token);
    }
    box.value = q;
    _autoGrowQuery();
  }

  // _joinQueryTerm appends a term to an existing query with the required AND,
  // or returns it alone when the box is empty.
  function _joinQueryTerm(q, term) {
    return q.trim() ? q.trim() + ' AND ' + term : term;
  }

  // _removeQueryToken drops a field's token and the one boolean operator that
  // bound it (the preceding operator when present, otherwise the following
  // one) so the remaining expression stays well-formed under the
  // operator-required grammar.
  function _removeQueryToken(q, field) {
    const tok = field + ':(?:"[^"]*"|\\[[^\\]]*\\]|\\S+)';
    const op = '(?:AND\\s+NOT|AND|OR|NOT)';
    const withLead = new RegExp('\\s+' + op + '\\s+' + tok, 'i');
    const withTrail = new RegExp('(^|\\s)' + tok + '\\s+' + op + '\\s+', 'i');
    if (withLead.test(q)) q = q.replace(withLead, '');
    else if (withTrail.test(q)) q = q.replace(withTrail, (m, lead) => lead);
    else q = q.replace(_queryTokenRE(field), '');
    return q.replace(/\s{2,}/g, ' ').trim();
  }

  // _appendQueryToken adds a ready-made token (e.g. "ioc:true") if it isn't
  // already present, leaving any other tokens untouched.
  function _appendQueryToken(token) {
    const box = document.getElementById('filter-query');
    if (!box) return;
    const present = new RegExp('(^|\\s)' + token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(\\s|$)', 'i');
    if (present.test(box.value)) return;
    box.value = _joinQueryTerm(box.value, token);
    _autoGrowQuery();
  }

  // _insertQueryTemplate appends a "field:" (or "field:>=") template and
  // parks the cursor at the end so the analyst types the value. No fetch
  // fires — the template is incomplete until they finish it and hit Run.
  function _insertQueryTemplate(field) {
    const box = document.getElementById('filter-query');
    if (!box) return;
    box.value = _joinQueryTerm(box.value, field);
    _autoGrowQuery();
    box.focus();
    box.setSelectionRange(box.value.length, box.value.length);
  }

  // Build the query string representing the current filter state. Shared by
  // applyFilter (for /api/findings) and the export buttons so the exported
  // file matches the on-screen view exactly.
  function _currentFilterParams() {
    const params = {};
    // The whole filter expression now lives in the query box. The server
    // ANDs `q` on top of the view scoping below; an empty box means "no
    // user filter" and only the view scoping applies.
    const q = ((document.getElementById('filter-query') || {}).value || '').trim();
    if (q) params.q = q;

    // View-aware status filter, mirrored server-side. Without this, the
    // Findings view fetches every status (including acknowledged and
    // escalated) and filters client-side via _applyTabFilter — fine for
    // a thousand findings, painful for hundreds of thousands. This is the
    // view selector, not part of the query the analyst types.
    if (_tabMode === 'ack')            params.status = 'acknowledged';
    else if (_tabMode === 'esc')       params.status = 'escalated';
    else if (_tabMode === 'dismissed') params.status = 'dismissed';
    else if (_tabMode === 'ioc')       params.ioc_only = 'true';
    else                               params.status = 'open';
    if (_deltaMode) params.delta = 'true';

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
    else if (_tabMode === 'dismissed') p.status = 'dismissed';
    else if (_tabMode === 'ioc') p.ioc_only = 'true';
    else p.status = 'open'; // default 'findings' tab
    if (_deltaMode) p.delta = 'true';
    return Object.keys(p).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(p[k])}`).join('&');
  }

  // ── Client-side export helpers (Campaigns / Hosts) ─────────────────────────
  // CSV escaping per RFC 4180: wrap fields containing comma, quote, CR, or LF
  // in double quotes; double up internal quotes. Formula injection is
  // neutralized first — mirrors the server's spreadsheetSafe (handlers_api.go)
  // so attacker-controlled Zeek content (the raw-records export dumps DNS
  // queries, URIs, cert subjects, filenames) can't smuggle a leading
  // =/+/-/@ formula into the analyst's spreadsheet.
  function _csvField(v) {
    let s = v == null ? '' : String(v);
    if (s !== '') {
      const c0 = s[0];
      if (c0 === '\t' || c0 === '\r' || c0 === '\n') {
        s = "'" + s;
      } else {
        const t = s.replace(/^[ \t\r\n]+/, '');
        if (t && '=+-@'.indexOf(t[0]) !== -1) s = "'" + s;
      }
    }
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

  // The Export dialog replaces the old current/all dropdown pair with one
  // scope × format picker. XLSX is produced only for the All-findings scope
  // (the server has no current-view XLSX path, and Campaigns/Hosts serialize
  // client-side as CSV/JSON), so it's gated on the selected scope.
  function _initExportDialog() {
    const dlg = document.getElementById('export-dlg');
    const btn = document.getElementById('export-btn');
    if (!dlg || !btn) return;
    const xlsxRow = document.getElementById('export-fmt-xlsx');
    const xlsxInput = xlsxRow.querySelector('input');

    const syncFormatAvailability = () => {
      const allowXlsx = dlg.querySelector('input[name="export-scope"]:checked').value === 'all';
      xlsxInput.disabled = !allowXlsx;
      xlsxRow.classList.toggle('disabled', !allowXlsx);
      if (!allowXlsx && xlsxInput.checked) {
        dlg.querySelector('input[name="export-format"][value="csv"]').checked = true;
      }
    };

    btn.addEventListener('click', () => {
      syncFormatAvailability();
      dlg.showModal();
    });
    dlg.querySelectorAll('input[name="export-scope"]').forEach(r =>
      r.addEventListener('change', syncFormatAvailability));
    document.getElementById('export-dlg-cancel').addEventListener('click', () => dlg.close());
    document.getElementById('export-dlg-go').addEventListener('click', () => {
      const scope = dlg.querySelector('input[name="export-scope"]:checked').value;
      const format = dlg.querySelector('input[name="export-format"]:checked').value;
      dlg.close();
      _runExport(scope, format);
    });
  }

  function _runExport(scope, format) {
    if (scope === 'all') {
      window.location.href = `/api/export/${format}`;
      return;
    }
    // Current view: Campaigns/Hosts are client-side aggregations (CSV/JSON);
    // findings-style views stream from the server with the active filter.
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
      archer_version: _archerVersion.version,
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
        archer_version: _archerVersion.version,
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
    // Column order matches the Hosts tab UI (risk_score first, then host_ip)
    // — analysts pivot off risk score as the leading sort, so the export
    // mirrors what's on screen.
    const header = ['risk_score','host_ip','findings','severity','finding_types'];
    let out = _csvRow(header);
    hosts.forEach(h => {
      const r = _hostToRow(h);
      out += _csvRow(header.map(c => r[c]));
    });
    _downloadBlob(`archer_hosts_${_ts()}.csv`, 'text/csv', out);
  }

  function _downloadHostsJSON(hosts) {
    const out = JSON.stringify({
      archer_version: _archerVersion.version,
      saved_at: new Date().toISOString(),
      hosts: hosts.map(_hostToRow),
    }, null, 2);
    _downloadBlob(`archer_hosts_${_ts()}.json`, 'application/json', out);
  }

  // _resetFilterUI clears every filter form input back to its
  // empty/default state without triggering a re-fetch. The
  // reset-filter-btn click handler pairs it with applyFilter();
  // showContributingActivity pairs it with a src/dst write so the
  // form reads cleanly as "filtered on this pair only."
  //
  // _resetFilterUI clears the query box. Every filter predicate now lives
  // in that one field, so clearing it clears the whole filter state. It
  // does not touch the active view or trigger a re-fetch — the reset
  // button pairs it with applyFilter(); pivots pair it with a token write.
  function _resetFilterUI() {
    const box = document.getElementById('filter-query');
    if (box) { box.value = ''; _autoGrowQuery(); }
  }

  // _switchToFindingsView makes the Findings view active (highlight,
  // header, panel, mode) without fetching — used by the pivots, which set
  // the query box first and then call applyFilter().
  function _switchToFindingsView() {
    if (_tabMode === 'findings') return;
    _setViewActive('findings');
    _tabMode = 'findings';
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    const panel = document.getElementById('tab-findings');
    if (panel) panel.classList.add('active');
  }

  // showContributingActivity filters the Findings view on the CA's
  // (src, dst) pair by writing src:/dst: tokens into the query box. The
  // analyst sees the filter state in the box and can edit it; the
  // (src, dst) shape also surfaces newer activity on the same pair that
  // wasn't part of the original CA emission. Wired from the
  // ctx-show-contributing right-click item; visible only on CA rows.
  function showContributingActivity(f) {
    if (!f || f.type !== 'Correlated Activity') return;
    const src = f.src_ip || '';
    const dst = f.dst_ip || '';
    if (!src && !dst) return;
    _resetFilterUI();
    if (src) _setQueryToken('src', src);
    if (dst) _setQueryToken('dst', dst);
    _switchToFindingsView();
    applyFilter();
  }

  // pivotByTLS filters the Findings view to every finding carrying the
  // selected beacon's TLS fingerprint by writing a ja4:/ja3: token into
  // the query box — same shape as showContributingActivity. Wired from the
  // TLS Pivot detail action button; enabled when f.ja4 or f.ja3 is set.
  // JA4 is preferred when present (JA4+ plugin on sensor); falls back to
  // JA3 for sensors on stock Zeek.
  function pivotByTLS(f) {
    if (!f || !(f.ja4 || f.ja3)) return;
    _resetFilterUI();
    if (f.ja4) _setQueryToken('ja4', f.ja4);
    else       _setQueryToken('ja3', f.ja3);
    _switchToFindingsView();
    applyFilter();
  }

  // ── Query history ──────────────────────────────────────────────────────────
  // The last N distinct queries the analyst ran, most-recent-first, persisted
  // in localStorage so the list survives reloads. The Recent ▾ button reopens
  // any of them. Recorded in applyFilter, so every run path (Run, Enter, chip
  // selects, pivots) feeds the same list; a cleared (empty) box records nothing.
  const _QUERY_HISTORY_KEY = 'archer:query-history';
  const _QUERY_HISTORY_MAX = 10;

  function _loadQueryHistory() {
    try {
      const raw = JSON.parse(localStorage.getItem(_QUERY_HISTORY_KEY) || '[]');
      return Array.isArray(raw) ? raw.filter(q => typeof q === 'string') : [];
    } catch (_) { return []; }
  }

  function _recordQuery(q) {
    q = (q || '').trim();
    if (!q) return;
    let hist = _loadQueryHistory().filter(item => item !== q);
    hist.unshift(q);
    hist = hist.slice(0, _QUERY_HISTORY_MAX);
    try { localStorage.setItem(_QUERY_HISTORY_KEY, JSON.stringify(hist)); } catch (_) {}
  }

  function _renderQueryHistoryMenu() {
    const menu = document.getElementById('query-history-menu');
    if (!menu) return;
    menu.innerHTML = '';
    const hist = _loadQueryHistory();
    if (!hist.length) {
      const li = document.createElement('li');
      li.className = 'query-history-empty';
      li.textContent = 'No recent queries';
      menu.appendChild(li);
      return;
    }
    hist.forEach(q => {
      const li = document.createElement('li');
      li.textContent = q;
      li.title = q;
      li.addEventListener('click', e => {
        e.stopPropagation();
        menu.classList.add('hidden');
        _setFullQuery(q);
        applyFilter();
      });
      menu.appendChild(li);
    });
  }

  function applyFilter() {
    _recordQuery(((document.getElementById('filter-query') || {}).value || ''));
    // A filter change can affect every tab's result set, so invalidate
    // all caches. Other tabs will re-fetch lazily when the analyst
    // visits them. The active tab refetches now. _loadCounts always
    // fires regardless of active tab — the info-line is global, so
    // skipping it on Campaigns/Hosts left dashes on screen.
    _invalidateAllTabs();
    _loadCounts();
    if (_isAggregateTab(_tabMode)) {
      _ensureAggregate();
    } else {
      loadFindings(_currentFilterParams());
    }
  }

  // Re-fetch the current view in place after a server-state change that affects
  // a read-time-stamped findings field — the TLS-fingerprint benign mark (the
  // "fp benign" chip) or an IOC-list edit (the "ioc" chip / ioc_match). Those
  // are stamped server-side at /api/findings read time, so the cached rows are
  // stale until we refetch. Stays on the current page (gotoOffset) and
  // invalidates the other tabs so a benign:/ioc: filtered view re-derives lazily.
  // The scroll container for the active aggregate tab. Campaigns, Hosts,
  // and Dismissed-Campaigns each render into a `.table-wrap` (Dismissed-
  // Campaigns shares the Campaigns panel); their renderers rebuild the
  // tbody but don't touch scrollTop, so an in-place reload has to save and
  // restore it explicitly (the findings table does this via Table.load's
  // preserveScroll instead).
  function _aggScrollEl() {
    const tb = document.getElementById(_tabMode === 'hosts' ? 'hosts-tbody' : 'campaigns-tbody');
    return tb ? tb.closest('.table-wrap') : null;
  }

  // Reload the active view — a findings tab or a Campaigns/Hosts aggregate —
  // after a list-mutating action (allowlist/IOC/suppress, dismiss, status
  // change) without losing the analyst's place: same tab, same page, same
  // scroll position. The curated rows drop out and the rest shift up.
  // opts.counts also refreshes the per-status totals — a status change moves
  // a finding between tabs, so the info line and sidebar badges need
  // reconciling; curate-in-place actions leave the status untouched and skip
  // it.
  async function _reloadFindingsInPlace(opts) {
    const refreshCounts = !!(opts && opts.counts);
    if (_isAggregateTab(_tabMode)) {
      // Capture the aggregate page offset + scroll before _invalidateAllTabs
      // (which calls _invalidateAggregate) zeroes them, then restore both
      // around the rebuild.
      const key = _aggTabKey(_tabMode);
      const keepOffset = _aggTabState[key].offset;
      const sc = _aggScrollEl();
      const keepScroll = sc ? sc.scrollTop : 0;
      _invalidateAllTabs();
      if (refreshCounts) _loadCounts();
      _aggTabState[key].offset = keepOffset;
      await _ensureAggregate();
      if (sc) sc.scrollTop = keepScroll;
    } else {
      // Capture the page offset before _invalidateAllTabs zeroes every tab's
      // offset — otherwise the reload always lands on page 1.
      const keepOffset = _curTab().offset;
      _invalidateAllTabs();
      if (refreshCounts) _loadCounts();
      await loadFindings(_currentFilterParams(), { gotoOffset: keepOffset, preserveScroll: true });
    }
  }

  // ── Delta mode ─────────────────────────────────────────────────────────────
  function initDeltaBar() {
    document.getElementById('delta-btn').addEventListener('click', () => {
      _deltaMode = true;
      document.getElementById('delta-btn').classList.add('active');
      document.getElementById('show-all-btn').classList.remove('active');
      _invalidateAllTabs();
      _loadCounts();
      loadFindings(_currentFilterParams());
    });
    document.getElementById('show-all-btn').addEventListener('click', () => {
      _deltaMode = false;
      document.getElementById('show-all-btn').classList.add('active');
      document.getElementById('delta-btn').classList.remove('active');
      _invalidateAllTabs();
      _loadCounts();
      loadFindings(_currentFilterParams());
    });
  }

  // ── /logs preview ──────────────────────────────────────────────────────────
  function _setLogsDirHint(dir) {
    const el = document.getElementById('logs-dir-path');
    if (el) el.textContent = dir || '/logs';
  }

  function initLogsPanel() {
    _setLogsDirHint(_logsDir);
    _loadLogsTree();
  }

  async function _loadLogsTree() {
    const container = document.getElementById('logs-tree');
    if (!container) return;
    try {
      const data = await api('/api/logs/tree');
      const sensors = (data && data.sensors) || [];
      if (data && data.logs_dir) {
        _logsDir = data.logs_dir;
        _setLogsDirHint(_logsDir);
      }
      _logsAvailable = sensors.length > 0;
      const btn = document.getElementById('analyze-btn');
      if (btn && !_slotBusy) btn.disabled = !_logsAvailable;
      _setLogsPill(sensors);

      container.innerHTML = '';
      if (sensors.length === 0) {
        const empty = document.createElement('div');
        empty.textContent = 'No logs found in /logs';
        empty.style.cssText = 'color:var(--fg-dim);font-size:10px;font-style:italic;padding:4px 12px';
        container.appendChild(empty);
        return;
      }
      sensors.forEach(s => {
        const wrap = document.createElement('div');
        wrap.className = 'logs-tree-sensor';
        const head = document.createElement('div');
        head.style.cssText = 'color:var(--fg-text);font-weight:600;font-size:10px;padding:2px 12px;cursor:pointer';
        head.textContent = `${s.name} (${s.total_files} file${s.total_files !== 1 ? 's' : ''}, ${_humanBytes(s.total_size_bytes)})`;
        const datesEl = document.createElement('div');
        datesEl.style.cssText = 'display:none;padding:0 12px 2px 20px';
        (s.dates || []).slice(0, 12).forEach(d => {
          const row = document.createElement('div');
          row.style.cssText = 'color:var(--fg-dim);font-size:9px;line-height:1.4';
          row.textContent = `${d.date} — ${d.files} file${d.files !== 1 ? 's' : ''}, ${_humanBytes(d.size_bytes)}`;
          datesEl.appendChild(row);
        });
        if ((s.dates || []).length > 12) {
          const more = document.createElement('div');
          more.style.cssText = 'color:var(--fg-dim);font-size:9px;font-style:italic';
          more.textContent = `… +${s.dates.length - 12} older`;
          datesEl.appendChild(more);
        }
        head.addEventListener('click', () => {
          datesEl.style.display = datesEl.style.display === 'none' ? 'block' : 'none';
        });
        wrap.appendChild(head);
        wrap.appendChild(datesEl);
        container.appendChild(wrap);
      });
    } catch (_) {
      if (!_logsAvailable && !_slotBusy) {
        const btn = document.getElementById('analyze-btn');
        if (btn) btn.disabled = true;
      }
    }
  }

  // _setLogsPill summarizes the staged logs onto the query-bar pill:
  // sensor count and total size, or "none" when nothing is staged.
  function _setLogsPill(sensors) {
    const btn = document.getElementById('logs-preview-btn');
    if (!btn) return;
    if (!sensors || sensors.length === 0) {
      btn.textContent = 'Logs: none ▾';
      return;
    }
    const total = sensors.reduce((sum, s) => sum + (s.total_size_bytes || 0), 0);
    btn.textContent = `Logs: ${sensors.length} · ${_humanBytes(total)} ▾`;
  }

  function _humanBytes(n) {
    if (!n || n < 1024) return `${n || 0}B`;
    const u = ['KB', 'MB', 'GB', 'TB'];
    let v = n / 1024;
    let i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v < 10 ? 1 : 0)}${u[i]}`;
  }

  // ── Analyze ────────────────────────────────────────────────────────────────
  function _updateTIStatus() {
    // Recognizes the v0.7.0 split types plus the legacy unified one so
    // pre-v0.7.0 findings still in the DB count toward the TI status pill.
    const tiTypes = new Set([
      'TI Hit (IP)', 'TI Hit (Domain)', 'TI Hit (Hash)',
      'Suspicious URL',
      'Threat Intel Hit',
    ]);
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
  let _slotBusy = false;
  let _logsAvailable = false;

  function _setAnalyzing(active) {
    _slotBusy = active;
    const btn = document.getElementById('analyze-btn');
    if (btn) {
      btn.disabled = active ? true : !_logsAvailable;
      // The bar takes the button's slot while a run is in flight; swap them.
      btn.style.display = active ? 'none' : '';
    }
    document.getElementById('analysis-controls').style.display = active ? 'flex' : 'none';
    document.getElementById('progress-bar').style.display = active ? '' : 'none';
    // Reset Stop/Pause buttons to their default labels and enabled state
    // every time analysis starts or finishes, so a partial-state from a
    // prior cancel doesn't bleed into the next run.
    const stopBtn = document.getElementById('stop-btn');
    const pauseBtn = document.getElementById('pause-btn');
    if (stopBtn)  { stopBtn.disabled = false;  stopBtn.textContent = 'Stop'; }
    if (pauseBtn) { pauseBtn.disabled = false; pauseBtn.textContent = 'Pause'; }
    if (!active) {
      _paused = false;
    }
  }

  function _applyRunningState(st) {
    _setAnalyzing(true);
    // Restore the bar to the run's current position. Without this a reload
    // mid-analysis leaves the bar at 0 until the next phase-boundary SSE event,
    // which on a large corpus can be far off — it looks frozen even though the
    // run (and Stop/Pause) are live. st.pct/step come from /api/analyze/status.
    if (typeof st.pct === 'number') {
      document.getElementById('progress-bar').value = st.pct;
    }
    if (st.step) {
      document.getElementById('analysis-status').textContent = st.step;
    }
    if (st.paused) {
      _paused = true;
      document.getElementById('pause-btn').textContent = 'Resume';
      setStatus('Analysis paused — click Resume to continue');
    } else {
      setStatus(st.step ? `Analysis in progress… ${st.step}` : 'Analysis in progress…');
    }
  }

  // Sets the UI to maintenance state and polls /api/analyze/status every 2 s
  // until the slot is free, then restores the correct UI state (idle or
  // running). Shared by _syncAnalyzeState (page load) and the 409 catch in
  // _kickAnalyze (click during maintenance).
  function _startMaintenancePoll() {
    _slotBusy = true;
    const btn = document.getElementById('analyze-btn');
    // Maintenance isn't an analysis run — show the (disabled) button, not the
    // bar, even if we got here from a click that had already swapped them.
    if (btn) { btn.disabled = true; btn.style.display = ''; }
    document.getElementById('analysis-controls').style.display = 'none';
    document.getElementById('progress-bar').style.display = 'none';
    setStatus('Maintenance in progress…');
    const poll = setInterval(async () => {
      try {
        const s2 = await api('/api/analyze/status');
        if (s2.blocked) return;
        clearInterval(poll);
        if (s2.running) {
          _applyRunningState(s2);
        } else {
          _setAnalyzing(false);
          setStatus('');
        }
      } catch (_) {}
    }, 2000);
  }

  async function _syncAnalyzeState() {
    try {
      const s = await api('/api/analyze/status');
      if (s.blocked) {
        _startMaintenancePoll();
      } else if (s.running) {
        _applyRunningState(s);
      }
    } catch (_) {}
  }

  function initAnalyze() {
    _syncAnalyzeState();

    async function _kickAnalyze(endpoint, startMsg) {
      _setAnalyzing(true);
      document.getElementById('progress-bar').value = 0;
      document.getElementById('ti-status').textContent = 'Fetching…';
      document.getElementById('ti-status').style.color = 'var(--fg-dim)';
      setStatus(startMsg);
      try {
        await api(endpoint, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({}),
        });
      } catch (e) {
        if (String(e).includes('already running') || String(e).includes('409')) {
          try {
            const st = await api('/api/analyze/status');
            if (st.blocked) {
              _startMaintenancePoll();
            } else if (!st.running) {
              _setAnalyzing(false);
              setStatus('');
            } else {
              _applyRunningState(st);
            }
          } catch (_) {
            setStatus('Analysis already running');
          }
        } else {
          setStatus('Analysis failed: ' + e);
          _setAnalyzing(false);
        }
      }
    }

    const btn = document.getElementById('analyze-btn');
    if (btn) {
      btn.addEventListener('click', () =>
        _kickAnalyze('/api/analyze', 'Starting analysis…'));
    }

    document.getElementById('stop-btn').addEventListener('click', async () => {
      // The analyzer cancels at phase boundaries, not in tight loops, so
      // there can be a noticeable delay between clicking Stop and the
      // 'done' SSE event arriving. Without UI feedback the analyst clicks
      // again or assumes nothing happened. Disable both buttons + relabel
      // Stop + show a status message so the cancellation is visibly
      // "received" — the SSE 'done' handler will reset everything.
      const stopBtn = document.getElementById('stop-btn');
      const pauseBtn = document.getElementById('pause-btn');
      if (stopBtn) {
        stopBtn.disabled = true;
        stopBtn.textContent = 'Stopping…';
      }
      if (pauseBtn) {
        pauseBtn.disabled = true;
      }
      setStatus('Cancellation requested — waiting for analyzer to wind down…');
      try {
        await api('/api/analyze/cancel', {method: 'POST'});
      } catch (e) {
        // If the cancel request itself failed (network blip, 409 because
        // analysis just finished, etc.), restore the button so the user
        // isn't stuck with a permanently-disabled Stop. The 'done' event
        // would normally reset everything; this is the failure-path
        // safety net.
        setStatus('Cancellation request failed: ' + e);
        if (stopBtn) {
          stopBtn.disabled = false;
          stopBtn.textContent = 'Stop';
        }
        if (pauseBtn) {
          pauseBtn.disabled = false;
        }
      }
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

  // _showUnseenModal queries the per-session "new since you last looked"
  // count and pops the new-findings modal only when there are unseen findings
  // the modal hasn't already shown THIS SESSION. The "already shown" guard is
  // the server-side per-session high-water (seen_count) — not a JS variable —
  // so a page refresh (which reuses the session) doesn't re-announce the same
  // findings. It re-pops only when the count climbs above seen_count (new
  // findings arrived) or a fresh login starts a new session. The login
  // boundary is the same cutoff the "New only" table filter uses, so the two
  // agree and closing the modal doesn't empty the New view.
  async function _showUnseenModal() {
    try {
      const r = await fetch('/api/findings/unseen', { cache: 'no-store' });
      if (!r.ok) return;
      const d = await r.json();
      const count = d.count || 0;
      const total = d.total || 0;
      const seen  = d.seen_count || 0;
      if (count <= 0 || count <= seen) return;
      const msg = `${count} new finding${count !== 1 ? 's' : ''} since you last checked\n${total} total`;
      document.getElementById('analysis-alert-msg').textContent = msg;
      document.getElementById('analysis-alert-dlg').showModal();
      // Record the pop server-side so a refresh of this session won't repeat it.
      fetch('/api/findings/modal-ack', { method: 'POST' }).catch(() => {});
    } catch (_) { /* best-effort — modal is informational */ }
  }

  // ── SSE ────────────────────────────────────────────────────────────────────
  function initSSE() {
    SSE.on('progress', evt => {
      // A run can start without this client having clicked Analyze — a watch
      // tick triggers analysis server-side and streams the same progress
      // events. Swap the button for the bar on the first event of any run, so
      // the in-flight UI reflects every analysis, not just operator-kicked ones.
      if (!_slotBusy) _setAnalyzing(true);
      document.getElementById('progress-bar').value = evt.pct || 0;
      document.getElementById('analysis-status').textContent = evt.step || '';
      setStatus(evt.step || '');
    });

    SSE.on('status', evt => {
      if (evt.msg) setStatus(evt.msg);
    });

    SSE.on('done', async evt => {
      _setAnalyzing(false);
      if (evt.skipped) {
        setStatus('No changes since last analysis — skipped');
        return;
      }
      // _setAnalyzing(false) above swapped the bar back to the Analyze button;
      // hold the swap for a 2 s fill-to-100% completion flash before restoring.
      const btn = document.getElementById('analyze-btn');
      const bar = document.getElementById('progress-bar');
      btn.style.display = 'none';
      bar.style.display = '';
      bar.value = evt.cancelled ? 0 : 100;
      setStatus(evt.cancelled
        ? `Analysis stopped — ${evt.count || 0} partial findings`
        : `Analysis complete — ${evt.count || 0} findings (${evt.new_count || 0} new)`);
      document.getElementById('analysis-status').textContent = '';
      // Analysis just finished: every tab's cache is potentially stale
      // (new findings emitted, existing ones may have shifted scores).
      _invalidateAllTabs();
      if (_isAggregateTab(_tabMode)) {
        await _ensureAggregate();
      } else {
        await loadFindings(_currentFilterParams());
      }
      _loadCounts();
      _loadFacets();
      _updateTIStatus();
      _loadLogsTree();
      // Catch any notifications missed if SSE connection dropped during analysis
      fetch('/api/notifications')
        .then(r => r.json())
        .then(data => { if (Array.isArray(data)) data.filter(n => !n.dismissed).forEach(n => Notifications.add(n)); })
        .catch(() => {});
      setTimeout(() => { bar.value = 0; bar.style.display = 'none'; btn.style.display = ''; }, 2000);
      // Route the modal through the per-user "unseen" endpoint rather than
      // this run's evt.new_count. evt.new_count is the global per-run is_new
      // flag, which resets every watch tick — an analyst sitting on the page
      // across hourly passes would only ever see the latest run's new
      // findings. _showUnseenModal counts everything detected since *this
      // analyst* last acknowledged, so it accumulates correctly, and it stays
      // silent when nothing is new to them (the status line already confirms
      // the run completed).
      if (!evt.cancelled) {
        _showUnseenModal();
      }
    });

    SSE.on('notification', n => Notifications.add(n));

    // Watch heartbeat — the server ticks watch.heartbeat every 60s
    // independent of watch config; we use it to drive a small dot
    // in the top bar that distinguishes "watch is healthy and
    // quiet" from "watch is dead and quiet." After 180s without a
    // tick (3 missed beats) the dot flips red. Until the first
    // tick lands the dot is dim grey ("unknown"). A 30s checker
    // re-evaluates the dot state so the UI updates promptly when
    // the SSE pipe goes silent — without the checker, the dot
    // would stay green forever if no heartbeat ever flipped it.
    (function watchHeartbeatTracker() {
      const dot = document.getElementById('watch-health-dot');
      if (!dot) return;
      const staleThresholdMS = 3 * 60 * 1000; // 3 missed 60s beats
      let lastBeat = 0;
      function fmtAge(ms) {
        const s = Math.round(ms / 1000);
        if (s < 60) return s + 's';
        const m = Math.round(s / 60);
        return m + 'm';
      }
      function setHealthy() {
        dot.classList.remove('health-stale', 'health-unknown');
        dot.classList.add('health-healthy');
        dot.title = 'Watch heartbeat: healthy (last beat just now)';
      }
      function setStale(age) {
        dot.classList.remove('health-healthy', 'health-unknown');
        dot.classList.add('health-stale');
        dot.title = 'Watch heartbeat: stale (no signal for ' + fmtAge(age) + ')';
      }
      function evaluate() {
        if (lastBeat === 0) return; // still unknown, no signal yet
        const age = Date.now() - lastBeat;
        if (age >= staleThresholdMS) setStale(age);
      }
      SSE.on('watch.heartbeat', () => {
        lastBeat = Date.now();
        setHealthy();
      });
      // SSE 'open' fires on initial connect AND on reconnect after a
      // transient drop. Treat the connection itself as proof-of-life
      // — without this, a brief drop-and-reconnect can leave the dot
      // stale for up to one heartbeat interval (60s) after the SSE
      // pipe is already alive again, because the next server-side
      // tick hadn't yet fired. NEW-103 in the twenty-third audit
      // round. Stale flips back to healthy here even if the actual
      // heartbeat is still seconds away.
      SSE.on('open', () => {
        lastBeat = Date.now();
        setHealthy();
      });
      setInterval(evaluate, 30000);
    })();

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

    // resync_required is the canary the server sends when an SSE
    // buffer overflowed and we missed events. Best-effort live
    // updates is fine for most apps but Archer's live channel
    // includes new TI hits, unauthorized sensor attempts, and
    // CRITICAL findings — silent drops there mean the analyst sees
    // "all quiet" while real alerts piled up server-side. The fix:
    // re-fetch the source-of-truth endpoints (findings list +
    // notifications) so the UI converges to the actual state.
    // Audit 2026-05-10 NEW-29.
    SSE.on('resync_required', () => {
      showToast('Live updates fell behind — re-syncing from server', 4000);
      loadFindings(_currentFilterParams()).catch(() => {});
      fetch('/api/notifications')
        .then(r => r.json())
        .then(data => {
          if (Array.isArray(data)) {
            // Notifications.dismissAll() would also POST a dismiss-all to the
            // server, which we don't want. Just rebuild the local list from
            // the freshly-fetched server state.
            data.filter(n => !n.dismissed).forEach(n => Notifications.add(n));
          }
        })
        .catch(() => {});
    });

    SSE.connect();

    document.getElementById('analysis-alert-ok').addEventListener('click', () => {
      // Just close. The new-findings boundary is anchored at login, not at
      // dismiss, so the "New only" filter still surfaces these findings for
      // review after the modal is closed; it re-anchors on next login.
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
    // Pulse dot mirrors the enrollment dialog's "awaiting sensor join"
    // indicator. Subsequent success/error paths set textContent, which
    // wipes the dot — no explicit cleanup needed.
    status.innerHTML = '<span class="pulse-dot"></span>Scanning logs…';
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
        sec.innerHTML = `<div style="font-weight:bold;margin:6px 0;color:var(--accent)">${_esc(logType)} — ${recs.length} record(s)</div>`;
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

  // _toggleDismiss is the single source of truth for dismiss /
  // un-dismiss. Called from both the context-menu Dismiss item and
  // (post-tabbed-dock) the action footer's Dismiss button so both
  // entry points run identical state-transition logic. Lives at
  // IIFE-level so initContextMenu's click handler can call it
  // alongside initDetailActions's button handler.
  async function _toggleDismiss(f) {
    const newStatus = f.status === 'dismissed' ? '' : 'dismissed';
    const label = newStatus === 'dismissed' ? 'Dismiss Finding' : 'Un-dismiss Finding';
    const note = await promptNote(label);
    if (note === null) return; // cancelled
    try {
      await api(`/api/findings/${f.id}`, {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({status: newStatus, note}),
      });
      const updated = await fetchFinding(f.id);
      if (_selectedFinding && _selectedFinding.id === f.id) {
        _selectedFinding = updated;
        Detail.render(updated);
      }
      const idx = _allFindings.findIndex(x => x.id === f.id);
      if (idx >= 0) _allFindings[idx] = updated;
      Table.update(updated);
      // After dismiss the row leaves the current tab; after
      // un-dismiss it leaves the Dismissed tab. Either way the
      // tab needs to refetch so totals + visible rows reconcile —
      // in place, holding the analyst's page and scroll position.
      await _reloadFindingsInPlace({ counts: true });
    } catch (e) { setStatus('Error: ' + e); }
  }

  // _bulkDismissCampaign dismisses every finding whose (dst_ip, dst_port)
  // matches the campaign's key. Driven from the Campaigns context menu;
  // the campaign object only carries the aggregation (srcs / maxScore /
  // types) so member findings are resolved against the cached aggregate.
  // The PATCH loop is best-effort: a single failure doesn't abort the
  // batch — the operator gets a partial-success status line instead so
  // they can tell whether to re-try.
  async function _bulkDismissCampaign(camp) {
    if (!camp) return;
    const dst  = camp.dst || '';
    const port = camp.port || '';
    // Resolve member findings from the aggregate cache. The Dismissed >
    // Campaigns view is built over a status=dismissed cache, so on that
    // sub-tab we'd be un-dismissing the bucket. Keep semantics simple
    // and only offer this from the top-level Campaigns view for now.
    const findings = (_aggregateState.findings || []).filter(f =>
      (f.dst_ip || f.domain || '') === dst &&
      String(f.dst_port || '') === String(port) &&
      f.status !== 'dismissed'
    );
    if (findings.length === 0) {
      setStatus('No open findings in this campaign to dismiss');
      return;
    }
    const label = `Dismiss ${findings.length} finding${findings.length === 1 ? '' : 's'} (${dst}${port ? ':' + port : ''})`;
    const note = await promptNote(label);
    if (note === null) return; // cancelled
    let ok = 0, fail = 0;
    setStatus(`Dismissing ${findings.length} findings…`);
    for (const f of findings) {
      try {
        await api(`/api/findings/${f.id}`, {
          method: 'PATCH',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({status: 'dismissed', note}),
        });
        ok++;
      } catch (_) { fail++; }
    }
    await _reloadFindingsInPlace({ counts: true });
    if (fail === 0) setStatus(`Dismissed ${ok} finding${ok === 1 ? '' : 's'} in campaign`);
    else            setStatus(`Dismissed ${ok}, failed ${fail} — re-try to clear remaining`);
  }

  function initDetailActions() {
    const rawBtn = document.getElementById('raw-btn');
    if (rawBtn) {
      rawBtn.addEventListener('click', () => {
        if (_selectedFinding) _showRawRecords(_selectedFinding);
      });
    }
    const tlsBtn = document.getElementById('tls-btn');
    if (tlsBtn) {
      tlsBtn.addEventListener('click', () => {
        if (_selectedFinding) pivotByTLS(_selectedFinding);
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

    // Per-cell right-click → "Copy cell". Native text selection breaks on
    // punctuation (e.g. a Community ID's `:`/`=` truncate a double-click
    // selection), so analysts can't reliably grab a whole cell value.
    // This copies the cell's full text content regardless of separators.
    const rawTableEl = document.getElementById('raw-dlg-table');
    const cellMenu   = document.getElementById('raw-cell-menu');
    if (rawTableEl && cellMenu) {
      let _rawCellText = '';
      rawTableEl.addEventListener('contextmenu', e => {
        const td = e.target.closest && e.target.closest('td');
        if (!td) return;
        e.preventDefault();
        _rawCellText = td.textContent;
        cellMenu.classList.remove('hidden');
        const margin = 8;
        const r = cellMenu.getBoundingClientRect();
        let left = (e.clientX + r.width  > window.innerWidth  - margin)
          ? Math.max(margin, e.clientX - r.width)  : e.clientX;
        let top  = (e.clientY + r.height > window.innerHeight - margin)
          ? Math.max(margin, e.clientY - r.height) : e.clientY;
        cellMenu.style.left = left + 'px';
        cellMenu.style.top  = top  + 'px';
      });
      document.getElementById('raw-cell-copy').addEventListener('click', () => {
        const ok = copyToClipboard(_rawCellText);
        showToast(ok ? 'Cell copied' : 'Copy failed');
      });
      const hideCellMenu = () => cellMenu.classList.add('hidden');
      document.addEventListener('click', hideCellMenu);
      rawTableEl.addEventListener('scroll', hideCellMenu);
      document.getElementById('raw-dialog').addEventListener('close', hideCellMenu);
    }

    document.getElementById('dismiss-btn').addEventListener('click', async () => {
      if (!_selectedFinding) return;
      _toggleDismiss(_selectedFinding);
    });

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
        // Acknowledging moves the finding out of the open Findings view and
        // into the Acknowledged tab (re-open does the reverse). Reload in
        // place so it leaves the current view immediately and the per-status
        // counts reconcile — holding the analyst's page and scroll position —
        // rather than lingering with a check mark until a refresh.
        await _reloadFindingsInPlace({ counts: true });
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
          // Escalating moves the finding out of the open Findings view into
          // the Escalated tab immediately, mirroring Ack — reload in place so
          // it leaves the current view and the counts reconcile, holding the
          // analyst's page and scroll position.
          await _reloadFindingsInPlace({ counts: true });
          setStatus(ips.length > 0 ? 'Escalated — TI lookup running in background' : 'Escalated');
        } catch (e) { setStatus('Error: ' + e); }
      };
    });

    document.getElementById('esc-dlg-cancel').addEventListener('click', () => _escDlg.close());

    document.getElementById('chart-btn').addEventListener('click', () => {
      if (_selectedFinding) BeaconChart.show(_selectedFinding);
    });

    document.getElementById('score-evo-btn').addEventListener('click', () => {
      if (typeof BeaconEvolution !== 'undefined') BeaconEvolution.expand();
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

    // Export the selected finding's full context (Detail body + TI
    // Results + Analyst Notes) as a plain-text file. Pure client-side:
    // everything is already on the finding payload, so no extra round
    // trip and no new endpoint to authenticate.
    const exportBtn = document.getElementById('export-notes-btn');
    if (exportBtn) {
      exportBtn.addEventListener('click', () => {
        if (_pivotCtx) {
          if (_pivotCtx.type === 'host') _downloadHostPivotText(_pivotCtx.label, _pivotCtx.hrs, _pivotCtx.findings);
          else                           _downloadCampaignPivotText(_pivotCtx.label, _pivotCtx.findings);
          return;
        }
        if (!_selectedFinding) return;
        _downloadFindingText(_selectedFinding);
      });
    }
  }

  // _downloadFindingText builds a self-contained text file: a
  // finding-context header (so the file is readable on its own without
  // the Archer UI), the detector's Detail body, TI Results, and the
  // analyst notes thread. TI vs analyst partitioning mirrors the dock's
  // exact-match on author === "TI Enrichment" (see detail.js's
  // _renderNotes). Locked by a Go-side contract test (NEW-108).
  function _downloadFindingText(f) {
    const sep = '────────────────────────────────────────────────────────────';
    const dst = f.dst_ip ? (f.dst_ip + (f.dst_port ? ':' + f.dst_port : '')) : '';
    const techs = (window.ATTACK_MAP && window.ATTACK_MAP[f.type]) || [];
    const attackLine = techs.map(t => `${t.id} ${t.name}`).join('; ');
    const lines = [
      `Archer Finding #${f.id}`,
      sep,
      `Type:        ${f.type || ''}`,
      `ATT&CK:      ${attackLine}`,
      `Severity:    ${f.severity || ''}`,
      `Score:       ${f.score == null ? '' : f.score}`,
      `Source:      ${f.src_ip || ''}`,
      `Destination: ${dst}`,
      `Timestamp:   ${f.timestamp || ''} UTC`,
      `Status:      ${f.status || 'open'}`,
      `Sensor:      ${f.sensor || ''}`,
      sep,
      '',
      'DETAIL',
      sep,
      f.detail ? String(f.detail) : '(no detail)',
      '',
    ];

    const notes = Array.isArray(f.notes) ? f.notes : [];
    const tiNotes = notes.filter(n => (n.author || '') === 'TI Enrichment');
    const analystNotes = notes.filter(n => (n.author || '') !== 'TI Enrichment');

    lines.push('TI RESULTS', sep);
    if (tiNotes.length === 0) {
      lines.push('(no TI results)', '');
    } else {
      tiNotes.forEach((n, i) => {
        lines.push(`TI Result ${i + 1} — ${n.author || 'unknown'} • ${n.timestamp || ''}`);
        lines.push(n.text || '');
        lines.push('');
      });
    }

    lines.push('ANALYST NOTES', sep);
    if (analystNotes.length === 0) {
      lines.push('(no notes)', '');
    } else {
      analystNotes.forEach((n, i) => {
        lines.push(`Note ${i + 1} — ${n.author || 'unknown'} • ${n.timestamp || ''}`);
        lines.push(n.text || '');
        lines.push('');
      });
    }

    const blob = new Blob([lines.join('\n')], {type: 'text/plain;charset=utf-8'});
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `archer-finding-${f.id}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  const _TI_TYPES_EXPORT = new Set(['TI Hit (IP)', 'TI Hit (Domain)', 'TI Hit (Hash)', 'Threat Intel Hit']);

  function _downloadHostPivotText(ip, hrs, findings) {
    const sep = '────────────────────────────────────────────────────────────';
    const lines = [`Archer Host Risk Summary — ${ip}`, sep];
    if (hrs) {
      lines.push(`Composite Risk: ${hrs.score}  [${hrs.severity}]`);
      lines.push(`Detail: ${hrs.detail || ''}`);
    }
    lines.push('', `CONTACT SET (${findings.length})`, sep);
    findings.forEach(f => {
      const dst = f.dst_ip ? (f.dst_ip + (f.dst_port ? ':' + f.dst_port : '')) : '';
      lines.push(`[${f.score | 0}] ${f.type}   ${dst}   ${(f.timestamp || '').slice(0, 16)}`);
      if (f.detail) lines.push(`  ${f.detail}`);
    });
    const tiHits = findings.filter(f => _TI_TYPES_EXPORT.has(f.type));
    lines.push('', `TI RESULTS (${tiHits.length})`, sep);
    if (tiHits.length === 0) {
      lines.push('(no threat intel matches)');
    } else {
      tiHits.forEach(f => {
        const dst = f.dst_ip ? (f.dst_ip + (f.dst_port ? ':' + f.dst_port : '')) : '';
        lines.push(`${f.type}   ${dst}   ${(f.timestamp || '').slice(0, 16)}`);
        if (f.detail) lines.push(`  ${f.detail}`);
      });
    }
    _downloadBlob(`archer-host-${ip}-${_ts()}.txt`, 'text/plain', lines.join('\n'));
  }

  function _downloadCampaignPivotText(label, findings) {
    const sep = '────────────────────────────────────────────────────────────';
    const lines = [`Archer Campaign — ${label}`, sep, `Findings (${findings.length})`, sep];
    findings.forEach(f => {
      lines.push(`[${f.score | 0}] ${f.type}   ${f.src_ip || ''}   ${(f.timestamp || '').slice(0, 16)}`);
      if (f.detail) lines.push(`  ${f.detail}`);
    });
    const tiHits = findings.filter(f => _TI_TYPES_EXPORT.has(f.type));
    lines.push('', `TI RESULTS (${tiHits.length})`, sep);
    if (tiHits.length === 0) {
      lines.push('(no threat intel matches)');
    } else {
      tiHits.forEach(f => {
        lines.push(`${f.type}   ${f.src_ip || ''}   ${(f.timestamp || '').slice(0, 16)}`);
        if (f.detail) lines.push(`  ${f.detail}`);
      });
    }
    const safeLabel = label.replace(/[^a-zA-Z0-9._-]/g, '_');
    _downloadBlob(`archer-campaign-${safeLabel}-${_ts()}.txt`, 'text/plain', lines.join('\n'));
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
        _reloadFindingsInPlace();
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
          _reloadFindingsInPlace();
        });
        listEl.appendChild(row);
      });
    }

    document.getElementById('suppressions-btn').addEventListener('click', async () => {
      await _renderSuppressions();
      dlg.showModal();
    });
  }

  // ── Pair allowlist (tuple-scoped permanent view filter) ───────────────────
  // _openPairAllowAdd pre-fills the add dialog from the right-clicked
  // finding. Scope defaults to that finding's own type — muting
  // "Beacon" on a known-good DNS pair must not also blind the DNS
  // Tunneling detector on the same pair. "All finding types" is the
  // deliberate broaden.
  function _openPairAllowAdd(f) {
    const dlg = document.getElementById('pair-allow-add-dialog');
    document.getElementById('pa-src').value    = f.src_ip || '';
    document.getElementById('pa-dst').value    = f.dst_ip || '';
    document.getElementById('pa-port').value   = f.dst_port || '';
    document.getElementById('pa-sensor').value = f.sensor || '';
    const scope = document.getElementById('pa-scope');
    const ftype = f.type || '';
    scope.options[0].value = ftype;
    scope.options[0].textContent = ftype ? `Only "${ftype}" findings` : 'This finding type';
    scope.selectedIndex = 0;
    document.getElementById('pa-detail').value = '';
    const err = document.getElementById('pa-error');
    err.style.display = 'none';
    dlg.showModal();
  }

  async function _renderPairAllow() {
    const listEl = document.getElementById('pair-allow-list');
    listEl.textContent = 'Loading…';
    let data;
    try { data = await api('/api/pair-allowlist'); }
    catch (e) { listEl.textContent = 'Error loading pair allowlist.'; return; }
    if (!Array.isArray(data) || data.length === 0) {
      listEl.innerHTML = '<div style="color:var(--fg-dim);font-size:13px">No pair allowlist rules.</div>';
      return;
    }
    listEl.innerHTML = '';
    data.forEach(p => {
      const when  = p.created_at ? new Date(p.created_at * 1000).toUTCString().replace(' GMT', ' UTC') : '';
      const scope = p.finding_type ? _esc(p.finding_type) : 'all finding types';
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)';
      row.innerHTML = `
        <div style="flex:1;min-width:0">
          <div style="font-family:monospace;font-size:13px">${_esc(p.src)} → ${_esc(p.dst)} : ${_esc(p.port || '·')}</div>
          <div style="font-size:11px;color:var(--fg-dim);margin-top:2px">Scope: ${scope}${p.sensor ? ' · Sensor: ' + _esc(p.sensor) : ''}</div>
          ${p.detail ? `<div style="font-size:11px;color:var(--fg-dim);margin-top:2px">${_esc(p.detail)}</div>` : ''}
          <div style="font-size:11px;color:var(--fg-dim);margin-top:2px">Added ${_esc(p.created_by || 'unknown')}${when ? ' · ' + when : ''}</div>
        </div>
        <button class="dlg-btn secondary" style="padding:3px 10px;font-size:12px;flex-shrink:0">Remove</button>`;
      row.querySelector('button').addEventListener('click', async () => {
        await api(`/api/pair-allowlist/${p.id}`, {method: 'DELETE'}).catch(() => {});
        setStatus(`Removed pair rule ${p.src} → ${p.dst}:${p.port || ''}`);
        await _renderPairAllow();
        _reloadFindingsInPlace();
      });
      listEl.appendChild(row);
    });
  }

  function initPairAllowlist() {
    const addDlg = document.getElementById('pair-allow-add-dialog');
    document.getElementById('pa-cancel').addEventListener('click', () => addDlg.close());
    document.getElementById('pa-ok').addEventListener('click', async () => {
      const src  = document.getElementById('pa-src').value.trim();
      const dst  = document.getElementById('pa-dst').value.trim();
      const port = document.getElementById('pa-port').value.trim();
      const sensor = document.getElementById('pa-sensor').value.trim();
      const finding_type = document.getElementById('pa-scope').value;
      const detail = document.getElementById('pa-detail').value.trim();
      const err = document.getElementById('pa-error');
      if (!src || !dst) {
        err.textContent = 'Source and destination are required.';
        err.style.display = 'block';
        return;
      }
      try {
        await api('/api/pair-allowlist', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({src, dst, port, sensor, finding_type, detail}),
        });
        addDlg.close();
        setStatus(`Pair allowlisted ${src} → ${dst}:${port || ''}`);
        _reloadFindingsInPlace();
        // Keep the Relationships tab fresh if the Allowlist dialog is open.
        if (document.getElementById('allowlist-dialog').open) _renderPairAllow();
      } catch (e) {
        err.textContent = e || 'Failed to add rule.';
        err.style.display = 'block';
      }
    });
  }

  // ── Allowlist / IOC dialogs ────────────────────────────────────────────────
  // The Allowlist dialog carries two tabs: "entries" (the IP/CIDR/domain
  // textarea, explicit Save) and "relationships" (the pair allowlist —
  // changes are immediate via per-row Remove, so Save is irrelevant and
  // the secondary button reads "Close").
  function _setAllowlistTab(name) {
    document.querySelectorAll('#allowlist-tabs .dlg-tab-btn').forEach(b =>
      b.classList.toggle('active', b.dataset.altab === name));
    document.querySelectorAll('#allowlist-dialog .al-tab-panel').forEach(p =>
      p.classList.toggle('active', p.dataset.alpanel === name));
    const noSave = name === 'relationships' || name === 'suggestions';
    document.getElementById('allowlist-save').style.display = noSave ? 'none' : '';
    document.getElementById('allowlist-cancel').textContent = noSave ? 'Close' : 'Cancel';
    if (name === 'relationships') _renderPairAllow();
    if (name === 'suggestions')   _renderSuggestAllow();
  }

  async function _renderSuggestAllow() {
    const listEl = document.getElementById('suggest-allow-list');
    listEl.textContent = 'Loading…';
    let data;
    try { data = await api('/api/pair-allowlist/suggested'); }
    catch (e) { listEl.textContent = 'Error loading suggestions.'; return; }
    if (!Array.isArray(data) || data.length === 0) {
      listEl.innerHTML = '<div style="color:var(--fg-dim);font-size:13px">No suggestions — no acknowledged beacons have re-fired for 14+ days.</div>';
      return;
    }
    listEl.innerHTML = '';
    data.forEach(s => {
      const card = document.createElement('div');
      card.style.cssText = 'padding:10px 0;border-bottom:1px solid var(--border)';
      const idMeta = [
        s.sensor ? 'sensor: ' + s.sensor : '',
        s.host   ? 'host: '   + s.host   : '',
        s.uri    ? 'uri: '    + s.uri    : '',
      ].filter(Boolean).join(' · ');
      card.innerHTML =
        '<div style="font-family:monospace;font-size:13px">' + _esc(s.src_ip) + ' → ' + _esc(s.dst_ip) + ' : ' + _esc(s.dst_port || '·') + '</div>' +
        '<div style="font-size:11px;color:var(--fg-dim);margin-top:2px">' +
          _esc(s.finding_type) + ' · ' + _esc(String(s.day_count)) + ' days (' + _esc(s.first_seen) + ' → ' + _esc(s.last_seen) + ')' +
          ' · peak score ' + _esc(String(s.peak_score)) +
          (s.acked_by ? ' · acked by ' + _esc(s.acked_by) : '') +
        '</div>' +
        (idMeta ? '<div style="font-size:11px;color:var(--fg-dim);margin-top:2px">' + _esc(idMeta) + '</div>' : '') +
        '<div style="display:flex;gap:8px;margin-top:8px;align-items:center">' +
          '<input type="text" class="dlg-input sg-just" placeholder="Justification (required)" style="flex:1;font-size:12px">' +
          '<button class="dlg-btn primary sg-apply" style="padding:3px 12px;font-size:12px;flex-shrink:0">Apply</button>' +
        '</div>' +
        '<div class="sg-error" style="display:none;color:var(--sev-high);font-size:11px;margin-top:4px"></div>';
      const input   = card.querySelector('.sg-just');
      const btn     = card.querySelector('.sg-apply');
      const errEl   = card.querySelector('.sg-error');
      btn.addEventListener('click', async () => {
        const detail = input.value.trim();
        if (!detail) {
          errEl.textContent = 'Justification is required.';
          errEl.style.display = 'block';
          return;
        }
        errEl.style.display = 'none';
        btn.disabled = true;
        try {
          await api('/api/pair-allowlist', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({src: s.src_ip, dst: s.dst_ip, port: s.dst_port, finding_type: s.finding_type, sensor: s.sensor || '', detail}),
          });
          setStatus('Allowlisted ' + s.src_ip + ' → ' + s.dst_ip + ':' + (s.dst_port || ''));
          card.remove();
          _reloadFindingsInPlace();
          if (document.getElementById('allowlist-dialog').open) _renderPairAllow();
        } catch (e) {
          errEl.textContent = e || 'Failed.';
          errEl.style.display = 'block';
          btn.disabled = false;
        }
      });
      listEl.appendChild(card);
    });
  }

  function initListDialogs() {
    const alDlg = document.getElementById('allowlist-dialog');
    document.querySelectorAll('#allowlist-tabs .dlg-tab-btn').forEach(b =>
      b.addEventListener('click', () => _setAllowlistTab(b.dataset.altab)));
    document.getElementById('allowlist-btn').addEventListener('click', async () => {
      const data = await api('/api/allowlist').catch(() => []);
      document.getElementById('allowlist-ta').value = (Array.isArray(data) ? data : []).join('\n');
      _setAllowlistTab('entries');
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
      _reloadFindingsInPlace();
      _loadAllowSet();
    });

    const iocDlg = document.getElementById('ioc-dialog');
    document.querySelectorAll('#ioc-tabs .dlg-tab-btn').forEach(b =>
      b.addEventListener('click', () => _setIOCTab(b.dataset.ioctab)));
    document.getElementById('ioc-btn').addEventListener('click', async () => {
      const [net, fp] = await Promise.all([
        api('/api/ioc').catch(() => []),
        api('/api/ioc?kind=fp').catch(() => ({})),
      ]);
      document.getElementById('ioc-ta').value = (Array.isArray(net) ? net : []).join('\n');
      document.getElementById('ioc-fp-ta').value = _composeFPText(fp);
      _setIOCTab('net');
      iocDlg.showModal();
    });
    document.getElementById('ioc-cancel').addEventListener('click', () => iocDlg.close());
    document.getElementById('ioc-save').addEventListener('click', async () => {
      const netLines = document.getElementById('ioc-ta').value
        .split('\n').map(s => s.trim()).filter(Boolean);
      const fpLines = document.getElementById('ioc-fp-ta').value
        .split('\n').map(s => s.trim()).filter(Boolean);
      // Both panels are always in the DOM, so save persists whichever tab the
      // operator edited — the net list and the JA3/JA4 list go in one click.
      try {
        await api('/api/ioc', {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(netLines),
        });
        await api('/api/ioc?kind=fp', {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(fpLines),
        });
      } catch (e) {
        setStatus('Error: ' + e);
        return;
      }
      setStatus('IOC list saved');
      iocDlg.close();
      _loadIOCList();
      // The network IOC list is matched at /api/findings read time (the "ioc"
      // chip / ioc_match), so refresh the table; the JA3/JA4 fp sublist is
      // analysis-time and unaffected until the next pass.
      _reloadFindingsInPlace();
    });
  }

  function _setIOCTab(name) {
    document.querySelectorAll('#ioc-tabs .dlg-tab-btn').forEach(b =>
      b.classList.toggle('active', b.dataset.ioctab === name));
    document.querySelectorAll('#ioc-dialog .ioc-tab-panel').forEach(p =>
      p.classList.toggle('active', p.dataset.iocpanel === name));
  }

  // _composeFPText builds the JA3/JA4 textarea from /api/ioc?kind=fp: a comment
  // banner, the always-active built-in fingerprints (each with an inline label),
  // then the operator's own entries. Built-in lines are informational — the
  // server strips them on save and re-emits them here on the next open.
  function _composeFPText(data) {
    const builtin = (data && Array.isArray(data.builtin)) ? data.builtin : [];
    const operator = (data && Array.isArray(data.operator)) ? data.operator : [];
    const lines = [
      '# Built-in C2 fingerprints — always active, cannot be removed.',
      '# (editing the lines below has no effect; they return on save)',
    ];
    // Trim the parenthetical variant suffix (e.g. " (no SNI)") off the inline
    // label so the longer JA4 lines don't soft-wrap in the textarea.
    builtin.forEach(b => {
      const label = (b.label || 'built-in').replace(/\s*\([^)]*\)/g, '').trim();
      lines.push(b.fingerprint + '  # ' + label);
    });
    lines.push('', '# Your fingerprints (one JA3 or JA4 per line):');
    operator.forEach(o => lines.push(o));
    return lines.join('\n') + '\n';
  }

  // ── Settings dialog ────────────────────────────────────────────────────────
  // Tabs only toggle panel visibility; every config input stays in the DOM,
  // so _collectSettings/_collectArchive (id-based) save the whole form
  // regardless of which tab is active.
  function _setSettingsTab(name) {
    document.querySelectorAll('#settings-tabs .dlg-tab-btn').forEach(b =>
      b.classList.toggle('active', b.dataset.settab === name));
    document.querySelectorAll('#settings-dialog .settings-tab-panel').forEach(p =>
      p.classList.toggle('active', p.dataset.setpanel === name));
  }

  // Skin is a per-browser UI preference, not server config: applied to
  // <html data-theme> (the early head script seeds it before first paint) and
  // persisted to localStorage. Canvas-drawn surfaces can't observe CSS-var
  // changes, so applyTheme fires archer:themechange for graph/chart to redraw.
  function applyTheme(name) {
    document.documentElement.setAttribute('data-theme', name);
    window.dispatchEvent(new CustomEvent('archer:themechange', { detail: { theme: name } }));
  }

  function initTheme() {
    const sel = document.getElementById('cfg-theme');
    if (!sel) return;
    // Reflect the saved skin. The <option> list is the source of truth for
    // valid values: an unknown saved value leaves selectedIndex at -1, so we
    // fall the select back to cobalt (CSS already falls back via the base :root).
    sel.value = localStorage.getItem('archer.theme') || 'cobalt';
    if (sel.selectedIndex < 0) sel.value = 'cobalt';
    sel.addEventListener('change', () => {
      localStorage.setItem('archer.theme', sel.value);
      applyTheme(sel.value);
    });
  }

  function initSettings() {
    const dlg = document.getElementById('settings-dialog');
    initTheme();
    document.querySelectorAll('#settings-tabs .dlg-tab-btn').forEach(b =>
      b.addEventListener('click', () => _setSettingsTab(b.dataset.settab)));
    document.getElementById('settings-btn').addEventListener('click', async () => {
      // Non-admins get Settings too, but only the Appearance tab (theme is a
      // per-browser preference). Skip the admin config fetches and open
      // straight to Appearance; tab/Save visibility is gated once at init.
      if (!(_currentUser && _currentUser.role === 'admin')) {
        _setSettingsTab('appearance');
        dlg.showModal();
        return;
      }
      const [cfg, archive] = await Promise.all([
        api('/api/config').catch(() => ({})),
        api('/api/archive').catch(() => null),
      ]);
      _populateSettings(cfg);
      _populateArchive(archive);
      _refreshDiskUsage(); // populates the Disk Usage row and the warning banner
      _refreshDetectorActivity(); // populates the Detector Health block
      const sec = document.getElementById('service-tokens-section');
      if (sec) sec.style.display = '';
      _loadServiceTokens();
      _setSettingsTab('detection');
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
        // the new filter is reflected without a page reload. Honor the
        // active per-tab pagination so this re-render doesn't dump
        // every row into the DOM.
        _orgCIDRs = Array.isArray(payload.org_internal_cidrs) ? payload.org_internal_cidrs : [];
        Campaigns.build(_allFindings, {
          campaignsOffset: _aggTabState.campaigns.offset,
          campaignsLimit:  _pageSize,
          hostsOffset:     _aggTabState.hosts.offset,
          hostsLimit:      _pageSize,
        });
        _aggTabState.campaigns.total = Campaigns.getCampaigns().length;
        _aggTabState.hosts.total     = Campaigns.getHosts().length;
        _clampAggOffset(_aggTabState.campaigns);
        _clampAggOffset(_aggTabState.hosts);
        _updatePaginationFooter();
        setStatus('Settings saved');
      } catch (e) {
        setStatus('Error: ' + e);
      }
      dlg.close();
    });

    // DB backup: anchor click against /api/admin/backup so the browser
    // streams the response straight to disk instead of buffering the
    // whole .db into memory like fetch + blob would. Same-origin GET
    // carries the session cookie, so admin auth flows naturally.
    // Server returns Content-Disposition with a timestamped filename;
    // download="" leaves the filename to the server's header.
    const backupBtn = document.getElementById('db-backup-btn');
    const backupStatus = document.getElementById('db-backup-status');
    if (backupBtn) {
      backupBtn.addEventListener('click', () => {
        backupStatus.textContent = 'Snapshotting…';
        backupStatus.style.color = 'var(--fg-dim)';
        const a = document.createElement('a');
        a.href = '/api/admin/backup';
        a.download = '';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        // The browser handles the rest. There's no completion event we
        // can hang off a cross-process file save, so flip the message
        // to a quiet "started" tone shortly after the click and clear
        // it on the next dialog open.
        setTimeout(() => {
          backupStatus.textContent = 'Download started — check your browser';
          backupStatus.style.color = 'var(--accent)';
        }, 300);
      });
    }

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
            _setAnalyzing(true);
            dlg.close();
          }
        } catch (e) {
          if (String(e).includes('already running') || String(e).includes('in progress') || String(e).includes('409')) {
            resetStatus.textContent = 'Server busy — try again';
            resetStatus.style.color = 'var(--sev-high, #c66)';
            try {
              const st = await api('/api/analyze/status');
              if (st.blocked) { _startMaintenancePoll(); }
              else if (st.running) { _applyRunningState(st); }
              else { _setAnalyzing(false); }
            } catch (_) {}
          } else {
            resetStatus.textContent = 'Error: ' + e;
            resetStatus.style.color = 'var(--sev-high, #c66)';
          }
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
            _setAnalyzing(true);
          }
        } catch (e) {
          if (String(e).includes('already') || String(e).includes('in progress') || String(e).includes('409')) {
            runStatus.textContent = 'Server busy — try again';
            runStatus.style.color = 'var(--sev-high, #c66)';
            try {
              const st = await api('/api/analyze/status');
              if (st.blocked) { _startMaintenancePoll(); }
              else if (st.running) { _applyRunningState(st); }
              else { _setAnalyzing(false); }
            } catch (_) {}
          } else {
            runStatus.textContent = 'Scan error: ' + e;
            runStatus.style.color = 'var(--sev-high, #c66)';
          }
        }
        // The scan runs in the background; the existing SSE flow handles
        // progress + done. We re-enable the button immediately so the
        // operator can close Settings and watch the regular UI for results.
        scanBtn.disabled = false;
      });
    }
  }

  // ── Service tokens ──────────────────────────────────────────────────────────

  async function _loadServiceTokens() {
    const list   = document.getElementById('service-token-list');
    const status = document.getElementById('service-token-status');
    if (!list) return;
    try {
      const tokens = await api('/api/service-tokens');
      if (!tokens.length) {
        list.innerHTML = '<div style="color:var(--fg-dim);font-size:0.9em">No tokens yet.</div>';
        return;
      }
      list.innerHTML = tokens.map(t => {
        const d = new Date(t.created_at * 1000).toLocaleDateString();
        return `<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;font-size:0.9em">
          <span style="flex:1;font-family:monospace">${_esc(t.label)}</span>
          <span style="color:var(--fg-dim)">${_esc(t.created_by)} · ${d}</span>
          <button class="dlg-btn secondary" data-revoke-id="${t.id}" type="button" style="padding:2px 8px">Revoke</button>
        </div>`;
      }).join('');
      list.querySelectorAll('[data-revoke-id]').forEach(btn => {
        btn.addEventListener('click', () => _revokeServiceToken(parseInt(btn.dataset.revokeId, 10)));
      });
    } catch (e) {
      if (status) status.textContent = 'Failed to load tokens.';
    }
  }

  async function _revokeServiceToken(id) {
    const status = document.getElementById('service-token-status');
    try {
      await api(`/api/service-tokens/${id}`, { method: 'DELETE' });
      if (status) { status.textContent = 'Token revoked.'; setTimeout(() => { status.textContent = ''; }, 3000); }
      _loadServiceTokens();
    } catch (e) {
      if (status) status.textContent = 'Revoke failed: ' + e;
    }
  }

  (function _initServiceTokenCreate() {
    const btn = document.getElementById('service-token-create-btn');
    if (!btn) return;
    btn.addEventListener('click', async () => {
      const labelEl = document.getElementById('service-token-label');
      const newBox  = document.getElementById('service-token-new');
      const valEl   = document.getElementById('service-token-value');
      const status  = document.getElementById('service-token-status');
      const label   = labelEl ? labelEl.value.trim() : '';
      if (!label) { if (status) status.textContent = 'Enter a label first.'; return; }
      try {
        const res = await api('/api/service-tokens', { method: 'POST', body: JSON.stringify({ label }) });
        if (labelEl) labelEl.value = '';
        if (newBox)  newBox.style.display = '';
        if (valEl)   valEl.textContent = res.token || '';
        if (status)  { status.textContent = 'Token created.'; setTimeout(() => { status.textContent = ''; }, 5000); }
        _loadServiceTokens();
      } catch (e) {
        if (status) status.textContent = 'Create failed: ' + e;
      }
    });
  })();

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

  // _refreshDetectorActivity hits /api/detector-activity and repaints the
  // Settings "Detector Health" block. Same cadence as disk usage. Silent on
  // error — this is an advisory health panel, not a load-bearing surface.
  async function _refreshDetectorActivity() {
    let data = null;
    try { data = await api('/api/detector-activity'); } catch (_) { data = null; }
    _renderDetectorActivityBlock(data);
  }

  function _renderDetectorActivityBlock(data) {
    const el = document.getElementById('detector-activity-content');
    if (!el) return;
    el.innerHTML = '';
    if (!data || !Array.isArray(data.detectors) || data.detectors.length === 0) {
      el.textContent = 'No detections recorded yet.';
      return;
    }
    const dropped = data.detectors.filter(d => d.dropped);
    if (dropped.length > 0) {
      const warn = document.createElement('div');
      warn.style.cssText = 'color:var(--sev-high,#f97316);font-weight:600;margin-bottom:6px';
      warn.textContent = dropped.length + ' detector' + (dropped.length === 1 ? '' : 's') +
        ' went silent this week — check the sensor feed and Zeek policy.';
      el.appendChild(warn);
    }
    const table = document.createElement('div');
    table.style.cssText = 'display:grid;grid-template-columns:1fr auto auto auto;gap:2px 14px;align-items:baseline';
    const head = (txt, alignEnd) => {
      const h = document.createElement('span');
      h.textContent = txt;
      h.style.cssText = 'font-size:10px;color:var(--fg-dim);text-transform:uppercase;letter-spacing:0.05em' +
        (alignEnd ? ';text-align:end' : '');
      return h;
    };
    table.appendChild(head('Detector'));
    table.appendChild(head('7d', true));
    table.appendChild(head('Prior 7d', true));
    table.appendChild(head('Total', true));
    data.detectors.forEach(d => {
      const name = document.createElement('span');
      name.textContent = d.dropped ? '⚠ ' + d.type : d.type;
      name.style.cssText = 'font-family:ui-monospace,monospace;white-space:nowrap;' +
        (d.dropped ? 'color:var(--sev-high,#f97316);font-weight:600' : 'color:var(--fg-primary)');
      const cell = val => {
        const c = document.createElement('span');
        c.textContent = val;
        c.style.cssText = 'font-family:ui-monospace,monospace;text-align:end;' +
          (d.dropped ? 'color:var(--sev-high,#f97316)' : 'color:var(--fg-primary)');
        return c;
      };
      table.appendChild(name);
      table.appendChild(cell(d.count_7d));
      table.appendChild(cell(d.count_prior_7d));
      table.appendChild(cell(d.total));
    });
    el.appendChild(table);
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
    set('cfg-http-beacon-thresh', cfg.http_beacon_min_requests);
    set('cfg-strobe-thresh',  cfg.strobe_min_connections);
    set('cfg-longconn',       cfg.long_conn_min_hours);
    set('cfg-exfil',          cfg.exfil_min_bytes_mb);
    set('cfg-nxdomain',       cfg.dns_nxdomain_threshold);
    set('cfg-tunnelbytes',    cfg.dns_tunnel_label_len);
    set('cfg-tunneldiv',      cfg.dns_unique_subdomain_min);
    set('cfg-dns-beacon-thresh', cfg.dns_beacon_min_queries);
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
    const alwaysFull = document.getElementById('cfg-watch-always-full');
    if (alwaysFull) alwaysFull.checked = !!cfg.watch_always_full;

    const sensorStale = document.getElementById('cfg-sensor-stale-hours');
    const feedStale   = document.getElementById('cfg-feed-stale-hours');
    const rsyncStale  = document.getElementById('cfg-rsync-stale-hours');
    if (sensorStale) sensorStale.value = cfg.sensor_stale_threshold_hours || 2;
    if (feedStale)   feedStale.value   = cfg.feed_stale_threshold_hours   || 24;
    if (rsyncStale)  rsyncStale.value  = cfg.rsync_stale_threshold_hours  || 4;
    const auditRet = document.getElementById('cfg-audit-retention');
    if (auditRet) auditRet.value = cfg.audit_log_retention_days || 0;
    const specEn = document.getElementById('cfg-spectral-enabled');
    // spectral_enabled defaults true in config.Default(); upgraded
    // installs preserve that value because json.Unmarshal only
    // overwrites fields present in the stored blob. Treat undefined
    // as the default (true) so the checkbox reflects what the
    // analyzer will actually do.
    if (specEn) specEn.checked = cfg.spectral_enabled !== false;
    // Spectral calibration knobs. Missing-on-upgrade behavior: the
    // server seeds Default() before unmarshal so the in-memory cfg
    // already has the right defaults — but the JSON returned to the
    // SPA reflects whatever the server has, which after upgrade may
    // include defaults that weren't in the stored blob. Use the
    // fallback only for genuinely-absent fields (undefined), not for
    // legitimate operator-set zeros.
    const specMinObs  = document.getElementById('cfg-spectral-min-obs');
    if (specMinObs)  specMinObs.value  = cfg.spectral_min_observations  != null ? cfg.spectral_min_observations  : 16;
    const specFAP    = document.getElementById('cfg-spectral-fap');
    if (specFAP)     specFAP.value     = cfg.spectral_fap_threshold     != null ? cfg.spectral_fap_threshold     : 12;
    const specRescue = document.getElementById('cfg-spectral-rescue');
    if (specRescue)  specRescue.value  = cfg.spectral_rescue_threshold  != null ? cfg.spectral_rescue_threshold  : 0.5;
    const dgaEn = document.getElementById('cfg-dga-enabled');
    if (dgaEn) dgaEn.checked = cfg.dga_enabled !== false;
    const dgaEntropy = document.getElementById('cfg-dga-entropy');
    if (dgaEntropy) dgaEntropy.value = cfg.dga_entropy_threshold != null ? cfg.dga_entropy_threshold : 3.5;
    const dgaBigram = document.getElementById('cfg-dga-bigram');
    if (dgaBigram) dgaBigram.value = cfg.dga_bigram_threshold != null ? cfg.dga_bigram_threshold : -4.5;
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
      beacon_min_connections:   parseInt(g('cfg-beacon-thresh'), 10),
      http_beacon_min_requests: parseInt(g('cfg-http-beacon-thresh'), 10),
      strobe_min_connections:   parseInt(g('cfg-strobe-thresh'))      || 1000,
      long_conn_min_hours:      parseFloat(g('cfg-longconn'))     || 1.0,
      exfil_min_bytes_mb:       parseFloat(g('cfg-exfil'))        || 5.0,
      dns_nxdomain_threshold:   parseInt(g('cfg-nxdomain'))       || 200,
      dns_tunnel_label_len:     parseInt(g('cfg-tunnelbytes'))    || 40,
      dns_unique_subdomain_min: parseInt(g('cfg-tunneldiv'))      || 50,
      dns_beacon_min_queries:   parseInt(g('cfg-dns-beacon-thresh'), 10),
      virustotal_api_key:       g('cfg-vt-key'),
      abuseipdb_api_key:        g('cfg-abuse-key'),
      otx_api_key:              g('cfg-otx-key'),
      crowdsec_api_key:         g('cfg-crowdsec-key'),
      greynoise_api_key:        g('cfg-greynoise-key'),
      censys_api_id:            g('cfg-censys-id').trim(),
      censys_api_secret:        g('cfg-censys-secret').trim(),
      org_internal_cidrs:       cidrs,
      watch_always_full:        !!(document.getElementById('cfg-watch-always-full') || {}).checked,
      spectral_enabled:         !!(document.getElementById('cfg-spectral-enabled') || {}).checked,
      spectral_min_observations: parseInt(g('cfg-spectral-min-obs'))  || 16,
      spectral_fap_threshold:    parseFloat(g('cfg-spectral-fap'))    || 12,
      spectral_rescue_threshold: parseFloat(g('cfg-spectral-rescue')) || 0.5,
      dga_enabled:              !!(document.getElementById('cfg-dga-enabled') || {}).checked,
      dga_entropy_threshold:    parseFloat(g('cfg-dga-entropy')) || 3.5,
      dga_bigram_threshold:     parseFloat(g('cfg-dga-bigram'))  || -4.5,
      sensor_stale_threshold_hours: parseInt(g('cfg-sensor-stale-hours')) || 2,
      feed_stale_threshold_hours:   parseInt(g('cfg-feed-stale-hours'))   || 24,
      rsync_stale_threshold_hours:  parseInt(g('cfg-rsync-stale-hours'))  || 4,
      audit_log_retention_days:     parseInt(g('cfg-audit-retention'))    || 0,
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
    _renderWatchSidebarStatus(cfg);
  }

  // _renderWatchSidebarStatus fills the read-only sidebar lines visible to
  // every role: cadence + run time, and the configured timezone. The
  // enabled/disabled label is set by _updateWatchUI; the controls themselves
  // live in the admin-only modal. Configured schedule shows even when watch
  // is disabled so a non-admin can see what's set up.
  function _renderWatchSidebarStatus(cfg) {
    const whenEl = document.getElementById('watch-status-when');
    const tzEl   = document.getElementById('watch-status-tz');
    if (!cfg) return;
    const interval = (cfg.interval_hours === 24) ? 0 : (cfg.interval_hours || 0);
    if (whenEl) {
      if (!cfg.time) {
        whenEl.textContent = '';
      } else if (interval === 1) {
        whenEl.textContent = `Hourly at :${cfg.time.split(':')[1] || '00'}`;
      } else {
        const cad = _watchCadenceLabel(interval);
        whenEl.textContent = `${cad.charAt(0).toUpperCase() + cad.slice(1)} at ${cfg.time}`;
      }
    }
    if (tzEl) {
      const tz = cfg.timezone || 'UTC';
      tzEl.textContent = cfg.timezone_abbr ? `${tz} (${cfg.timezone_abbr})` : tz;
    }
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
      labelEl.textContent = 'First full scan at';
      timeInput.style.display = '';
      minInput.style.display  = 'none';
    }
  }

  // _renderWatchSchedulePreview shows the upcoming-run state at the bottom
  // of the watch sidebar. The cadence / anchor / TZ are already visible in
  // the controls above (dropdown, time input, timezone input), so we don't
  // restate any of them — the preview is just "what's about to happen,"
  // in the timezone the user already configured.
  function _renderWatchSchedulePreview(cfg) {
    const el = document.getElementById('watch-schedule-preview');
    if (!el) return;
    el.innerHTML = '';
    if (!cfg || !cfg.enabled) { el.textContent = ''; return; }
    if (!cfg.next_run) return;

    const interval = (cfg.interval_hours === 24) ? 0 : (cfg.interval_hours || 0);
    const kind     = cfg.next_run_kind || '';

    const line1 = document.createElement('div');
    line1.style.fontSize = '11px';
    line1.style.color = 'var(--fg-dim)';
    let suffix = '';
    if (interval !== 0) {
      if (kind === 'full')        suffix = ' | Full Scan';
      else if (kind === 'incremental') suffix = ' | Incremental TI/IOC';
    }
    line1.textContent = `Next: ${cfg.next_run}${suffix}`;
    el.appendChild(line1);

    // Only mention the next full scan when the next tick is incremental
    // and the server told us when the next full one will fire. Daily
    // cadence (every tick is full) and the "next is already full" case
    // both skip it.
    if (interval !== 0 && kind === 'incremental' && cfg.next_full_run) {
      const line2 = document.createElement('div');
      line2.style.fontSize = '11px';
      line2.style.color = 'var(--fg-dim)';
      line2.textContent = `Next Full Scan: ${cfg.next_full_run}`;
      el.appendChild(line2);
    }
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

    const wdlgClose = document.getElementById('watch-dlg-close');
    if (wdlgClose) {
      wdlgClose.addEventListener('click', () => {
        const dlg = document.getElementById('watch-dlg');
        if (dlg) dlg.close();
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

      // The click-anchor arrow is positioned per right-click below,
      // after the menu has been measured. Default it to top-left so
      // the first paint isn't off in an unrelated corner.
      const arrow = document.getElementById('ctx-arrow');
      if (arrow) {
        arrow.textContent = '↖';
        arrow.setAttribute('data-corner', 'tl');
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

      // Hosts tab right-click: hide the external-lookup submenu. Hosts
      // rows surface internal RFC1918 IPs only (the tab is built from
      // the operator's org-CIDR membership check inside campaigns.js),
      // and the lookup destinations (VT/AbuseIPDB/Shodan/etc.) are
      // public-internet reputation services that have nothing to say
      // about an internal address. The .ctx-target-aware loop above
      // already showed the Lookup item; we override here.
      if (_tabMode === 'hosts') {
        const lookupEl = document.getElementById('ctx-lookup');
        if (lookupEl) lookupEl.style.display = 'none';
      }

      // Source Records pivots a single finding to its underlying Zeek
      // log rows. A Hosts-tab row is a per-host risk roll-up, not a
      // finding, so there's no single record set to resolve — hide the
      // item there. Two-way set: no other loop touches this row-level
      // item, so it must be re-shown off the Hosts tab.
      const srcRecEl = document.getElementById('ctx-source-records');
      if (srcRecEl) srcRecEl.style.display = _tabMode === 'hosts' ? 'none' : '';

      // Correlation pivot: only visible when the right-clicked row is
      // a Correlated Activity finding. The action latches the ids
      // filter to the CA's ID + every contributor ID (from
      // f.correlations) and re-fetches on the Findings tab — see
      // showContributingActivity for the full sequence. Hidden on
      // every other finding type to keep the menu uncluttered.
      const isCA = f && f.type === 'Correlated Activity';
      document.querySelectorAll('.ctx-correlation-only').forEach(el => {
        el.style.display = isCA ? '' : 'none';
      });

      // Role gate: viewers can't perform any write action, so hide them
      // entirely instead of letting the user click into a 403.
      // Tab gate: Acknowledge / Escalate / Suppress operate on a single
      // finding's status. Right-clicks on Campaigns or Hosts rows reach
      // here with a synthesised "row" that doesn't represent a finding
      // those actions can target — hide them on those tabs to keep the
      // menu honest.
      const role = (_currentUser && _currentUser.role) || 'viewer';
      const isViewer = role === 'viewer';
      const onAggregateTab = _isAggregateTab(_tabMode);
      // Bulk-Dismiss is offered on the top-level Campaigns view only.
      // On Dismissed > Campaigns everything is already dismissed, so the
      // item would be a confusing no-op; on Hosts a bulk dismiss across
      // a source IP would erase that host's risk story, so it's exempt.
      const onCampaignsTab = _tabMode === 'campaigns';
      document.querySelectorAll('.ctx-write').forEach(el => {
        if (isViewer) { el.style.display = 'none'; return; }
        // Allowlist / IOC act on the right-clicked IP, not on a
        // finding's status, so they apply to a Campaigns row's dst IP
        // even though that row is a synthesised aggregate, not a
        // finding. Every other write (Ack/Escalate/Dismiss/Suppress)
        // needs a real finding and stays hidden on aggregate tabs.
        // Hosts is excluded deliberately: its rows are internal org
        // IPs, where allowlisting/IOC-ing is a footgun — same reason
        // the external-lookup submenu is hidden there.
        const ipScopedWrite = el.classList.contains('ctx-target-aware');
        if (onAggregateTab && !(ipScopedWrite && onCampaignsTab && showColAware)) {
          el.style.display = 'none';
        } else if (!el.classList.contains('ctx-target-aware') || showColAware) {
          el.style.display = '';
        }
      });
      document.querySelectorAll('.ctx-write-sep').forEach(el => {
        // Show the separator on Campaigns so the bulk-Dismiss item below
        // it doesn't float against the column-aware section.
        const show = !isViewer && (!onAggregateTab || onCampaignsTab);
        el.style.display = show ? '' : 'none';
      });
      // Dismiss on Campaigns rows performs a bulk dismiss across every
      // finding in that campaign. Hosts is intentionally exempt — bulk
      // dismissing every finding for a source IP would erase the host's
      // risk story, so the Dismiss item stays hidden there.
      const dismissEl = document.getElementById('ctx-dismiss');
      if (dismissEl && !isViewer && onCampaignsTab) {
        dismissEl.style.display = '';
        dismissEl.classList.remove('ctx-disabled');
        dismissEl.removeAttribute('title');
        dismissEl.firstChild.nodeValue = 'Dismiss campaign';
      }

      // State-aware: don't offer actions that no longer apply.
      const status = (f && f.status) || 'open';
      _disable('ctx-ack',
        status === 'acknowledged' || status === 'escalated' || status === 'dismissed',
        status === 'escalated' ? 'Already escalated'
          : status === 'dismissed' ? 'Already dismissed'
          : 'Already acknowledged');
      _disable('ctx-escalate',
        status === 'escalated' || status === 'dismissed',
        status === 'dismissed' ? 'Already dismissed' : 'Already escalated');
      // Dismiss item toggles label/behaviour based on current status:
      // a dismissed finding offers Un-dismiss (→ status=open) so the
      // analyst can revert a mistake without flipping through the
      // detail pane's status dropdown. Skip on campaign aggregates —
      // the row carries no status and the campaign-aware "Dismiss
      // campaign" label was already set above.
      const dismissItem = document.getElementById('ctx-dismiss');
      if (dismissItem && !(f && f._campaign)) {
        dismissItem.firstChild.nodeValue = status === 'dismissed' ? 'Un-dismiss' : 'Dismiss';
      }
      if (showColAware) {
        _disable('ctx-allowlist', _allowSet.has(_ctxTarget), 'Already on allowlist');
        _disable('ctx-ioc-add',   _iocSet.has(_ctxTarget),   'Already on IOC list');
      }

      // Beacon Chart only matters for findings carrying timeseries data —
      // the analyzer attaches TSData to "Beacon" and "HTTP Beacon"
      // findings only. The list-response projection strips ts_data
      // (see handlers_api.go's listFinding), so we can't gate on its
      // presence here; type is a reliable proxy and always available.
      const chartItem = document.getElementById('ctx-chart');
      const hasChart = !!(f && (f.type === 'Beacon' || f.type === 'HTTP Beacon' || f.type === 'DNS Beacon' || f.type === 'Port-Hopping Beacon'));
      if (chartItem) chartItem.style.display = hasChart ? '' : 'none';

      // Campaign-only items: revealed when campaigns.js attached _campaign.
      const showCampaign = !!(f && f._campaign);
      document.querySelectorAll('.ctx-campaign-only').forEach(el => {
        el.style.display = showCampaign ? '' : 'none';
      });

      // Position the menu, then measure and clamp into the viewport.
      // The static 220×200 fallback under-counts the actual menu — items
      // are dynamically shown/hidden and the larger UI font has pushed
      // the rendered size past those numbers, so a click near the right
      // or bottom edge cut the menu off. Measuring after reveal lets us
      // place it correctly regardless of which items are visible.
      menu.style.left = '0px';
      menu.style.top  = '0px';
      menu.classList.remove('hidden');
      const margin = 8;
      const r = menu.getBoundingClientRect();

      // Decide whether the menu opens down-right, down-left, up-right,
      // or up-left of the click. The chosen corner anchors at the click.
      const openLeft = (e.clientX + r.width  > window.innerWidth  - margin);
      const openUp   = (e.clientY + r.height > window.innerHeight - margin);
      let left = openLeft ? Math.max(margin, e.clientX - r.width)  : e.clientX;
      let top  = openUp   ? Math.max(margin, e.clientY - r.height) : e.clientY;
      if (left < margin) left = margin;
      if (top  < margin) top  = margin;
      menu.style.left = left + 'px';
      menu.style.top  = top  + 'px';

      // Place the click-anchor arrow at whichever corner of the menu
      // sits closest to the click point, with a glyph pointing back
      // toward the click. ↖↗↙↘ correspond to top-left / top-right /
      // bottom-left / bottom-right respectively.
      if (arrow) {
        const corner = (openUp ? 'b' : 't') + (openLeft ? 'r' : 'l');
        const glyph  = { tl: '↖', tr: '↗', bl: '↙', br: '↘' }[corner];
        arrow.setAttribute('data-corner', corner);
        arrow.textContent = glyph;
      }
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
      // Scope the query to the column the analyst right-clicked: Pivot on a
      // Src cell writes `src:<ip>`, a Dst cell writes `dst:<ip>` — the "show
      // me every finding where this IP is the source / destination" intent.
      // Falls back to a bare term if the column is somehow unresolved (the
      // term then matches across src/dst). Clear first so this is the only
      // predicate.
      _resetFilterUI();
      const box = document.getElementById('filter-query');
      const token = _ctxTargetCol ? `${_ctxTargetCol}:${_ctxTarget}` : _ctxTarget;
      if (box) { box.value = token; _autoGrowQuery(); }
      // On an aggregate panel (Campaigns / Hosts / Dismissed-Campaigns)
      // a row is a synthesised roll-up, not a finding, so applying a
      // filter in place is a no-op the analyst can't see. The intent of
      // Pivot there is to switch to the Findings view AND carry the query
      // across. Invalidate first so the Findings view's cache doesn't
      // paint stale pre-filter rows before the new fetch lands.
      if (_isAggregateTab(_tabMode)) {
        _invalidateAllTabs();
        _activateView('findings');
        return;
      }
      applyFilter();
    });

    document.getElementById('ctx-show-contributing').addEventListener('click', () => {
      if (_ctxFinding) showContributingActivity(_ctxFinding);
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
    document.getElementById('ctx-dismiss').addEventListener('click', () => {
      if (!_ctxFinding) return;
      // Campaign rows carry _campaign with the aggregation; route to the
      // bulk path. Single-finding rows go through _toggleDismiss.
      if (_ctxFinding._campaign) _bulkDismissCampaign(_ctxFinding._campaign);
      else _toggleDismiss(_ctxFinding);
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
        _reloadFindingsInPlace();
      });
    });

    document.getElementById('ctx-pair-allow').addEventListener('click', () => {
      if (_ctxFinding) _openPairAllowAdd(_ctxFinding);
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
        _reloadFindingsInPlace();
      });
    });
    document.getElementById('ctx-ioc-add').addEventListener('click', () => {
      if (!_ctxTarget) return;
      _addToList('/api/ioc', 'IOC List', _ctxTarget, () => {
        _loadIOCList();
        _reloadFindingsInPlace();
      });
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
      // Censys migrated their analyst-facing UI from search.censys.io to
      // platform.censys.io in 2026. The /hosts/<ip> path is unchanged.
      if (_ctxTarget) _open(`https://platform.censys.io/hosts/${encodeURIComponent(_ctxTarget)}`);
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
      // Source from the aggregate cache when available — the active
      // findings tab may be paginated to a small slice (or empty if the
      // analyst opened Campaigns directly), and the graph needs every
      // finding belonging to this campaign to render the full host set.
      const pool = (_aggregateState.loaded && _aggregateState.findings.length > 0)
        ? _aggregateState.findings
        : _allFindings;
      const findings = pool.filter(f =>
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

  // ── Account menu + change/reset password ───────────────────────────────────
  // One dialog drives two flows. Self-service ('self') requires the
  // current password and posts to /api/me/password; admin reset
  // ('admin') sets another user's password via PATCH /api/users/{id}
  // and hides the current-password row.
  let _cpwMode = 'self';
  let _cpwTarget = null;

  function initAccountMenu() {
    const btn  = document.getElementById('user-menu-btn');
    const menu = document.getElementById('user-menu');
    if (!btn || !menu) return;
    const close = () => { menu.hidden = true; btn.setAttribute('aria-expanded', 'false'); };
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const opening = menu.hidden;
      menu.hidden = !opening;
      btn.setAttribute('aria-expanded', opening ? 'true' : 'false');
    });
    document.addEventListener('click', (e) => {
      if (!menu.hidden && !menu.contains(e.target) && e.target !== btn) close();
    });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
    document.getElementById('change-pw-menu-item').addEventListener('click', () => {
      close();
      _openChangePassword('self', _currentUser);
    });
    const dlg = document.getElementById('change-password-dialog');
    document.getElementById('cpw-cancel').addEventListener('click', () => dlg.close());
    document.getElementById('cpw-submit').addEventListener('click', _submitChangePassword);
  }

  function _openChangePassword(mode, user) {
    _cpwMode = mode;
    _cpwTarget = user || null;
    const dlg    = document.getElementById('change-password-dialog');
    const curRow = document.getElementById('cpw-current-row');
    const err    = document.getElementById('cpw-error');
    ['cpw-current','cpw-new','cpw-confirm'].forEach(id => { document.getElementById(id).value = ''; });
    err.style.display = 'none';
    if (mode === 'admin') {
      document.getElementById('cpw-title').textContent = `Reset password — ${user.email}`;
      curRow.style.display = 'none';
    } else {
      document.getElementById('cpw-title').textContent = 'Change Password';
      curRow.style.display = '';
    }
    dlg.showModal();
    document.getElementById(mode === 'admin' ? 'cpw-new' : 'cpw-current').focus();
  }

  async function _submitChangePassword() {
    const dlg  = document.getElementById('change-password-dialog');
    const err  = document.getElementById('cpw-error');
    const cur  = document.getElementById('cpw-current').value;
    const npw  = document.getElementById('cpw-new').value;
    const conf = document.getElementById('cpw-confirm').value;
    const fail = (m) => { err.textContent = m; err.style.display = 'block'; };
    err.style.display = 'none';
    if (npw.length < 8) { fail('New password must be at least 8 characters.'); return; }
    if (npw !== conf)   { fail('Passwords do not match.'); return; }
    try {
      if (_cpwMode === 'admin') {
        await api(`/api/users/${_cpwTarget.id}`, {
          method: 'PATCH',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({password: npw}),
        });
        dlg.close();
        setStatus(`Password reset for ${_cpwTarget.email}`);
        _loadUsers();
      } else {
        await api('/api/me/password', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({current_password: cur, new_password: npw, confirm: conf}),
        });
        dlg.close();
        setStatus('Password changed.');
      }
    } catch (e) {
      fail(e || 'Failed to change password.');
    }
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
        if (!isSelf) actions.push(`<button class="user-resetpw-btn" data-uid="${u.id}">Reset PW</button>`);
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
          <td style="font-size:11px;color:var(--fg-dim);font-family:ui-monospace,'SF Mono',Menlo,Monaco,Consolas,monospace">${_esc((u.created_at||'').slice(0, 16))}</td>
          <td style="white-space:nowrap;text-align:right">${actions.join(' ')}</td>`;
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

      // Reset-password handlers (admin reset of another user)
      tbody.querySelectorAll('.user-resetpw-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const uid = parseInt(btn.dataset.uid);
          const u = users.find(x => x.id === uid);
          if (u) _openChangePassword('admin', u);
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

  // Canonical strong-_esc — handles &, <, >, ", '. Every module that
  // interpolates server-supplied strings into innerHTML uses the same
  // shape (see notifications.js, campaigns.js, feeds.js, sensors.js,
  // table.js, detail.js). The codebase convention is one _esc per
  // IIFE-scoped module rather than a shared helper, but every copy
  // MUST escape all five characters — the SPA consistency test
  // (Go-side, server/web_esc_consistency_test.go) walks the JS
  // sources and fails if any copy diverges. Pre-NEW-30 there were
  // three distinct shapes (strong, near-strong, weak) and the comment
  // claiming "convention" was aspirational rather than descriptive.
  // Audit 2026-05-10 NEW-30.
  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
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
      // Row select: render the projected row immediately so the detail
      // pane responds without a roundtrip, then upgrade to the full
      // finding (which carries ts_data / intervals / notes that the
      // list projection strips). The chart and notes affordances only
      // light up after the upgrade lands. Auto-expand the dock when
      // collapsed — clicking a row is an explicit ask for detail, so
      // keeping the dock collapsed would defeat the operator intent.
      f => {
        _selectedFinding = f;
        _pivotCtx = null; // a direct row click leaves any pivot context
        if (_isDockCollapsed()) _setDockCollapsed(false, false);
        Detail.render(f);
        if (!f || !f.id) return;
        fetchFinding(f.id).then(full => {
          if (!_selectedFinding || _selectedFinding.id !== full.id) return;
          _selectedFinding = full;
          Detail.render(full);
        }).catch(() => {});
      },
      (e, f) => showMenu(e, f)
    );

    // Hosts-row click opens the host-pivot view: HRS roll-up at top,
    // followed by a contact-set table of every network finding for this
    // host sorted score-desc. Clicking a contact-set row drills into
    // that finding's full detail.
    const onHostClick = ip => {
      const pool = (_aggregateState.loaded && _aggregateState.findings.length > 0)
        ? _aggregateState.findings : _allFindings;
      const hrs = pool.find(x => _isHostFinding(x) && x.src_ip === ip);
      const contactFindings = pool
        .filter(x => x.src_ip === ip && !_isHostFinding(x) && x.type !== 'Correlated Activity')
        .sort((a, b) => b.score - a.score);
      _selectedFinding = hrs || null;
      _pivotCtx = {type: 'host', label: ip, hrs: hrs || null, findings: contactFindings};
      if (_isDockCollapsed()) _setDockCollapsed(false, false);
      Detail.renderHostPivot(ip, hrs, contactFindings, f => {
        _selectedFinding = f;
        _pivotCtx = null;
        if (_isDockCollapsed()) _setDockCollapsed(false, false);
        Detail.render(f);
      });
    };
    const onCampaignClick = (dst, port) => {
      const pool = (_aggregateState.loaded && _aggregateState.findings.length > 0)
        ? _aggregateState.findings : _allFindings;
      const campaignFindings = pool
        .filter(x => x.dst_ip === dst && (x.dst_port || '') === (port || '') && !_isHostFinding(x))
        .sort((a, b) => b.score - a.score);
      _selectedFinding = null;
      _pivotCtx = {type: 'campaign', label: port ? `${dst}:${port}` : dst, findings: campaignFindings};
      if (_isDockCollapsed()) _setDockCollapsed(false, false);
      Detail.renderCampaignPivot(dst, port, campaignFindings, f => {
        _selectedFinding = f;
        _pivotCtx = null;
        if (_isDockCollapsed()) _setDockCollapsed(false, false);
        Detail.render(f);
      });
    };
    Campaigns.init((e, pseudo) => showMenu(e, pseudo), _isOrgIP, onHostClick, onCampaignClick);

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

    Notifications.init(async notif => {
      // Dispatch by notification kind. Sensor and feed alarms open
      // their respective modals; finding alarms run the existing
      // jump-to-row logic. Empty kind reads as "finding" for
      // backward compat with notifications persisted before the
      // kind field existed.
      const kind = notif.kind || 'finding';
      if (kind === 'sensor') {
        if (typeof Sensors !== 'undefined' && Sensors.open) Sensors.open();
        return;
      }
      if (kind === 'feed') {
        if (typeof Feeds !== 'undefined' && Feeds.open) Feeds.open();
        return;
      }
      const findingId = notif.finding_id;
      // The finding may be filtered out of _allFindings or live on a
      // different page than the one currently loaded. Fetch it directly
      // so we always know its status (and therefore which tab to land
      // on) regardless of the active view state.
      let target = _allFindings.find(x => x.id === findingId);
      if (!target) {
        try {
          const r = await fetch('/api/findings/' + findingId);
          if (r.ok) target = await r.json();
        } catch (_) {}
      }
      if (!target) {
        setStatus('Finding no longer available');
        return;
      }

      // Clear the query and delta mode. Operator intent: "regardless of
      // other filtering or pagination, jump to that finding." The query
      // box held every predicate _currentFilterParams can emit, so
      // clearing it neutralises all of them — missing one would make the
      // position query 404 and the jump silently fall back to the "hidden
      // from table view" path instead of scrolling+highlighting. The
      // active view is then chosen by the finding's status.
      _resetFilterUI();
      _deltaMode = false;
      const showAllBtn = document.getElementById('show-all-btn');
      const deltaBtn   = document.getElementById('delta-btn');
      if (showAllBtn) showAllBtn.classList.add('active');
      if (deltaBtn)   deltaBtn.classList.remove('active');

      // Switch tab manually instead of dispatching a click — the click
      // handler kicks off its own loadFindings(offset=0) which would
      // race the position-aware load below. Doing it inline keeps to a
      // single fetch.
      let targetTab = 'findings';
      if (target.status === 'acknowledged') targetTab = 'ack';
      else if (target.status === 'escalated') targetTab = 'esc';
      else if (target.status === 'dismissed') {
        targetTab = 'dismissed';
        // If the analyst's Show Dismissed toggle is off, force it on
        // so the jump lands somewhere visible. localStorage is
        // updated so the choice persists past this jump.
        if (!_showDismissed) {
          try { localStorage.setItem('archer:show-dismissed', 'true'); } catch (_) {}
          _applyShowDismissed(true);
        }
      }
      _setViewActive(targetTab);
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      const findingsPanel = document.getElementById('tab-findings');
      if (findingsPanel) findingsPanel.classList.add('active');
      _tabMode = targetTab;
      // The jump always lands on a single finding, so route Dismissed
      // to the Findings sub-tab regardless of last-used preference —
      // Campaigns sub-view doesn't have a row to jump to.
      if (targetTab === 'dismissed') _setDismissedSubTab('findings');
      _invalidateAllTabs();
      _loadCounts();
      _loadFacets();

      // Look up the absolute position under the now-cleared filter,
      // then fetch the page that contains it. `positionFound` lets us
      // tell "row exists in the filtered listing" from "row is hidden
      // by allowlist/suppression" — the single-finding fetch above
      // bypasses filterFindings, but every list endpoint runs through
      // it, so a finding whose src/dst is now allowlisted or
      // suppressed has Details we can render but no row to jump to.
      const params = _currentFilterParams();
      let pageOffset = 0;
      let positionFound = true;
      try {
        const qs = new URLSearchParams(params).toString();
        const posRes = await fetch(`/api/findings/${findingId}/position` + (qs ? '?' + qs : ''));
        if (posRes.ok) {
          const pos = await posRes.json();
          if (pos.found) pageOffset = Math.floor(pos.offset / _pageSize) * _pageSize;
          else positionFound = false;
        } else if (posRes.status === 404) {
          positionFound = false;
        }
      } catch (_) { /* fall through with offset=0 */ }

      try {
        await loadFindings(params, { gotoOffset: pageOffset });
      } catch (e) {
        setStatus('Jump load failed: ' + e);
      }
      _selectedFinding = target;
      Detail.render(target);
      if (positionFound) {
        Table.jumpTo(findingId);
      } else {
        // The notification's row is filtered out of every listing
        // (typical cause: src or dst was added to the allowlist or
        // suppression list after the bell rang). The Details are
        // rendered in the dock from the direct fetch, so the analyst
        // can still inspect and take action via the footer buttons —
        // but the table has no row to scroll to. Surface that
        // explicitly so the click isn't a mysterious no-op.
        setStatus('Finding is hidden from table view (allowlisted, suppressed, or filter mismatch). Details rendered in dock.');
      }
    });

    // Fetch current user for display, note authorship, and role-gating
    api('/api/me').then(u => {
      _currentUser = u;
      const el = document.getElementById('user-display');
      if (el) el.textContent = u.display || u.email || '';
      if (u.role === 'admin') {
        document.getElementById('users-btn').style.display = '';
        document.getElementById('audit-btn').style.display = '';
        // Admins get the Watch Mode settings modal: reveal the chip button
        // (and hide the plain title). Non-admins see the read-only status
        // only — the plain label stays and the modal is never reachable
        // (POST is also admin-gated server-side).
        const wt   = document.getElementById('watch-mode-title');
        const wl   = document.getElementById('watch-mode-label');
        const wrow = document.getElementById('watch-mode-btn-row');
        const wdlg = document.getElementById('watch-dlg');
        if (wt && wdlg) {
          if (wl) wl.style.display = 'none';
          if (wrow) wrow.style.display = '';
          wt.addEventListener('click', () => wdlg.showModal());
        }
        _refreshPendingBadge();
        if (typeof AuditLog !== 'undefined') AuditLog.init();
      }
      // Sensors menu is visible to admin + analyst; only admins get the
      // enroll/disenroll/purge buttons (Sensors.init takes the gate).
      if (u.role === 'admin' || u.role === 'analyst') {
        Sensors.init(u.role === 'admin');
      }
      // Feeds menu mirrors Sensors: admin + analyst can read; admin
      // gets the add/edit/delete actions. Feed fetching itself is
      // automatic — runs at watch full-pass cadence, not on demand.
      if (typeof Feeds !== 'undefined' && (u.role === 'admin' || u.role === 'analyst')) {
        Feeds.init(u.role === 'admin');
      }
      // TLS Fingerprints modal — read-only hunt surface for every role.
      // The pivot reuses pivotByTLS via an injected callback; JA4 takes
      // precedence over JA3 the same way the per-finding TLS Pivot does.
      if (typeof Fingerprints !== 'undefined' && Fingerprints.init) {
        Fingerprints.init({
          onPivot: (kind, fp) => pivotByTLS(kind === 'ja4' ? { ja4: fp } : { ja3: fp }),
          onToast: (msg) => showToast(msg, 4000),
          onChange: _reloadFindingsInPlace,
          canWrite: u.role !== 'viewer',
        });
      }
      // ATT&CK Coverage modal — clicking a technique replaces the whole query
      // with just attack:<id> (a focused pivot, not an upsert onto the current
      // query) and lands on the Findings view.
      if (typeof Attack !== 'undefined' && Attack.init) {
        Attack.init({
          onPivot: (id) => { _setFullQuery('attack:' + id); _switchToFindingsView(); applyFilter(); },
        });
      }
      // Per-fingerprint Benign / Malicious actions in the finding detail pane,
      // so an analyst can triage a JA3/JA4 straight from a finding — including
      // a low-concern fingerprint the TLS wall hides. Same endpoints the wall
      // uses, so a benign mark yields the same `fp benign` chip on next refresh.
      if (typeof Detail !== 'undefined' && Detail.init) {
        Detail.init({
          canWrite: u.role !== 'viewer',
          onMarkBenign: (kind, fp) => {
            api('/api/fingerprint-allowlist', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ kind, fingerprint: fp, note: '' }),
            })
              .then(() => {
                showToast('Marked benign — findings carrying this fingerprint now show the “fp benign” chip', 4500);
                _reloadFindingsInPlace();
              })
              .catch(err => showToast('Could not mark benign: ' + err, 4500));
          },
          onMarkMalicious: (kind, fp) => {
            api('/api/ioc-fingerprint', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ fingerprint: fp }),
            })
              .then(() => showToast('Added to IOC list — flags as Malicious JA3/JA4 on the next analysis', 4500))
              .catch(err => showToast('Could not mark malicious: ' + err, 4500));
          },
        });
      }
      // Hide write-only controls for viewers
      if (u.role === 'viewer') {
        ['analyze-btn','allowlist-btn','ioc-btn','suppressions-btn',
         'ack-btn','esc-btn','supp-btn','add-note-btn'].forEach(id => {
          const el = document.getElementById(id);
          if (el) el.style.display = 'none';
        });
      }
      // Settings is open to all roles, but non-admins see only the Appearance
      // tab — theme is a per-browser preference, the rest of Settings is admin
      // config. Hide the admin config tabs and the Save button (the appearance
      // picker applies instantly via localStorage, no save), and relabel
      // Cancel to Close since there's nothing to cancel.
      if (u.role !== 'admin') {
        ['detection', 'ti', 'ops', 'admin'].forEach(t => {
          const btn = document.querySelector('#settings-tabs .dlg-tab-btn[data-settab="' + t + '"]');
          if (btn) btn.style.display = 'none';
        });
        const saveBtn = document.getElementById('settings-save');
        if (saveBtn) saveBtn.style.display = 'none';
        const cancelBtn = document.getElementById('settings-cancel');
        if (cancelBtn) cancelBtn.textContent = 'Close';
      }
    }).catch(() => {});

    initUserManagement();
    initAccountMenu();

    BeaconChart.init();
    _initExportDropdown('chart-export-btn', 'chart-export-menu', BeaconChart.exportImage);
    initViews();
    _initShowDismissedToggle();
    _initDismissedSubTabs();
    _initDockTabs();
    _initDockCollapse();
    _initDockResize();
    _initDockKeyboardShortcuts();
    if (typeof BeaconEvolution !== 'undefined' && BeaconEvolution.init) {
      BeaconEvolution.init();
      _initExportDropdown('beacon-evolution-export-btn', 'beacon-evolution-export-menu', BeaconEvolution.exportImage);
    }
    initFilterBar();
    initDeltaBar();
    initLogsPanel();
    initAnalyze();
    initDetailActions();
    initSuppressDialog();
    initSuppressionsManager();
    initPairAllowlist();
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
    _loadVersion();  // fill statusbar version pill + About dialog from /api/version
    _initAboutDialog();

    // Disk-usage telemetry — poll every 5 minutes so the warning banner can
    // surface without the user having to open Settings. The endpoint itself
    // caches identically, so this is essentially free after the first call.
    _refreshDiskUsage();
    setInterval(_refreshDiskUsage, 5 * 60 * 1000);
    loadFindings(_currentFilterParams())
      .then(() => _updateTIStatus())
      .catch(() => setStatus('Ready — click Import then Analyze'));
    _loadCounts();
    _loadFacets();
    // Login-time new-findings prompt: show what's accumulated since this
    // analyst last acknowledged, across every watch pass since — not just
    // the most recent run. Silent when nothing is new to them.
    _showUnseenModal();
    setStatus('Ready');
  }

  async function _loadOrgCIDRs() {
    try {
      const cfg = await api('/api/config');
      _orgCIDRs = Array.isArray(cfg.org_internal_cidrs) ? cfg.org_internal_cidrs : [];
    } catch (_) { /* keep current list on failure */ }
  }

  // Pulls /api/version once on init and writes the result to the statusbar
  // pill plus the About dialog's hidden fields. The endpoint is
  // unauthenticated so this works even on the login screen, but we only
  // ever call it from init() after the user is in.
  async function _loadVersion() {
    try {
      const r = await fetch('/api/version', { cache: 'no-store' });
      if (!r.ok) return;
      const v = await r.json();
      _archerVersion = {
        version:    v.version    || _archerVersion.version,
        commit:     v.commit     || 'unknown',
        build_time: v.build_time || 'unknown',
      };
      const pill = document.getElementById('version-pill');
      if (pill) pill.textContent = _archerVersion.version;
      const av = document.getElementById('about-version');    if (av) av.textContent = _archerVersion.version;
      const ac = document.getElementById('about-commit');     if (ac) ac.textContent = _archerVersion.commit;
      const ab = document.getElementById('about-build-time'); if (ab) ab.textContent = _archerVersion.build_time;
    } catch (_) { /* keep defaults on failure */ }
  }

  function _initAboutDialog() {
    const pill   = document.getElementById('version-pill');
    const dlg    = document.getElementById('about-dialog');
    const close  = document.getElementById('about-close');
    if (!pill || !dlg) return;
    pill.addEventListener('click', () => { try { dlg.showModal(); } catch (_) { dlg.setAttribute('open',''); } });
    if (close) close.addEventListener('click', () => dlg.close());
  }

  init();
})();
