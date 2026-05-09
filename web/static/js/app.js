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
    findings: _newTabState(),
    ack:      _newTabState(),
    esc:      _newTabState(),
    ioc:      _newTabState(),
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

  // Aggregate cache: every finding within the current time range, no
  // status / ioc_only filter. Powers Campaigns and Hosts views — those
  // are roll-ups, so they need the full set to be accurate. Loaded
  // lazily when either tab is first visited; invalidated alongside
  // _tabState on every filter change.
  let _aggregateState = { findings: [], loaded: false };
  // Per-tab render-pagination state for the aggregate tabs. offset is the
  // 0-based start index of the current page in the full _campaigns /
  // _hosts arrays; total is the full aggregated row count. Independent
  // per tab so paging on Campaigns doesn't affect Hosts.
  const _aggTabState = {
    campaigns: { offset: 0, total: 0 },
    hosts:     { offset: 0, total: 0 },
  };
  function _invalidateAggregate() {
    _aggregateState = { findings: [], loaded: false };
    _aggTabState.campaigns = { offset: 0, total: 0 };
    _aggTabState.hosts     = { offset: 0, total: 0 };
  }
  let _countsLoaded = false;

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
  const _findingsTabs = new Set(['findings', 'ack', 'esc', 'ioc']);
  const _aggregateTabs = new Set(['campaigns', 'hosts']);
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
      const e = await r.json().catch(() => ({}));
      throw (e.error || r.statusText);
    }
    const page = await r.json();
    ts.total   = parseInt(r.headers.get('X-Total-Count') || '0', 10) || 0;
    ts.findings = Array.isArray(page) ? page : [];
    ts.loaded = true;

    _allFindings = ts.findings;
    _renderCurrentTab();
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
    if (!_aggregateState.loaded) {
      const params = _currentFilterParams();
      delete params.status;
      delete params.ioc_only;
      delete params.delta;
      params.limit = String(_FULL_FETCH_LIMIT);
      params.offset = '0';
      const qs = new URLSearchParams(params).toString();
      try {
        const r = await fetch('/api/findings' + (qs ? '?' + qs : ''));
        if (!r.ok) return;
        const all = await r.json();
        _aggregateState.findings = Array.isArray(all) ? all : [];
        _aggregateState.loaded = true;
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
    if (_tabMode === 'campaigns') {
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
    const params = _currentFilterParams();
    delete params.status;
    delete params.ioc_only;
    delete params.delta;
    delete params.type;
    delete params.sensor;
    delete params.limit;
    delete params.offset;
    const qs = new URLSearchParams(params).toString();
    try {
      const r = await fetch('/api/findings/facets' + (qs ? '?' + qs : ''));
      if (!r.ok) return;
      const data = await r.json();
      _populateTypeDropdown(Array.isArray(data.types) ? data.types : []);
      _populateSensorDropdown(Array.isArray(data.sensors) ? data.sensors : []);
    } catch (e) { /* swallow — stale dropdown is acceptable */ }
  }

  function _populateTypeDropdown(types) {
    const sel = document.getElementById('filter-type');
    if (!sel) return;
    const cur = sel.value;
    sel.innerHTML = '<option value="">All Types</option>';
    types.forEach(t => {
      // Host Risk Score is a per-host roll-up surfaced through the
      // Hosts tab — not a network event the Findings filter should
      // expose as a discrete option.
      if (HOST_FINDING_TYPES.has(t)) return;
      const opt = document.createElement('option');
      opt.value = t; opt.textContent = t;
      if (t === cur) opt.selected = true;
      sel.appendChild(opt);
    });
  }

  function _populateSensorDropdown(sensors) {
    const sel = document.getElementById('filter-sensor');
    if (!sel) return;
    const cur = sel.value;
    while (sel.options.length > 1) sel.remove(1);
    sensors.forEach(s => {
      const opt = document.createElement('option');
      opt.value = s; opt.textContent = s;
      if (s === cur) opt.selected = true;
      sel.appendChild(opt);
    });
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
      if (!r.ok) return;
      const c = await r.json();
      _tabState.findings.total = c.open || 0;
      _tabState.ack.total      = c.ack  || 0;
      _tabState.esc.total      = c.esc  || 0;
      _tabState.ioc.total      = c.ioc  || 0;
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
      const a = _aggTabState[_tabMode];
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
      const a = _aggTabState[_tabMode];
      return a.total === 0 ? 1 : Math.floor(a.offset / _pageSize) + 1;
    }
    const ts = _curTab();
    return ts.total === 0 ? 1 : Math.floor(ts.offset / _pageSize) + 1;
  }
  function _totalPagesForActiveTab() {
    if (_isAggregateTab(_tabMode)) {
      return Math.max(1, Math.ceil(_aggTabState[_tabMode].total / _pageSize));
    }
    const ts = _curTab();
    return Math.max(1, Math.ceil(ts.total / _pageSize));
  }

  // _gotoPage navigates the active tab to a specific 1-based page.
  // Findings tabs trigger a server-side fetch; aggregate tabs re-render
  // the cached slice. Out-of-range pages clamp to the valid window.
  async function _gotoPage(page) {
    if (_isAggregateTab(_tabMode)) {
      const a = _aggTabState[_tabMode];
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
    document.getElementById('info-line').textContent = parts.join('  •  ');

    // findings-count reflects the active tab — what's currently rendered.
    const cur = _curTab();
    document.getElementById('findings-count').textContent =
      cur.loaded ? `${cur.total.toLocaleString()} total` : '';
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
          // All four share #tab-findings panel; just change the cache slot.
          // Cached tabs render instantly; first-visit tabs fetch their
          // own page with the right server-side filter.
          document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
          document.getElementById('tab-findings').classList.add('active');
          _tabMode = tab;
          _showCurrentTab();
        } else {
          document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
          const panel = document.getElementById('tab-' + tab);
          if (panel) panel.classList.add('active');
          // Campaigns / Hosts are roll-ups — they need every finding in
          // the time range, not whatever's loaded for the current
          // findings tab. Lazy-fetch the aggregate cache on first visit.
          // Setting _tabMode here lets the pagination footer pick the
          // right per-tab Load More state.
          if (tab === 'campaigns' || tab === 'hosts') {
            _tabMode = tab;
            _ensureAggregate();
          }
        }
      });
    });
  }

  // ── Filter bar ─────────────────────────────────────────────────────────────
  function initFilterBar() {
    // Time-range preset dropdown. Independent of the From/To inputs in
    // the Advanced bar — selecting a preset applies it immediately and
    // doesn't touch any other filter field. Power users wanting a
    // specific date window open Advanced and set From/To, which
    // override the preset when present.
    const rangeSel = document.getElementById('filter-range');
    if (rangeSel) {
      rangeSel.addEventListener('change', () => {
        _invalidateAllTabs();
        applyFilter();
      });
    }

    document.getElementById('apply-filter-btn').addEventListener('click', applyFilter);
    document.getElementById('reset-filter-btn').addEventListener('click', () => {
      ['filter-search','filter-src','filter-dst','filter-port'].forEach(id => {
        const el = document.getElementById(id); if (el) el.value = '';
      });
      document.getElementById('filter-sev').value = '';
      document.getElementById('filter-type').value = '';
      document.getElementById('filter-sensor').value = '';
      document.getElementById('filter-score').value = '0';
      const rs = document.getElementById('filter-range');
      if (rs) rs.value = '1mo';
      // Reset goes through the same path as applyFilter so the active
      // tab refetches and the info-line counts repopulate (instead of
      // sticking on the dashes left by _invalidateAllTabs).
      applyFilter();
    });
    ['filter-search','filter-src','filter-dst','filter-port'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('keydown', e => { if (e.key === 'Enter') applyFilter(); });
    });

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

  // _rangeFromDate translates a preset key (1d/7d/1mo/3mo/6mo/all) into
  // an ISO datetime string for the matching window's start, or '' for
  // "all time". The dropdown is independent of the From/To inputs in
  // the Advanced bar — those override the preset when set, but the
  // dropdown does NOT write to them. Selecting a preset applies
  // immediately without touching anything else in the filter bar.
  function _rangeFromDate(key) {
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
    return new Date(Date.now() - off).toISOString().slice(0, 16);
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
    // Date filter comes from the Time-range dropdown only. Custom
    // From/To inputs were removed from the Advanced bar — the dropdown
    // covers every common hunt window and the perf cost of a date
    // walking heuristic on each fetch isn't worth a power-user knob.
    const rangeKey = g('filter-range');
    const computed = _rangeFromDate(rangeKey);
    if (computed) params.from = computed;

    // Tab-aware status filter, mirrored server-side. Without this, the
    // Findings tab fetches every status (including acknowledged and
    // escalated) and filters client-side via _applyTabFilter — fine for
    // a thousand findings, painful for hundreds of thousands.
    if (_tabMode === 'ack')      params.status = 'acknowledged';
    else if (_tabMode === 'esc') params.status = 'escalated';
    else if (_tabMode === 'ioc') params.ioc_only = 'true';
    else                         params.status = 'open';
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

  function applyFilter() {
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
      const btn = document.getElementById('analyze-btn');
      if (btn) btn.disabled = sensors.length === 0;

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
      const btn = document.getElementById('analyze-btn');
      if (btn) btn.disabled = true;
    }
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

  function _setAnalyzing(active) {
    const btn = document.getElementById('analyze-btn');
    if (btn) btn.disabled = active;
    document.getElementById('analysis-controls').style.display = active ? 'flex' : 'none';
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
          setStatus('Analysis already running');
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
        loadFindings(_currentFilterParams());
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
          loadFindings(_currentFilterParams());
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
      loadFindings(_currentFilterParams());
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
    const alwaysFull = document.getElementById('cfg-watch-always-full');
    if (alwaysFull) alwaysFull.checked = !!cfg.watch_always_full;
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
      watch_always_full:        !!(document.getElementById('cfg-watch-always-full') || {}).checked,
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
      document.querySelectorAll('.ctx-write').forEach(el => {
        if (isViewer || onAggregateTab) el.style.display = 'none';
        else if (!el.classList.contains('ctx-target-aware') || showColAware) el.style.display = '';
      });
      document.querySelectorAll('.ctx-write-sep').forEach(el => {
        el.style.display = (isViewer || onAggregateTab) ? 'none' : '';
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

      // Beacon Chart only matters for findings carrying timeseries data —
      // the analyzer attaches TSData to "Beaconing" and "HTTP Beaconing"
      // findings only. The list-response projection strips ts_data
      // (see handlers_api.go's listFinding), so we can't gate on its
      // presence here; type is a reliable proxy and always available.
      const chartItem = document.getElementById('ctx-chart');
      const hasChart = !!(f && (f.type === 'Beaconing' || f.type === 'HTTP Beaconing'));
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
        loadFindings(_currentFilterParams());
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
        loadFindings(_currentFilterParams());
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
      // Row select: render the projected row immediately so the detail
      // pane responds without a roundtrip, then upgrade to the full
      // finding (which carries ts_data / intervals / notes that the
      // list projection strips). The chart and notes affordances only
      // light up after the upgrade lands.
      f => {
        _selectedFinding = f;
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

    // Hosts-row click lifts the per-host roll-up's Host Risk Score finding
    // out of _allFindings (it's filtered out of the Findings tab) and
    // renders its detail breakdown. Without this hook the Hosts tab would
    // stop at "host has score 99" with no way to see why.
    const onHostClick = ip => {
      const f = _allFindings.find(x => _isHostFinding(x) && x.src_ip === ip);
      if (f) {
        _selectedFinding = f;
        Detail.render(f);
      }
    };
    Campaigns.init((e, pseudo) => showMenu(e, pseudo), _isOrgIP, onHostClick);

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
      // Feeds menu mirrors Sensors: admin + analyst can read; admin
      // gets the add/edit/delete actions. Feed fetching itself is
      // automatic — runs at watch full-pass cadence, not on demand.
      if (typeof Feeds !== 'undefined' && (u.role === 'admin' || u.role === 'analyst')) {
        Feeds.init(u.role === 'admin');
      }
      // Hide write-only controls for viewers
      if (u.role === 'viewer') {
        ['analyze-btn','allowlist-btn','ioc-btn','suppressions-btn',
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
    _initExportDropdown('chart-export-btn', 'chart-export-menu', BeaconChart.exportImage);
    initTabs();
    initFilterBar();
    initDeltaBar();
    initLogsPanel();
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
