// detail.js — detail pane renderer
'use strict';

const Detail = (() => {
  const EXPLANATIONS = window.SCORE_EXPLANATIONS || {};

  function _sevColor(sev) {
    return {CRITICAL:'var(--sev-critical)', HIGH:'var(--sev-high)', MEDIUM:'var(--sev-medium)',
            LOW:'var(--sev-low)', INFO:'var(--sev-info)', IOC_HIT:'var(--ioc-color)'}[sev] || 'var(--fg-text)';
  }

  function _statusLabel(s) {
    if (s === 'acknowledged') return 'ACKNOWLEDGED';
    if (s === 'escalated')    return 'ESCALATED';
    if (s === 'dismissed')    return 'DISMISSED';
    return 'OPEN';
  }

  // _fmtDur renders a seconds value in human units for the triage
  // header — "47s", "5m 2s", "1h 03m". Sub-second cadences (rare, but
  // a tight loop or a parser artifact can produce one) keep one
  // decimal so they don't collapse to "0s".
  function _fmtDur(sec) {
    if (!isFinite(sec) || sec <= 0) return '0s';
    if (sec < 1)   return sec.toFixed(1) + 's';
    if (sec < 90)  return Math.round(sec) + 's';
    if (sec < 3600) {
      const m = Math.floor(sec / 60), s = Math.round(sec % 60);
      return s ? `${m}m ${s}s` : `${m}m`;
    }
    const h = Math.floor(sec / 3600), m = Math.round((sec % 3600) / 60);
    return m ? `${h}h ${String(m).padStart(2, '0')}m` : `${h}h`;
  }

  // _beaconTriage builds the structured triage header for Beaconing /
  // HTTP Beaconing findings from the additive fields the analyzer now
  // persists (migration 0018). Returns [] for non-beacon findings or
  // when sample_size is zero — a pre-0018 historical beacon row reads
  // back zeroed, so it cleanly falls back to the raw Detail string with
  // no broken header. stddev is reconstructed mean × jitter (jitter is
  // the interval CV); that's the "± Ns" spread an analyst reads first.
  function _beaconTriage(f) {
    const isBeacon = f.type === 'Beaconing' || f.type === 'HTTP Beaconing';
    if (!isBeacon || !(f.sample_size > 0)) return [];
    const mean = f.mean_interval || 0;
    const cv   = f.jitter || 0;
    const std  = mean * cv;
    const out = [];
    out.push('Beacon triage');
    out.push(`Cadence    : every ${_fmtDur(mean)} ± ${_fmtDur(std)}   (median ${_fmtDur(f.median_interval || 0)})`);
    out.push(`Jitter     : ${(cv * 100).toFixed(1)}%`);
    out.push(`Samples    : n=${f.sample_size}`);
    out.push(`Sub-scores : Timing ${(f.ts_score || 0).toFixed(2)}   Data size ${(f.ds_score || 0).toFixed(2)}   Histogram ${(f.hist_score || 0).toFixed(2)}   Persistence ${(f.dur_score || 0).toFixed(2)}`);
    out.push('');
    return out;
  }

  // _row returns a key/value row HTML string.
  function _row(key, val, mono) {
    return `<div class="ds-row"><span class="ds-key">${_esc(key)}</span><span class="ds-val${mono ? ' mono' : ''}">${val}</span></div>`;
  }

  // _section wraps rows in a labelled section div.
  function _section(title, rowsHtml) {
    const titleHtml = title ? `<div class="ds-section-title">${_esc(title)}</div>` : '';
    return `<div class="ds-section">${titleHtml}${rowsHtml}</div>`;
  }

  // _parseDetail splits the analyzer's pipe-delimited detail string
  // into individual rows. Each segment is trimmed; empty ones dropped.
  function _parseDetail(detail) {
    if (!detail) return '';
    return detail.split('|').map(s => s.trim()).filter(Boolean).map(seg => {
      const colon = seg.indexOf(':');
      // Only treat text before the colon as a key label when it is short
      // enough to fit the key column without overflowing. Segments where
      // the label portion is a long phrase (e.g. "Contributing finding IDs",
      // "URLhaus malware distribution host") render full-width instead.
      if (colon > 0 && colon <= 28) {
        const k = seg.slice(0, colon).trim();
        const v = seg.slice(colon + 1).trim();
        return _row(k, _esc(v), true);
      }
      return `<div class="ds-row"><span class="ds-val mono">${_esc(seg)}</span></div>`;
    }).join('');
  }

  function render(f) {
    const header = document.getElementById('detail-header');
    const text   = document.getElementById('detail-text');
    const rec    = document.getElementById('analyst-rec');

    const dst    = f.dst_ip || '—';
    const sensor = f.sensor || '';
    header.textContent = `${f.type}  [${f.severity}  score ${f.score}]  ${f.src_ip || '—'} → ${dst}${f.dst_port ? ':' + f.dst_port : ''}`;
    header.style.color = _sevColor(f.severity);

    const sections = [];

    // --- Identity ---
    let id = '';
    id += _row('Type',      _esc(f.type));
    id += _row('Severity',  `${_esc(f.severity)}<span style="color:var(--fg-dim)">  score </span>${_esc(String(f.score))}`, false);
    id += _row('Status',    _esc(_statusLabel(f.status)));
    if (sensor)           id += _row('Sensor',    _esc(sensor));
    id += _row('Timestamp', _esc(f.timestamp || '—'));
    id += _row('Source',    _esc(f.source_file || '—'));
    sections.push(_section('', id));

    // --- Endpoints ---
    let ep = '';
    if (f.src_ip)   ep += _row('Src IP',   _esc(f.src_ip),   true);
    if (f.dst_ip)   ep += _row('Dst IP',   _esc(f.dst_ip),   true);
    if (f.dst_port) ep += _row('Dst Port', _esc(f.dst_port), true);
    if (f.ja3) {
      ep += _row('JA3', _esc(f.ja3), true);
      const n = f.ja3_sibling_count || 0;
      ep += _row('JA3 match', `${n} other beacon${n === 1 ? '' : 's'} in dataset${n > 0 ? '  <span style="color:var(--fg-dim)">(JA3 Pivot ▸)</span>' : ''}`);
    }
    if (f.ja4) ep += _row('JA4', _esc(f.ja4), true);
    if (Array.isArray(f.top_uris) && f.top_uris.length > 1) {
      ep += `<div class="ds-row"><span class="ds-key">Beacon paths</span><span class="ds-val mono">${_esc(f.hostname || 'this host')}</span></div>`;
      f.top_uris.forEach(u => {
        ep += `<div class="ds-row"><span class="ds-key"></span><span class="ds-val mono">${_esc(u.uri)}  <span style="color:var(--fg-dim)">(n=${_esc(String(u.count))})</span></span></div>`;
      });
    }
    if (ep) sections.push(_section('Endpoints', ep));

    // --- Beacon triage ---
    const triage = _beaconTriage(f);
    if (triage.length > 0) {
      let tr = '';
      // triage[0] is the section label, skip it; remaining are "Key : value" lines
      for (let i = 1; i < triage.length; i++) {
        const line = triage[i];
        if (!line) continue;
        const colon = line.indexOf(':');
        if (colon > 0) {
          tr += _row(line.slice(0, colon).trim(), _esc(line.slice(colon + 1).trim()));
        } else {
          tr += `<div class="ds-row"><span class="ds-val">${_esc(line)}</span></div>`;
        }
      }
      sections.push(_section('Beacon triage', tr));
    }

    // --- Detection detail ---
    const detailHtml = _parseDetail(f.detail);
    if (detailHtml) sections.push(_section('Detection detail', detailHtml));

    // --- Flags ---
    let flags = '';
    if (f.is_new)    flags += `<span class="ds-flag new">NEW SINCE BASELINE</span> `;
    if (f.ioc_match) flags += `<span class="ds-flag ioc">MATCHED IOC LIST</span> `;
    if (f.status === 'escalated') {
      flags += `<span class="ds-flag esc">ESCALATED</span>`;
      let esc = `<div style="margin-top:6px">`;
      esc += _row('Escalated', _esc(f.status_ts || '—'));
      if (f.analyst) esc += _row('Analyst', _esc(f.analyst));
      esc += '</div>';
      flags += esc;
    }
    if (f.analyst_note) {
      flags += `<div style="margin-top:8px"><div class="ds-section-title">Analyst note</div><div class="ds-explain">${_esc(f.analyst_note)}</div></div>`;
    }
    if (flags) sections.push(_section('', flags));

    // --- Why flagged ---
    const explain = EXPLANATIONS[f.type] || '';
    if (explain) {
      sections.push(_section('Why flagged', `<div class="ds-explain">${_esc(explain)}</div>`));
    }

    text.innerHTML = sections.join('');
    rec.textContent = explain ? explain.split('.')[0] : '';

    // Action buttons
    const ackBtn     = document.getElementById('ack-btn');
    const escBtn     = document.getElementById('esc-btn');
    const dismissBtn = document.getElementById('dismiss-btn');
    const chartBtn   = document.getElementById('chart-btn');
    const pcapBtn    = document.getElementById('pcap-btn');
    const rawBtn     = document.getElementById('raw-btn');
    const suppBtn    = document.getElementById('supp-btn');

    // Workflow-state buttons. A dismissed finding can be un-dismissed
    // (Dismiss button label flips) but cannot be acknowledged or
    // escalated without un-dismissing first — keeps the state
    // transitions linear instead of letting a dismissed finding leak
    // into the Ack/Esc tabs unintentionally.
    ackBtn.disabled     = f.status === 'dismissed';
    escBtn.disabled     = f.status === 'escalated' || f.status === 'dismissed';
    dismissBtn.disabled = false;
    suppBtn.disabled    = false;
    pcapBtn.disabled    = !(f.src_ip && f.dst_ip);
    // Beacon Chart is meaningful only for the two finding types that
    // carry TSData. Gate on type instead of f.ts_data presence — list
    // responses are projected (no ts_data) and the row-click upgrade
    // fetch arrives a tick later, leaving the button momentarily
    // disabled if we gated on the field directly.
    chartBtn.disabled = !(f.type === 'Beaconing' || f.type === 'HTTP Beaconing');
    if (rawBtn) {
      rawBtn.disabled = !(f.src_ip && f.dst_ip);
      rawBtn.dataset.findingId = f.id;
    }
    // JA3 Pivot — only when this beacon carries a TLS fingerprint.
    // Label folds in the sibling count so the analyst sees the pivot's
    // size before clicking; 0 siblings still allows the pivot (it
    // narrows to just this finding's fingerprint, a valid hunt).
    const ja3Btn = document.getElementById('ja3-btn');
    if (ja3Btn) {
      ja3Btn.disabled = !f.ja3;
      const n = f.ja3_sibling_count || 0;
      ja3Btn.textContent = f.ja3 && n > 0 ? `JA3 Pivot (${n})` : 'JA3 Pivot';
    }
    const exportBtn = document.getElementById('export-notes-btn');
    if (exportBtn) exportBtn.disabled = false;

    ackBtn.textContent     = f.status === 'acknowledged' ? 'Acknowledged' : 'Acknowledge';
    dismissBtn.textContent = f.status === 'dismissed'    ? 'Un-dismiss'   : 'Dismiss';

    // Notes + TI Results — partitioned by note author so the two
    // tabs surface focused content. Updates badges on each tab.
    _renderNotes(f);

    // Score evolution chart — Beaconing / HTTP Beaconing only.
    // BeaconEvolution.load is a no-op for other types (hides container).
    // The Score Evolution tab button is also revealed/hidden in
    // lockstep so the tab strip only offers it for beacon types.
    // When switching to a non-beacon finding while the Evolution
    // tab is active, snap back to Detail — clicking the Detail tab
    // button routes through the registered handler so behavior
    // matches an analyst clicking it themselves.
    const hasEvolution = f.type === 'Beaconing' || f.type === 'HTTP Beaconing';
    const evolutionBtn = document.getElementById('evolution-tab-btn');
    if (evolutionBtn) {
      evolutionBtn.style.display = hasEvolution ? '' : 'none';
      if (!hasEvolution && evolutionBtn.classList.contains('active')) {
        const detailBtn = document.querySelector('.dock-tab-btn[data-dock-tab="detail"]');
        if (detailBtn) detailBtn.click();
      }
    }
    if (typeof BeaconEvolution !== 'undefined') {
      BeaconEvolution.load(f.id, f.type);
    }
  }

  // _renderNotes partitions a finding's notes between the Notes tab
  // (analyst-authored) and the TI Results tab (machine-authored
  // "TI Enrichment" notes from the escalation lookups). Tab badges
  // show counts so the analyst can see at a glance which tabs have
  // content without flipping through them.
  function _renderNotes(f) {
    const notesList = document.getElementById('notes-list');
    const tiList    = document.getElementById('ti-results-list');
    const notesBadge = document.getElementById('notes-badge');
    const tiBadge    = document.getElementById('ti-badge');
    if (!notesList || !tiList) return;
    notesList.innerHTML = '';
    tiList.innerHTML = '';

    const notes = f.notes || [];
    const analystNotes = [];
    const tiNotes = [];
    notes.forEach(n => {
      if ((n.author || '') === 'TI Enrichment') tiNotes.push(n);
      else analystNotes.push(n);
    });

    const renderInto = (list, items, emptyMsg) => {
      if (items.length === 0) {
        list.innerHTML = `<div style="font-size:11px;color:var(--fg-dim);font-style:italic">${emptyMsg}</div>`;
        return;
      }
      items.forEach(n => {
        const div = document.createElement('div');
        div.className = 'note-item';
        div.innerHTML = `
          <div class="note-meta"><span class="note-author">${_esc(n.author)}</span>  •  ${_esc(n.timestamp)}</div>
          <div class="note-text">${_esc(n.text)}</div>`;
        list.appendChild(div);
      });
    };
    renderInto(notesList, analystNotes, 'No notes yet');
    renderInto(tiList, tiNotes, 'No TI results yet — escalate the finding to run TI lookups');

    _setBadge(notesBadge, analystNotes.length);
    _setBadge(tiBadge,    tiNotes.length);
  }

  function _setBadge(el, n) {
    if (!el) return;
    if (n > 0) {
      el.textContent = String(n);
      el.classList.add('has-count');
    } else {
      el.textContent = '';
      el.classList.remove('has-count');
    }
  }

  // Canonical strong-_esc — see app.js for the convention notes.
  // Audit 2026-05-10 NEW-30.
  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function clear() {
    document.getElementById('detail-header').textContent = 'SELECT A FINDING';
    document.getElementById('detail-header').style.color = '';
    document.getElementById('detail-text').textContent = '';
    document.getElementById('analyst-rec').textContent = '';
    const nl = document.getElementById('notes-list');
    const tl = document.getElementById('ti-results-list');
    if (nl) nl.innerHTML = '';
    if (tl) tl.innerHTML = '';
    _setBadge(document.getElementById('notes-badge'), 0);
    _setBadge(document.getElementById('ti-badge'),    0);
    ['ack-btn','esc-btn','dismiss-btn','chart-btn','pcap-btn','ja3-btn','supp-btn','export-notes-btn'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = true;
    });
    // Hide the Score Evolution tab when no finding is selected. If
    // the tab was active, snap back to Detail so the panel area
    // doesn't look broken.
    const evolutionBtn = document.getElementById('evolution-tab-btn');
    if (evolutionBtn) {
      if (evolutionBtn.classList.contains('active')) {
        const detailBtn = document.querySelector('.dock-tab-btn[data-dock-tab="detail"]');
        if (detailBtn) detailBtn.click();
      }
      evolutionBtn.style.display = 'none';
    }
    if (typeof BeaconEvolution !== 'undefined') BeaconEvolution.clear();
  }

  return { render, clear };
})();
