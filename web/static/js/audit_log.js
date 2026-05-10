// audit_log.js — admin-only audit-log viewer (v0.14.0)
//
// Read-only modal that lists every state-changing admin action
// recorded server-side via Server.recordAudit. Cursor-based
// pagination on row id; most-recent first. Filter is client-side
// over loaded rows (substring match against action+target+actor).
'use strict';

const AuditLog = (() => {
  let _entries = [];
  let _nextCursor = 0;
  let _total = 0;
  let _loading = false;

  // Canonical strong-_esc — see app.js for the convention notes and
  // the Go-side consistency test. NEW-30.
  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function _fmtTS(ts) {
    if (!ts) return '—';
    return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19);
  }

  function _flat(j) {
    if (!j) return null;
    try {
      const obj = JSON.parse(j);
      if (obj && typeof obj === 'object') return obj;
      return null;
    } catch (e) {
      return null;
    }
  }

  function _kvLine(obj) {
    return Object.entries(obj)
      .map(([k, v]) => _esc(k) + '=' + _esc(typeof v === 'object' ? JSON.stringify(v) : String(v)))
      .join(', ');
  }

  // Renders a before→after transition, falling back to the details
  // bag for events that don't have a clean state-transition shape
  // (login_*, feed_refresh, finding_import). Either column may be
  // absent for create/delete events; we render just the side that's
  // populated.
  function _fmtChange(e) {
    const before = _flat(e.before_value);
    const after = _flat(e.after_value);
    const details = _flat(e.details);
    const parts = [];
    if (before && after) {
      parts.push('before: ' + _kvLine(before));
      parts.push('after: ' + _kvLine(after));
    } else if (after) {
      parts.push(_kvLine(after));
    } else if (before) {
      parts.push(_kvLine(before));
    }
    if (details) {
      parts.push(_kvLine(details));
    }
    return parts.join(' • ');
  }

  function _fmtTarget(e) {
    if (!e.target_type) return '';
    let out = _esc(e.target_type);
    if (e.target_id) out += ':' + _esc(String(e.target_id));
    if (e.target_name) out += ' (' + _esc(e.target_name) + ')';
    return out;
  }

  function _render() {
    const tbody = document.getElementById('audit-tbody');
    const filter = document.getElementById('audit-filter').value.trim().toLowerCase();
    const visible = filter
      ? _entries.filter(e =>
          (e.action || '').toLowerCase().includes(filter) ||
          (e.target_type || '').toLowerCase().includes(filter) ||
          (e.target_name || '').toLowerCase().includes(filter) ||
          (e.actor_email || '').toLowerCase().includes(filter))
      : _entries;
    if (visible.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--fg-dim);padding:12px">No matching audit entries</td></tr>';
    } else {
      tbody.innerHTML = visible.map(e => `
        <tr>
          <td style="padding:5px;font-family:monospace">${_esc(_fmtTS(e.ts))}</td>
          <td>${_esc(e.actor_email || 'system')}</td>
          <td><code>${_esc(e.action)}</code></td>
          <td>${_fmtTarget(e)}</td>
          <td style="font-family:monospace;font-size:11px;color:var(--fg-dim);word-break:break-all">${_fmtChange(e)}</td>
          <td style="font-family:monospace">${_esc(e.source_ip || '')}</td>
        </tr>`).join('');
    }
    document.getElementById('audit-total').textContent =
      `Showing ${visible.length}${filter ? ` of ${_entries.length} loaded` : ''} • ${_total} total entries`;
    document.getElementById('audit-load-more').style.display =
      _nextCursor > 0 ? 'inline-block' : 'none';
  }

  async function _loadPage(cursor) {
    if (_loading) return;
    _loading = true;
    try {
      const r = await fetch('/api/audit-log?cursor=' + cursor + '&count=100');
      if (!r.ok) throw new Error('audit log fetch: ' + r.status);
      const data = await r.json();
      if (cursor === 0) {
        _entries = data.entries || [];
      } else {
        _entries = _entries.concat(data.entries || []);
      }
      _nextCursor = data.next || 0;
      _total = data.total || 0;
    } catch (e) {
      console.error(e);
    } finally {
      _loading = false;
      _render();
    }
  }

  function open() {
    _entries = [];
    _nextCursor = 0;
    document.getElementById('audit-filter').value = '';
    document.getElementById('audit-dialog').showModal();
    _loadPage(0);
  }

  function init() {
    const btn = document.getElementById('audit-btn');
    if (btn) btn.addEventListener('click', open);
    document.getElementById('audit-close').addEventListener('click', () =>
      document.getElementById('audit-dialog').close());
    document.getElementById('audit-load-more').addEventListener('click', () => {
      if (_nextCursor > 0) _loadPage(_nextCursor);
    });
    document.getElementById('audit-filter').addEventListener('input', _render);
  }

  return { init, open };
})();
