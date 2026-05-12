// notifications.js — bell badge and notification panel
'use strict';

const Notifications = (() => {
  const _items = [];
  let _open = false;

  function _bellBtn()    { return document.getElementById('bell-btn'); }
  function _badge()      { return document.getElementById('notif-badge'); }
  function _panel()      { return document.getElementById('notif-panel'); }
  function _list()       { return document.getElementById('notif-list'); }
  function _dismissAllBtn() { return document.getElementById('dismiss-all-btn'); }

  function _sevColor(sev) {
    return {CRITICAL:'var(--sev-critical)', HIGH:'var(--sev-high)', MEDIUM:'var(--sev-medium)',
            LOW:'var(--sev-low)', INFO:'var(--sev-info)'}[sev] || 'var(--fg-text)';
  }

  // Canonical strong-_esc — see app.js for the convention notes and
  // the Go-side consistency test that ensures every module's copy
  // escapes all five characters. Audit 2026-05-10 NEW-26 / NEW-30.
  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function _render() {
    const el = _list();
    el.innerHTML = '';
    if (_items.length === 0) {
      el.innerHTML = '<div style="padding:12px;color:var(--fg-dim);font-size:11px">No alerts</div>';
      return;
    }
    _items.forEach(n => {
      const div = document.createElement('div');
      div.className = 'notif-item';
      const kind = n.kind || 'finding';
      // Finding alarms render src→dst:port; sensor/feed alarms render
      // a human-readable Detail line ("Sensor lab-1 hasn't checked in
      // for 2h 15m") supplied by the emitter. _sevColor returns from
      // a fixed enum; not user-controlled so it doesn't need escaping.
      // id is integer-coerced. Every other interpolation routes
      // through _esc.
      let body;
      if (kind === 'finding') {
        body = `<div class="notif-addr">${_esc(n.src_ip || '')} → ${_esc(n.dst_ip || '')} ${n.dst_port ? ':' + _esc(String(n.dst_port)) : ''}</div>`;
      } else {
        body = `<div class="notif-addr">${_esc(n.detail || n.target || '')}</div>`;
      }
      div.innerHTML = `
        <div class="notif-sev" style="color:${_sevColor(n.severity)}">${_esc(n.severity)} — ${_esc(n.type)}</div>
        ${body}
        <div class="notif-actions">
          <button class="btn-jump" data-notif-id="${Number(n.id) || 0}">Jump</button>
          <button class="btn-dismiss-notif" data-id="${Number(n.id) || 0}">Dismiss</button>
        </div>`;
      el.appendChild(div);
    });
  }

  function _findById(id) {
    return _items.find(x => x.id === id);
  }

  function _updateBadge() {
    const b = _badge();
    const bell = _bellBtn();
    if (_items.length === 0) {
      b.classList.add('hidden');
      bell.classList.remove('has-alerts');
    } else {
      b.textContent = _items.length > 99 ? '99+' : _items.length;
      b.classList.remove('hidden');
      bell.classList.add('has-alerts');
    }
  }

  function add(n) {
    if (_items.find(x => x.id === n.id)) return;
    _items.unshift(n);
    _updateBadge();
    if (_open) _render();
  }

  function dismiss(id) {
    const nid = parseInt(id, 10);
    const idx = _items.findIndex(n => n.id === nid);
    if (idx >= 0) _items.splice(idx, 1);
    fetch('/api/notifications', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({action: 'dismiss', id: nid}),
    }).catch(() => {});
    _updateBadge();
    _render();
  }

  function dismissAll() {
    _items.length = 0;
    fetch('/api/notifications', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({action: 'dismiss_all'}),
    }).catch(() => {});
    _updateBadge();
    _render();
  }

  function toggle() {
    _open = !_open;
    _panel().classList.toggle('hidden', !_open);
    if (_open) _render();
  }

  function close() {
    _open = false;
    _panel().classList.add('hidden');
  }

  function init(onJump) {
    _bellBtn().addEventListener('click', e => { e.stopPropagation(); toggle(); });
    _dismissAllBtn().addEventListener('click', () => dismissAll());

    _list().addEventListener('click', e => {
      const jumpBtn    = e.target.closest('.btn-jump');
      const dismissBtn = e.target.closest('.btn-dismiss-notif');
      if (jumpBtn) {
        close();
        const notif = _findById(parseInt(jumpBtn.dataset.notifId, 10));
        if (onJump && notif) onJump(notif);
      }
      if (dismissBtn) dismiss(dismissBtn.dataset.id);
    });

    document.addEventListener('click', e => {
      if (_open && !e.target.closest('#notif-wrap')) close();
    });

    fetch('/api/notifications')
      .then(r => r.json())
      .then(data => {
        if (Array.isArray(data)) data.filter(n => !n.dismissed).forEach(n => _items.push(n));
        _updateBadge();
      })
      .catch(() => {});
  }

  return { init, add, dismiss, dismissAll, close };
})();
