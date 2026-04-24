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
      div.innerHTML = `
        <div class="notif-sev" style="color:${_sevColor(n.severity)}">${n.severity} — ${n.type}</div>
        <div class="notif-addr">${n.src_ip || ''} → ${n.dst_ip || ''} ${n.dst_port ? ':' + n.dst_port : ''}</div>
        <div class="notif-actions">
          <button class="btn-jump" data-finding-id="${n.finding_id}">Jump</button>
          <button class="btn-dismiss-notif" data-id="${n.id}">Dismiss</button>
        </div>`;
      el.appendChild(div);
    });
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
        if (onJump) onJump(parseInt(jumpBtn.dataset.findingId, 10));
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
