// attack.js — the MITRE ATT&CK Coverage modal.
//
// A technique-first hunt surface: lists the ATT&CK techniques the current
// findings evidence (from /api/attack-coverage), grouped by tactic, with the
// finding count behind each. Clicking a technique hands its ID back to app.js,
// which pivots the Findings tab to attack:<id>. The ID also links out to
// attack.mitre.org. Opened from the filter-bar "ATT&CK" button; read-only.

'use strict';

const Attack = (() => {
  // app.js owns the query pivot (it lives inside its IIFE), so it injects a
  // callback at init time rather than us reaching into its private scope.
  let _onPivot = null;

  // Module-local fetch wrapper — app.js's api() is IIFE-private. Canonical
  // body shared with the other SPA modules (pinned by a Go consistency test).
  function _api(url, opts) {
    return fetch(url, opts || {}).then(r => {
      if (!r.ok) {
        return r.json().catch(() => ({})).then(e => Promise.reject(new Error(e.error || r.statusText)));
      }
      const ct = r.headers.get('content-type') || '';
      return ct.includes('json') ? r.json() : r.text();
    });
  }

  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function _render(data) {
    const wrap  = document.getElementById('attack-coverage');
    const empty = document.getElementById('attack-empty');
    if (!wrap) return;
    wrap.innerHTML = '';

    const techs = (data && data.techniques) || [];
    if (!techs.length) {
      if (empty) empty.style.display = '';
    } else {
      if (empty) empty.style.display = 'none';
      // Group by tactic in the (count-desc) order techniques arrive in.
      const order = [];
      const byTactic = {};
      techs.forEach(t => {
        if (!byTactic[t.tactic]) { byTactic[t.tactic] = []; order.push(t.tactic); }
        byTactic[t.tactic].push(t);
      });
      order.forEach(tactic => {
        const group = document.createElement('div');
        group.className = 'attack-group';
        let html = `<div class="attack-tactic">${_esc(tactic)}</div>`;
        byTactic[tactic].forEach(t => {
          const types = (t.types || []).map(x => `${x.type} (${x.count})`).join(', ');
          html += `<div class="attack-row">` +
            `<button class="attack-tech" type="button" data-id="${_esc(t.id)}" ` +
            `title="${_esc(types)}">` +
            `<span class="attack-chip">${_esc(t.id)}</span> ${_esc(t.name)}` +
            `<span class="attack-count">${_esc(String(t.count))}</span></button> ` +
            `<a class="attack-ext" href="${_esc(t.url)}" target="_blank" rel="noopener noreferrer" title="View on attack.mitre.org">↗</a>` +
            `</div>`;
        });
        group.innerHTML = html;
        wrap.appendChild(group);
      });
    }

    // Unmapped finding types (TI hits, roll-ups, notices) — shown so coverage
    // gaps are honest rather than hidden.
    const unmapped = (data && data.unmapped) || [];
    const det   = document.getElementById('attack-unmapped');
    const cnt   = document.getElementById('attack-unmapped-count');
    const list  = document.getElementById('attack-unmapped-list');
    if (det && cnt && list) {
      if (unmapped.length) {
        det.style.display = '';
        cnt.textContent = String(unmapped.length);
        list.innerHTML = unmapped.map(u =>
          `<div class="attack-row"><span>${_esc(u.type)}</span><span class="attack-count">${_esc(String(u.count))}</span></div>`
        ).join('');
      } else {
        det.style.display = 'none';
      }
    }
  }

  async function open() {
    const dlg = document.getElementById('attack-dialog');
    if (!dlg) return;
    const wrap = document.getElementById('attack-coverage');
    if (wrap) wrap.innerHTML = '<div class="fp-hint">Loading…</div>';
    dlg.showModal();
    try {
      _render(await _api('/api/attack-coverage'));
    } catch (e) {
      if (wrap) wrap.innerHTML = `<div class="fp-empty">Error: ${_esc(e.message)}</div>`;
    }
  }

  function init(opts) {
    opts = opts || {};
    _onPivot = opts.onPivot || null;

    const btn = document.getElementById('attack-coverage-btn');
    if (btn) btn.addEventListener('click', open);

    const closeBtn = document.getElementById('attack-close');
    if (closeBtn) closeBtn.addEventListener('click', () =>
      document.getElementById('attack-dialog').close());

    const wrap = document.getElementById('attack-coverage');
    if (wrap) wrap.addEventListener('click', e => {
      const btn = e.target.closest('.attack-tech');
      if (!btn) return;
      const id = btn.dataset.id;
      document.getElementById('attack-dialog').close();
      if (_onPivot && id) _onPivot(id);
    });
  }

  return { init, open };
})();
