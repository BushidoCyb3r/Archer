// rowmenu.js — small popover menu anchored to a kebab (⋮) button.
//
// Shared between the Feeds and Sensors modals. Each modal renders a
// `.row-kebab` button per row; the click handler builds an item list
// and calls RowMenu.open(button, items). The menu auto-closes on
// outside click, ESC, or after an item is selected.
//
// Items:
//   { label: string, onClick?: fn, danger?: bool, disabled?: bool, hint?: string }
//   '---' renders a separator.
//
// Positioning is fixed and right-aligned to the kebab button so the
// menu opens directly under it, with a flip to above if it would
// overflow the viewport bottom. The menu is appended to the open
// <dialog> when the kebab lives inside one — required because a
// `showModal()` dialog sits in the browser's top layer, and anything
// appended to document.body renders underneath the modal backdrop.

'use strict';

const RowMenu = (() => {
  let _open = null;

  function _close() {
    if (!_open) return;
    _open.remove();
    _open = null;
    document.removeEventListener('click', _onDocClick, true);
    document.removeEventListener('keydown', _onKey, true);
    window.removeEventListener('resize', _close);
    window.removeEventListener('scroll', _close, true);
  }

  function _onDocClick(e) {
    if (_open && !_open.contains(e.target)) _close();
  }

  function _onKey(e) {
    if (e.key === 'Escape') { _close(); e.stopPropagation(); }
  }

  function open(anchor, items) {
    _close();
    const menu = document.createElement('ul');
    menu.className = 'row-menu';
    items.forEach(it => {
      if (it === '---') {
        const sep = document.createElement('li');
        sep.className = 'row-menu-sep';
        menu.appendChild(sep);
        return;
      }
      const li = document.createElement('li');
      li.textContent = it.label;
      const cls = [];
      if (it.danger) cls.push('row-menu-danger');
      if (it.disabled) cls.push('row-menu-disabled');
      if (cls.length) li.className = cls.join(' ');
      if (it.hint) li.title = it.hint;
      if (!it.disabled && typeof it.onClick === 'function') {
        li.addEventListener('click', ev => {
          ev.stopPropagation();
          _close();
          it.onClick();
        });
      }
      menu.appendChild(li);
    });

    // Append inside the enclosing open dialog so the top-layer stacking
    // context contains the menu. Outside a dialog, body is fine.
    const parent = anchor.closest('dialog[open]') || document.body;
    parent.appendChild(menu);

    const rect = anchor.getBoundingClientRect();
    const mw = menu.offsetWidth;
    const mh = menu.offsetHeight;
    let left = rect.right - mw;
    let top  = rect.bottom + 4;
    if (left < 4) left = 4;
    if (left + mw > window.innerWidth - 4) left = window.innerWidth - mw - 4;
    if (top + mh > window.innerHeight - 4) top = rect.top - mh - 4;
    menu.style.left = left + 'px';
    menu.style.top  = top + 'px';

    _open = menu;
    // Defer the outside-click listener so the opening click doesn't
    // immediately close the menu.
    setTimeout(() => {
      document.addEventListener('click', _onDocClick, true);
      document.addEventListener('keydown', _onKey, true);
      window.addEventListener('resize', _close);
      window.addEventListener('scroll', _close, true);
    }, 0);
  }

  return { open, close: _close };
})();
