// dialog.js — centred, draggable modal dialogs (fixed size at declared widths)
'use strict';

const DlgManager = (() => {

  // Clear any inline position so the CSS centering takes over on the
  // next open. Width/height aren't touched — there's no resize handle,
  // so they stay at their declared values.
  function _resetPos(dlg) {
    dlg.style.left      = '';
    dlg.style.top       = '';
    dlg.style.margin    = '';
  }

  // Commit the current CSS-computed position to inline px values so we can
  // drag freely without fighting the `margin: auto` centering.
  function _snapToPixel(dlg) {
    const r = dlg.getBoundingClientRect();
    dlg.style.margin = '0';
    dlg.style.left = r.left + 'px';
    dlg.style.top  = r.top  + 'px';
  }

  function _attach(dlg) {
    // Standard dialogs mark their header with `.dlg-header`. The score-
    // evolution modal carries its own custom header structure and opts
    // into drag by adding `.dlg-drag-handle` instead — either qualifies.
    const header = dlg.querySelector('.dlg-header, .dlg-drag-handle');
    if (!header) return;

    header.addEventListener('mousedown', e => {
      if (e.target.closest('button,input,select,a,textarea')) return;
      e.preventDefault();

      _snapToPixel(dlg);

      const startX = e.clientX;
      const startY = e.clientY;
      const origL  = parseFloat(dlg.style.left);
      const origT  = parseFloat(dlg.style.top);

      function onMove(e) {
        let x = origL + (e.clientX - startX);
        let y = origT + (e.clientY - startY);
        x = Math.max(0, Math.min(window.innerWidth  - dlg.offsetWidth,  x));
        y = Math.max(0, Math.min(window.innerHeight - dlg.offsetHeight, y));
        dlg.style.left = x + 'px';
        dlg.style.top  = y + 'px';
      }

      function onUp() {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup',   onUp);
      }

      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup',   onUp);
    });

    const origShow = dlg.showModal.bind(dlg);
    dlg.showModal = () => { _resetPos(dlg); origShow(); };
  }

  function init() {
    document.querySelectorAll('dialog').forEach(_attach);
  }

  return { init };
})();
