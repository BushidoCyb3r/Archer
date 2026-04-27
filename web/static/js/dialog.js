// dialog.js — centred, draggable, resizable modal dialogs
'use strict';

const DlgManager = (() => {

  // Clear any inline position/size so the CSS transform-centering and
  // auto-fit-to-content take over again on the next open.
  function _resetPos(dlg) {
    dlg.style.left      = '';
    dlg.style.top       = '';
    dlg.style.transform = '';
    dlg.style.width     = '';
    dlg.style.height    = '';
  }

  // Commit the current CSS-computed position to inline px values so we can
  // drag freely without fighting the transform centering.
  function _snapToPixel(dlg) {
    const r = dlg.getBoundingClientRect();
    dlg.style.transform = 'none';
    dlg.style.left = r.left + 'px';
    dlg.style.top  = r.top  + 'px';
  }

  function _attachResize(dlg) {
    // Avoid double-mount if init() runs twice.
    if (dlg.querySelector(':scope > .dlg-resize-handle')) return;
    const grip = document.createElement('div');
    grip.className = 'dlg-resize-handle';
    grip.title = 'Drag to resize';
    dlg.appendChild(grip);

    grip.addEventListener('mousedown', e => {
      e.preventDefault();
      e.stopPropagation();

      _snapToPixel(dlg);

      const r = dlg.getBoundingClientRect();
      const startX = e.clientX;
      const startY = e.clientY;
      const startW = r.width;
      const startH = r.height;
      const left   = r.left;
      const top    = r.top;

      function onMove(ev) {
        // Cap so the dialog stays inside the viewport from its current top/left.
        const maxW = window.innerWidth  - left - 4;
        const maxH = window.innerHeight - top  - 4;
        const w = Math.max(280, Math.min(maxW, startW + (ev.clientX - startX)));
        const h = Math.max(160, Math.min(maxH, startH + (ev.clientY - startY)));
        dlg.style.width  = w + 'px';
        dlg.style.height = h + 'px';
      }

      function onUp() {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup',   onUp);
      }

      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup',   onUp);
    });
  }

  function _attach(dlg) {
    const header = dlg.querySelector('.dlg-header');
    if (!header) return;

    header.addEventListener('mousedown', e => {
      // Ignore clicks on interactive elements inside the header
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
        // Keep dialog fully within viewport
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

    _attachResize(dlg);

    // Patch showModal so every open re-centres and re-fits the dialog.
    const origShow = dlg.showModal.bind(dlg);
    dlg.showModal = () => { _resetPos(dlg); origShow(); };
  }

  function init() {
    document.querySelectorAll('dialog').forEach(_attach);
  }

  return { init };
})();
