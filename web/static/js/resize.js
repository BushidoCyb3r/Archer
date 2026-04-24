// resize.js — draggable column resize handles for any table
'use strict';

const ColResize = (() => {

  function init(tableId) {
    const table = document.getElementById(tableId);
    if (!table) return;

    const ths = Array.from(table.querySelectorAll('thead th'));
    if (ths.length === 0) return;

    // Lock every column except the last to its current rendered width.
    // The last column is left as auto so it absorbs any freed/taken space —
    // this prevents erratic reflow when dragging any column left.
    ths.slice(0, -1).forEach(th => {
      if (!th.style.width) {
        th.style.width = th.getBoundingClientRect().width + 'px';
      }
    });
    ths[ths.length - 1].style.width = ''; // auto — fills remaining space

    ths.forEach((th, i) => {
      // No handle on last column — it fills remaining space
      if (i === ths.length - 1) return;

      const handle = document.createElement('div');
      handle.className = 'col-resize-handle';
      th.appendChild(handle);

      handle.addEventListener('mousedown', e => {
        e.preventDefault();
        e.stopPropagation(); // prevent sort click

        const startX = e.clientX;
        const startW = th.getBoundingClientRect().width;

        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';

        function onMove(e) {
          const newW = Math.max(32, startW + (e.clientX - startX));
          th.style.width = newW + 'px';
        }

        function onUp() {
          document.body.style.cursor = '';
          document.body.style.userSelect = '';
          document.removeEventListener('mousemove', onMove);
          document.removeEventListener('mouseup',  onUp);
        }

        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup',   onUp);
      });
    });
  }

  return { init };
})();
