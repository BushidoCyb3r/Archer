'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { loadModule } = require('./load');

// Bulk-selection logic in table.js: a checkbox/modifier click toggles a
// finding's membership in the set the footer Acknowledge/Escalate/Dismiss
// buttons act on, Shift-click extends a range, the header checkbox selects the
// whole loaded page, load() clears the set, and the set is reflected onto the
// row checkboxes. Driven through a fake DOM that captures the delegated click
// handlers, since selection is event-driven rather than a public mutator.

function fakeFinding(id) {
  return {
    id, score: 0, severity: 'HIGH', type: 'Beacon',
    src_ip: '10.0.0.1', dst_ip: '203.0.113.1', dst_port: '443',
    timestamp: '2026-06-14T10:00:00Z', status: '', detail: 'x',
  };
}

function makeDom(findings) {
  const rows = findings.map(f => {
    const input = { type: 'checkbox', checked: false };
    return {
      dataset: { id: String(f.id) },
      classList: { toggle() {}, add() {}, remove() {} },
      querySelector: sel => (sel === '.row-check input' ? input : null),
      _input: input,
    };
  });
  let tbodyClick = null;
  let checkAllClick = null;
  const wrap = { clientHeight: 10000, scrollTop: 0, addEventListener() {} };
  const tbody = {
    innerHTML: '',
    closest: () => wrap,
    addEventListener: (ev, fn) => { if (ev === 'click') tbodyClick = fn; },
  };
  const checkAll = {
    checked: false, indeterminate: false,
    addEventListener: (ev, fn) => { if (ev === 'click') checkAllClick = fn; },
  };
  const document = {
    getElementById: id =>
      id === 'findings-tbody' ? tbody : id === 'findings-check-all' ? checkAll : null,
    querySelectorAll: sel => (sel === '#findings-tbody tr[data-id]' ? rows : []),
    addEventListener() {},
  };
  return {
    sandbox: { document, window: { addEventListener() {} }, requestAnimationFrame: fn => fn() },
    rows,
    tbody,
    fireRowClick(id, mods = {}) {
      const tr = rows.find(r => r.dataset.id === String(id));
      const target = {
        closest: sel =>
          sel === 'tr[data-id]' ? tr : sel === '.row-check' ? (mods.checkbox ? {} : null) : null,
      };
      tbodyClick({ target, shiftKey: !!mods.shift, ctrlKey: !!mods.ctrl, metaKey: !!mods.meta });
    },
    fireCheckAll(on) {
      checkAll.checked = on;
      checkAllClick({ target: checkAll });
    },
  };
}

function sorted(ids) { return [...ids].sort((a, b) => a - b); }

test('checkbox click toggles selection; Shift-click extends a range; Ctrl-click toggles one', () => {
  const findings = [10, 20, 30, 40, 50].map(fakeFinding);
  const dom = makeDom(findings);
  const Table = loadModule('table.js', 'Table', dom.sandbox);
  let lastCount = -1;
  Table.init(() => {}, () => {}, () => {}, c => { lastCount = c; });
  Table.load(findings);
  assert.strictEqual(Table.checkedCount(), 0, 'load starts with an empty selection');

  dom.fireRowClick(20, { checkbox: true });
  assert.deepStrictEqual(sorted(Table.getCheckedIds()), [20]);
  assert.strictEqual(lastCount, 1, 'selection-change callback reports the count');
  const row20 = dom.rows.find(r => r.dataset.id === '20');
  assert.strictEqual(row20._input.checked, true, 'the row checkbox reflects the set');

  // Shift-click 40 → anchor was 20, so the inclusive range 20..40 is selected.
  dom.fireRowClick(40, { shift: true });
  assert.deepStrictEqual(sorted(Table.getCheckedIds()), [20, 30, 40]);

  // Ctrl-click 20 toggles just that one off.
  dom.fireRowClick(20, { ctrl: true });
  assert.deepStrictEqual(sorted(Table.getCheckedIds()), [30, 40]);
});

test('header checkbox selects/clears the whole loaded page; load() clears the set', () => {
  const findings = [1, 2, 3, 4].map(fakeFinding);
  const dom = makeDom(findings);
  const Table = loadModule('table.js', 'Table', dom.sandbox);
  Table.init(() => {}, () => {}, () => {}, () => {});
  Table.load(findings);

  dom.fireCheckAll(true);
  assert.deepStrictEqual(sorted(Table.getCheckedIds()), [1, 2, 3, 4], 'select-all picks every loaded row');

  dom.fireCheckAll(false);
  assert.strictEqual(Table.checkedCount(), 0, 'unchecking select-all clears the set');

  dom.fireRowClick(2, { checkbox: true });
  assert.strictEqual(Table.checkedCount(), 1);
  Table.load(findings); // a data reload must drop the stale selection
  assert.strictEqual(Table.checkedCount(), 0, 'load() clears the selection');
});

test('rows render a selection checkbox column', () => {
  const findings = [1, 2].map(fakeFinding);
  const dom = makeDom(findings);
  const Table = loadModule('table.js', 'Table', dom.sandbox);
  Table.load(findings);
  assert.match(
    dom.tbody.innerHTML,
    /<td class="row-check"><input type="checkbox"/,
    'each row renders a selection checkbox cell'
  );
});
