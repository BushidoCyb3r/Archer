'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { loadModule } = require('./load');

// The findings table renders in the order the server returns. Sorting is
// server-authoritative now (the active column/dir ride the /api/findings
// fetch), because the table only holds a page and can't order the full set.
// Before this, the table re-sorted the loaded slice client-side, so clicking a
// column header reordered a single page out of the global order — misleading
// on a paginated tab, and the count flipped to the loaded-slice length. These
// tests pin the invariant one layer up from the (server) sort test: the client
// preserves received order and never re-sorts.

function makeDom() {
  const tbody = {
    innerHTML: '',
    closest: () => wrap,
  };
  const wrap = { clientHeight: 10000, scrollTop: 0 };
  const document = {
    getElementById: id => (id === 'findings-tbody' ? tbody : null),
    querySelectorAll: () => [],
    addEventListener: () => {},
  };
  return { document, tbody, window: {}, requestAnimationFrame: fn => fn() };
}

function renderedIds(tbody) {
  return [...tbody.innerHTML.matchAll(/<tr [^>]*data-id="(\d+)"/g)].map(m => Number(m[1]));
}

function fakeFinding(id, score) {
  return {
    id, score, severity: 'HIGH', type: 'Beacon',
    src_ip: '10.0.0.1', dst_ip: '203.0.113.1', dst_port: '443',
    timestamp: '2026-06-14T10:00:00Z', status: '', detail: 'x',
  };
}

test('Table.load renders in received order — no client-side re-sort', () => {
  const sandbox = makeDom();
  const Table = loadModule('table.js', 'Table', sandbox);

  // Deliberately NOT in score order: a client re-sort would reorder these by
  // score; a server-authoritative table must preserve the given order exactly.
  const order = [7, 3, 9, 1, 5];
  Table.load(order.map((id, i) => fakeFinding(id, /* score */ i * 10)));

  assert.deepStrictEqual(
    renderedIds(sandbox.tbody), order,
    'rendered row order must equal the order the server returned'
  );
});

test('Table.getSort reports the default sort, mapping dir to -1/1', () => {
  const Table = loadModule('table.js', 'Table', makeDom());
  const s = Table.getSort();
  // Field-wise: the object crosses the vm realm boundary, so its prototype
  // differs from the test realm's and deepStrictEqual would reject it.
  assert.strictEqual(s.col, 'score', 'default sort column is score');
  assert.strictEqual(s.dir, -1, 'default direction is descending (-1 → dir=desc)');
});
