'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { extractFn } = require('./load');

// _isInternalIP gates the node-shape encoding (internal hosts render as
// round-rectangles, external as circles). Wrong classification silently
// mis-encodes the graph, so pin the RFC ranges.
test('_isInternalIP classifies private/loopback/link-local as internal', () => {
  const f = extractFn('graph.js', '_isInternalIP');
  assert.strictEqual(f('10.0.4.12'), true);
  assert.strictEqual(f('172.16.0.1'), true);
  assert.strictEqual(f('172.31.255.254'), true);
  assert.strictEqual(f('192.168.1.1'), true);
  assert.strictEqual(f('127.0.0.1'), true);
  assert.strictEqual(f('169.254.10.10'), true);
  assert.strictEqual(f('::1'), true);
  assert.strictEqual(f('fe80::1'), true);
  assert.strictEqual(f('fd00::5'), true);
  assert.strictEqual(f('fc12::9'), true);
});

test('_isInternalIP classifies public space as external', () => {
  const f = extractFn('graph.js', '_isInternalIP');
  assert.strictEqual(f('203.0.113.50'), false);
  assert.strictEqual(f('8.8.8.8'), false);
  assert.strictEqual(f('172.32.0.1'), false, '172.32/16 is outside RFC1918');
  assert.strictEqual(f('172.15.0.1'), false);
  assert.strictEqual(f('192.169.0.1'), false);
  assert.strictEqual(f('2001:db8::1'), false);
  assert.strictEqual(f(''), false);
  assert.strictEqual(f(undefined), false);
});

// Count badge: heavy nodes carry their finding count in the label.
test('_nodeLabel appends a count badge at >= 10 findings', () => {
  const f = extractFn('graph.js', '_nodeLabel');
  assert.strictEqual(f('10.0.0.1', 1), '10.0.0.1');
  assert.strictEqual(f('10.0.0.1', 9), '10.0.0.1');
  assert.strictEqual(f('10.0.0.1', 10), '10.0.0.1 · 10');
  assert.strictEqual(f('203.0.113.5', 42), '203.0.113.5 · 42');
});

// Node cap keeps cose from hanging on a high fan-in campaign graph. The
// invariant: above the cap the kept set is exactly `cap` nodes, always
// includes the scoped dst hub, and carries no edge referencing a dropped node.
test('_capElements caps a high fan-in graph, keeps the hub, drops dangling edges', () => {
  const cap = 50;
  const dst = '203.0.113.9'; // scoped hub every src fans into
  const N = 200;
  const nodes = [{ data: { id: dst, count: N } }];
  const edges = [];
  for (let i = 0; i < N; i++) {
    const src = '10.0.0.' + i;
    nodes.push({ data: { id: src, count: 1 } });
    edges.push({ data: { id: 'e' + i, source: src, target: dst } });
  }

  const f = extractFn('graph.js', '_capElements');
  const out = f(nodes, edges, dst, cap);

  assert.strictEqual(out.truncated, true);
  assert.strictEqual(out.total, N + 1);
  assert.strictEqual(out.nodes.length, cap, 'kept set is exactly the cap');

  const kept = new Set(out.nodes.map(n => n.data.id));
  assert.ok(kept.has(dst), 'scoped dst hub is always kept');
  out.edges.forEach(e => {
    assert.ok(kept.has(e.data.source) && kept.has(e.data.target),
      'no edge references a dropped node');
  });
});

// Below the cap nothing is dropped and the set passes through untouched.
test('_capElements passes a small graph through untruncated', () => {
  const f = extractFn('graph.js', '_capElements');
  const nodes = [{ data: { id: 'a', count: 1 } }, { data: { id: 'b', count: 1 } }];
  const edges = [{ data: { id: 'e0', source: 'a', target: 'b' } }];
  const out = f(nodes, edges, 'b', 200);
  assert.strictEqual(out.truncated, false);
  assert.strictEqual(out.nodes.length, 2);
  assert.strictEqual(out.edges.length, 1);
});
