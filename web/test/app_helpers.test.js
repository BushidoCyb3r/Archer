'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { extractFn } = require('./load');

// _shouldBadgeUnseen preserves the old modal's pop condition exactly: badge
// only when there are unseen findings the analyst hasn't already been told
// about this session (server-side high-water, not a JS flag).
test('_shouldBadgeUnseen fires only above the session high-water', () => {
  const f = extractFn('app.js', '_shouldBadgeUnseen');
  assert.strictEqual(f(0, 0), false, 'no unseen findings');
  assert.strictEqual(f(5, 0), true, 'fresh session, unseen findings');
  assert.strictEqual(f(5, 5), false, 'already acknowledged at this count');
  assert.strictEqual(f(6, 5), true, 'count climbed past the high-water');
  assert.strictEqual(f(3, 5), false, 'count below high-water (retention purge)');
});

// _tickValue drives the animated count chips. Endpoints must be exact —
// a chip that settles on an off-by-one count is worse than no animation.
test('_tickValue interpolates with exact endpoints and no overshoot', () => {
  const f = extractFn('app.js', '_tickValue');
  assert.strictEqual(f(0, 100, 0), 0);
  assert.strictEqual(f(0, 100, 1), 100);
  assert.strictEqual(f(128, 129, 1), 129);
  assert.strictEqual(f(100, 0, 1), 0, 'counts can go down');
  for (let p = 0; p <= 1.0001; p += 0.05) {
    const v = f(0, 100, Math.min(1, p));
    assert.ok(v >= 0 && v <= 100, `no overshoot at p=${p}`);
  }
});

// _composeHideBenign builds the query the Hide FP Benign toggle sends. The
// parenthesization is the load-bearing part: an OR query ANDed without parens
// would rebind (`a OR b AND benign:false` leaves the `a` arm unfiltered).
// The Go-side TestHideBenignComposition (internal/query/eval_test.go) pins
// that the composed shape parses and evaluates correctly server-side.
test('_composeHideBenign wraps the user query and ANDs benign:false', () => {
  const f = extractFn('app.js', '_composeHideBenign');
  assert.strictEqual(f('', false), '', 'toggle off, empty query untouched');
  assert.strictEqual(f('type:beacon', false), 'type:beacon', 'toggle off, query untouched');
  assert.strictEqual(f('', true), 'benign:false', 'toggle on, empty query gets the bare token');
  assert.strictEqual(f('type:beacon', true), '(type:beacon) AND benign:false');
  assert.strictEqual(
    f('severity:critical OR score:>=90', true),
    '(severity:critical OR score:>=90) AND benign:false',
    'OR queries must be parenthesized so AND does not rebind');
});
