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
