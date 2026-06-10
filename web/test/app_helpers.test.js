'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { extractFn } = require('./load');

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
