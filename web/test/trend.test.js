'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { extractFn } = require('./load');

// _idxFor is the hit-testing core the trend chart's brush zoom and hover
// tooltip both stand on: a canvas x maps to the NEAREST day index, clamped
// to the rendered range. A drift here makes "Apply as filter" filter to the
// wrong dates — the silent-wrong-answer class, worse than a crash.
test('_idxFor maps canvas x to the nearest day index with clamping', () => {
  const f = extractFn('trend.js', '_idxFor');
  // plot: i0=0, n=5 days, padLeft=46, plotW=400 → points at x=46,146,246,346,446
  assert.strictEqual(f(46, 0, 5, 46, 400), 0, 'first point');
  assert.strictEqual(f(446, 0, 5, 46, 400), 4, 'last point');
  assert.strictEqual(f(146, 0, 5, 46, 400), 1, 'interior point');
  assert.strictEqual(f(195, 0, 5, 46, 400), 1, 'left of midpoint rounds down');
  assert.strictEqual(f(197, 0, 5, 46, 400), 2, 'right of midpoint rounds up');
  assert.strictEqual(f(0, 0, 5, 46, 400), 0, 'left of plot clamps to first');
  assert.strictEqual(f(9999, 0, 5, 46, 400), 4, 'right of plot clamps to last');
  // Zoomed range: indices offset by i0, same geometry
  assert.strictEqual(f(46, 10, 5, 46, 400), 10, 'zoomed first');
  assert.strictEqual(f(446, 10, 5, 46, 400), 14, 'zoomed last');
  assert.strictEqual(f(0, 10, 5, 46, 400), 10, 'zoomed clamp low');
  // Single-day span has no x scale — everything is that day
  assert.strictEqual(f(123, 7, 1, 46, 400), 7, 'n=1 always maps to i0');
});

// _yMaxFor scales the y axis to the visible series within the zoom range.
// Toggled-off series must not inflate the axis, out-of-zoom days must not
// either, and an all-zero view must still yield a drawable (non-zero) axis.
test('_yMaxFor scopes the axis to visible series and zoom range', () => {
  const f = extractFn('trend.js', '_yMaxFor');
  const series = [
    { key: 'beaconing', counts: [1, 9, 2, 0] },
    { key: 'ti', counts: [0, 0, 50, 3] },
  ];
  assert.strictEqual(f(series, 0, 3), 50, 'full range, all series');
  assert.strictEqual(f([series[0]], 0, 3), 9, 'toggled-off series excluded');
  assert.strictEqual(f(series, 0, 1), 9, 'zoom excludes the off-range spike');
  assert.strictEqual(f(series, 3, 3), 3, 'single-day zoom');
  assert.strictEqual(f([], 0, 3), 1, 'no visible series → axis floor of 1');
  assert.strictEqual(f([{ key: 'x', counts: [0, 0] }], 0, 1), 1, 'all-zero → floor of 1');
});
