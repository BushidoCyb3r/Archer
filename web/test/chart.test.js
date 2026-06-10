'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { extractFn } = require('./load');

// _bucketAt maps a logical canvas x to a histogram bucket index, -1 outside
// the plot. This is the hit-testing core for the Intervals/Bytes tooltips.
test('_bucketAt maps canvas x to bucket index with bounds', () => {
  const bucketAt = extractFn('chart.js', '_bucketAt');
  // plot: padLeft=72, plotW=400, 40 buckets → 10px per bucket
  assert.strictEqual(bucketAt(72, 72, 400, 40), 0);
  assert.strictEqual(bucketAt(81.9, 72, 400, 40), 0);
  assert.strictEqual(bucketAt(82, 72, 400, 40), 1);
  assert.strictEqual(bucketAt(471.9, 72, 400, 40), 39);
  assert.strictEqual(bucketAt(71, 72, 400, 40), -1, 'left of plot');
  assert.strictEqual(bucketAt(472, 72, 400, 40), -1, 'right of plot');
});

// _xTickCount returns the tick interval count (the draw loop renders n+1 labels, one per ~90px), clamped to a sane range.
test('_xTickCount scales with plot width and clamps to [3,8]', () => {
  const tc = extractFn('chart.js', '_xTickCount');
  assert.strictEqual(tc(180), 3, 'narrow plots clamp up to 3');
  assert.strictEqual(tc(450), 5);
  assert.strictEqual(tc(2000), 8, 'wide plots clamp down to 8');
});
