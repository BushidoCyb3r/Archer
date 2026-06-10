'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { loadModule } = require('./load');

// Sandbox that captures setTimeout delays (without firing them) and fakes
// EventSource so onopen/onerror can be driven deterministically.
function makeSandbox() {
  const timers = []; // { fn, ms }
  const instances = [];
  function FakeES(url) {
    this.url = url;
    instances.push(this);
  }
  FakeES.prototype.addEventListener = function () {};
  FakeES.prototype.close = function () {};
  const sandbox = {
    EventSource: FakeES,
    setTimeout: (fn, ms) => {
      timers.push({ fn, ms });
      return timers.length;
    },
  };
  return { sandbox, timers, instances };
}

// Locks the reconnect backoff added to sse.js: a fixed-interval retry hammered
// a down server every 2s per tab; it now doubles from 1s to a 30s cap and
// resets on a clean open. This is the kind of pure control-flow logic that had
// no automated coverage before the harness existed.
test('SSE reconnect uses capped exponential backoff, reset on open', () => {
  const { sandbox, timers, instances } = makeSandbox();
  const SSE = loadModule('sse.js', 'SSE', sandbox);

  SSE.connect();
  assert.strictEqual(instances.length, 1, 'connect() opens one EventSource');

  const expected = [1000, 2000, 4000, 8000, 16000, 30000, 30000];
  for (let i = 0; i < expected.length; i++) {
    instances[instances.length - 1].onerror(); // connection drops
    assert.strictEqual(timers[i].ms, expected[i], `backoff step ${i}`);
    timers[i].fn(); // fire the scheduled reconnect → new EventSource
  }

  // A clean open resets the backoff to the base interval.
  instances[instances.length - 1].onopen();
  instances[instances.length - 1].onerror();
  assert.strictEqual(timers[expected.length].ms, 1000, 'backoff resets to 1s after a successful open');
});

test('SSE.on registers handlers that fire on emitted events', () => {
  const { sandbox, instances } = makeSandbox();
  const SSE = loadModule('sse.js', 'SSE', sandbox);

  let opened = 0;
  SSE.on('open', () => { opened++; });
  SSE.connect();
  instances[0].onopen();

  assert.strictEqual(opened, 1, 'on("open") handler fires when the stream opens');
});
