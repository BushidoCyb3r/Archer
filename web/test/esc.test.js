'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { extractFn } = require('./load');

// Behavioral test of the canonical _esc HTML escaper (table.js copy). The
// Go-side web_esc_consistency_test.go asserts every SPA module's _esc is
// PRESENT and escapes the five-char set; this asserts what it actually does,
// so a regression in the replacement map or the regex is caught — _esc is the
// SPA's single XSS defense over attacker-controlled Zeek fields.
test('_esc escapes the five HTML-significant characters', () => {
  const esc = extractFn('table.js', '_esc');

  assert.strictEqual(esc('&'), '&amp;');
  assert.strictEqual(esc('<'), '&lt;');
  assert.strictEqual(esc('>'), '&gt;');
  assert.strictEqual(esc('"'), '&quot;');
  assert.strictEqual(esc("'"), '&#39;');

  assert.strictEqual(
    esc('<script>alert("x")</script>'),
    '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;',
    'a full injection payload is fully neutralized'
  );

  assert.strictEqual(esc(null), '', 'null → empty string, never the literal "null"');
  assert.strictEqual(esc(undefined), '', 'undefined → empty string');
  assert.strictEqual(esc(42), '42', 'non-strings are coerced to string');
  assert.strictEqual(esc('plain text'), 'plain text', 'safe input is unchanged');
});
