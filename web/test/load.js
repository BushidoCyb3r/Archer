'use strict';
//
// load.js — the JS test harness for Archer's vanilla-JS SPA modules.
//
// The SPA modules in web/static/js are browser IIFEs loaded by ordered
// <script> tags: `const Name = (() => { ... })();`. They have no build step
// and no module.exports — they're not written to be require()'d. This loader
// lets `node --test` exercise them anyway, with ZERO changes to the
// production files, two ways:
//
//   loadModule(file, exportName, sandbox)
//     Evaluates a whole module in a vm sandbox (you supply the browser
//     globals it touches — window, document, EventSource, setTimeout, …) and
//     returns the global object the IIFE assigns. Use this to drive a
//     module's public API. See sse.test.js.
//
//   extractFn(file, fnName)
//     Pulls a single `function NAME(...) {...}` out of a module's source by
//     string-aware brace matching and evaluates it standalone. Use this to
//     behaviorally test a pure IIFE-private helper (e.g. the _esc escaper)
//     without a DOM. See esc.test.js. The Go-side consistency tests assert a
//     helper is PRESENT and shaped right across modules; this asserts what it
//     actually DOES.
//
// Run:  node --test web/test/
//
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const JSDIR = path.join(__dirname, '..', 'static', 'js');

function loadModule(file, exportName, sandbox = {}) {
  const src = fs.readFileSync(path.join(JSDIR, file), 'utf8');
  const ctx = vm.createContext(Object.assign({ console }, sandbox));
  // `const Name` is script-scoped, not a global property, so append a capture
  // line in the same script to read the binding out into the context object.
  vm.runInContext(src + `\n;globalThis.__exports = ${exportName};`, ctx, { filename: file });
  return ctx.__exports;
}

function extractFn(file, fnName) {
  const lines = fs.readFileSync(path.join(JSDIR, file), 'utf8').split('\n');
  // These IIFE-member functions are indented two spaces and close with a `}`
  // at that same indent. Slice on indentation rather than brace-counting:
  // brace-counting the raw source is fooled by regex literals like
  // /[&<>"']/ whose quote characters desync any string-skipping logic, and a
  // full JS lexer is overkill. The modules' consistent indentation is the
  // reliable boundary.
  const startRe = new RegExp(`^(\\s*)function ${fnName}\\b`);
  let start = -1;
  let indent = '';
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(startRe);
    if (m) { start = i; indent = m[1]; break; }
  }
  if (start < 0) throw new Error(`${fnName} not found in ${file}`);
  const closeRe = new RegExp(`^${indent}}`);
  let end = -1;
  for (let i = start + 1; i < lines.length; i++) {
    if (closeRe.test(lines[i])) { end = i; break; }
  }
  if (end < 0) throw new Error(`no matching close for ${fnName} in ${file}`);
  return vm.runInNewContext('(' + lines.slice(start, end + 1).join('\n') + ')');
}

module.exports = { loadModule, extractFn };
