# SPA test harness

Dependency-free unit tests for the vanilla-JS SPA modules in `web/static/js`.

```sh
node --test web/test/*.test.js
```

Requires Node ≥ 18 (for the built-in `node:test` runner). **No npm, no
package.json, no build step** — matching the SPA itself, which ships as plain
`<script>` tags. CI runs this as the `js-test` job on every push/PR.

## Why a harness is needed

The SPA modules are browser IIFEs: `const Name = (() => { ... })();`. They have
no `module.exports`, so Node can't `require()` them directly. `load.js` bridges
that with **zero changes to the production files**, two ways:

- **`loadModule(file, exportName, sandbox)`** — evaluates a whole module in a
  `vm` sandbox (you supply the browser globals it touches: `window`,
  `document`, `EventSource`, `setTimeout`, …) and returns the global the IIFE
  assigns. Use it to drive a module's public API. Example: `sse.test.js` stubs
  `EventSource`/`setTimeout` and asserts the reconnect backoff.

- **`extractFn(file, fnName)`** — slices a single `function NAME(...) {...}` out
  of the source by its (consistent two-space) indentation and evaluates it
  standalone. Use it to behaviorally test a pure IIFE-private helper without a
  DOM. Example: `esc.test.js` tests the `_esc` HTML escaper's output.

## Relationship to the Go-side meta-tests

`internal/server/web_esc_consistency_test.go`, `web_api_consistency_test.go`,
and `sse_catalog_consistency_test.go` assert cross-module/cross-language
*consistency* by scanning the JS as text (every `_esc` is present and shaped
right; the SSE event list matches the server). These JS tests are the
complement: they assert *runtime behavior* of the code those meta-tests only
check for presence. Keep both.

## Extending

- **A module that touches the DOM at eval time** needs a DOM stub in its
  `sandbox` (provide just the `document`/`element` methods the module calls —
  build it up minimally, don't pull in jsdom). `app.js` and `table.js` are the
  large DOM-coupled modules; their pure helpers are the high-value targets once
  a small shared DOM stub exists.
- **A pure helper buried in a closure** is reachable via `extractFn` as long as
  it's a top-level `function` in the module at a consistent indent.
- Name new files `*.test.js` so the `web/test/*.test.js` glob picks them up;
  `load.js` is the harness, not a test, and is intentionally excluded.
