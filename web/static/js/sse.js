// sse.js — SSE connection manager with auto-reconnect
'use strict';

const SSE = (() => {
  let _es = null;
  const _handlers = {};

  function on(type, fn) {
    if (!_handlers[type]) _handlers[type] = [];
    _handlers[type].push(fn);
  }

  function _emit(type, data) {
    (_handlers[type] || []).forEach(fn => fn(data));
  }

  function _attachListeners(es) {
    ['progress', 'done', 'notification', 'status', 'ti_result', 'ti_done', 'unauthorized_attempt', 'sensor_enrolled', 'resync_required', 'watch.heartbeat'].forEach(type => {
      es.addEventListener(type, e => {
        try { _emit(type, JSON.parse(e.data)); } catch(err) { console.error('SSE parse error:', type, err); }
      });
    });
  }

  function connect() {
    if (_es) return;
    _es = new EventSource('/events');
    _attachListeners(_es);

    _es.onopen  = () => _emit('open', {});
    _es.onerror = () => {
      _emit('error', {});
      const old = _es;
      _es = null;
      old.close();
      setTimeout(connect, 2000);
    };
  }

  return { on, connect };
})();
