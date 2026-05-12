package server

import "time"

// Watch heartbeat — a small periodic SSE event that lets the UI
// distinguish "watch is healthy and quiet" from "watch is dead and
// quiet." Both look the same from the browser's perspective until
// you wait long enough for an event that never arrives.
//
// The event ticks unconditionally every watchHeartbeatInterval and
// carries an empty JSON object as payload. The frontend treats
// absence of the event for more than watchHeartbeatStaleThresholdMS
// (3 consecutive ticks at 60s = 180s) as a signal that the server
// or broker is wedged, regardless of watch config — if watch is
// disabled the heartbeat still ticks (it proves the SSE pipe is
// alive, which an operator wants to know even when they're not
// running scheduled analysis).
//
// Pattern matches the other startXxxLoop methods: goroutine outlives
// the call; process shutdown is the only termination.

const watchHeartbeatInterval = 60 * time.Second

func (s *Server) startWatchHeartbeatLoop() {
	go func() {
		// Don't fire immediately at boot — the SSE broker may have
		// zero subscribers in the first second or two before the
		// browser reconnects. The first tick happens after one full
		// interval, by which time the UI has had time to wire up
		// its listeners. The next-tick logic in the broker is
		// graceful about zero subscribers anyway, but the cleaner
		// shape is "no event fires before there's anyone listening."
		t := time.NewTicker(watchHeartbeatInterval)
		defer t.Stop()
		for range t.C {
			s.broker.Publish(SSEEvent{Type: "watch.heartbeat", Data: "{}"})
		}
	}()
}
