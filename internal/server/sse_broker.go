package server

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SSEEvent is a Server-Sent Event with a type and JSON data payload.
type SSEEvent struct {
	Type string
	Data string
}

// resyncRequiredEvent is the canary the broker substitutes when a
// client's buffer is full. The browser-side handler reacts by re-
// fetching /api/findings and /api/notifications — the source-of-
// truth endpoints that the dropped events would have updated. Pre-
// fix overflow was a silent drop; for a security tool whose live
// channel includes new TI hits, unauthorized sensor attempts, and
// CRITICAL findings, "all quiet" while actually missing alerts is
// a meaningful information-loss bug. Audit 2026-05-10 NEW-29.
var resyncRequiredEvent = SSEEvent{Type: "resync_required", Data: "{}"}

// Broker fans out SSE events to all connected clients.
type Broker struct {
	mu      sync.Mutex
	clients map[chan SSEEvent]struct{}
	// Per-client overflow flag. Set when Publish couldn't enqueue an
	// event because the buffer was full; cleared the moment ServeHTTP
	// drains a resync_required from the channel. While the flag is
	// set, subsequent Publish calls to that client are no-ops — there
	// would be no point queuing more events when the consumer's
	// already going to re-fetch from scratch. Mutex-protected because
	// Publish and ServeHTTP touch it from different goroutines.
	overflow map[chan SSEEvent]bool
}

func NewBroker() *Broker {
	return &Broker{
		clients:  make(map[chan SSEEvent]struct{}),
		overflow: make(map[chan SSEEvent]bool),
	}
}

func (b *Broker) Subscribe() chan SSEEvent {
	ch := make(chan SSEEvent, 32)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *Broker) Unsubscribe(ch chan SSEEvent) {
	b.mu.Lock()
	delete(b.clients, ch)
	delete(b.overflow, ch)
	b.mu.Unlock()
}

func (b *Broker) Publish(evt SSEEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.clients {
		// If this client is already in overflow, don't pile more
		// events on top of an already-stale channel — the
		// resync_required is still pending in their buffer and
		// they'll re-fetch when ServeHTTP drains it.
		if b.overflow[ch] {
			continue
		}
		select {
		case ch <- evt:
		default:
			// Buffer full. Drain everything we can without blocking
			// (the goroutine reading the channel is the only other
			// writer, so this is safe under the mutex), then drop a
			// single resync_required canary in. The drain is bounded
			// by the channel cap so this can't loop forever.
			drainChannel(ch)
			select {
			case ch <- resyncRequiredEvent:
				b.overflow[ch] = true
			default:
				// Even the canary couldn't go in — extremely rare
				// (would mean a parallel consumer is pulling and
				// pushing in the same instant). Mark overflow
				// anyway so the next Publish skips this client and
				// the consumer's next read picks up from a
				// definitely-stale state.
				b.overflow[ch] = true
			}
		}
	}
}

// drainChannel non-blockingly empties the channel buffer. Caller
// must hold b.mu — the broker's mutex serializes all writes to the
// channel, so under the lock there's no producer racing us.
func drainChannel(ch chan SSEEvent) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// clearOverflow flips the flag back off once ServeHTTP has consumed
// the resync_required canary. Subsequent Publish calls resume queuing
// real events into this client's buffer.
func (b *Broker) clearOverflow(ch chan SSEEvent) {
	b.mu.Lock()
	delete(b.overflow, ch)
	b.mu.Unlock()
}

// ServeHTTP handles the /events SSE endpoint.
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	// Pre-v0.14.8 this site set Access-Control-Allow-Origin: * —
	// vestigial from an early experiment. The SPA is same-origin
	// (served by the same Archer process) so CORS isn't needed,
	// and the header on review raised the "is this endpoint
	// meant to be public?" question. Archer doesn't set
	// Access-Control-Allow-Credentials, so cross-origin
	// EventSource attempts from a malicious page couldn't carry
	// the session cookie regardless — the header was just
	// confusing review noise. Removed entirely. v0.14.8 NEW-62.

	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case evt := <-ch:
			// SSE delimits records with "\n\n", so a literal newline
			// inside Data would prematurely terminate the event and
			// the rest of the payload would be parsed as a free-form
			// continuation by the browser. The spec's escape hatch is
			// "one data: prefix per line" — JSON serializers don't
			// emit interior newlines today, but operator-supplied
			// strings (notes, error messages from third-party feeds)
			// can leak them in via unrelated codepaths. Audit
			// 2026-05-10 LOW.
			fmt.Fprintf(w, "event: %s\n", evt.Type)
			for _, line := range strings.Split(evt.Data, "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprint(w, "\n")
			flusher.Flush()
			// If we just delivered the resync_required canary, the
			// client is about to re-fetch the source-of-truth
			// endpoints, so flip the overflow flag off so subsequent
			// Publish calls resume normal queueing. Audit 2026-05-10
			// NEW-29.
			if evt.Type == "resync_required" {
				b.clearOverflow(ch)
			}
		case <-ticker.C:
			// Keep-alive comment — prevents proxies and browsers from closing idle connections
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
