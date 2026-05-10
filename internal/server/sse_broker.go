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

// Broker fans out SSE events to all connected clients.
type Broker struct {
	mu      sync.Mutex
	clients map[chan SSEEvent]struct{}
}

func NewBroker() *Broker {
	return &Broker{clients: make(map[chan SSEEvent]struct{})}
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
	b.mu.Unlock()
}

func (b *Broker) Publish(evt SSEEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.clients {
		select {
		case ch <- evt:
		default:
		}
	}
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
	w.Header().Set("Access-Control-Allow-Origin", "*")

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
		case <-ticker.C:
			// Keep-alive comment — prevents proxies and browsers from closing idle connections
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
