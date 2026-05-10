package server

import (
	"testing"
)

// TestBrokerPublish_OverflowEmitsResyncRequired covers the NEW-29 fix:
// pre-fix a slow consumer's full buffer caused Publish to silently
// drop events; post-fix the broker drains the channel and emits a
// single resync_required canary, then no-ops further publishes until
// ServeHTTP drains the canary and clears the overflow flag.
func TestBrokerPublish_OverflowEmitsResyncRequired(t *testing.T) {
	b := NewBroker()
	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	// Fill the buffer (cap 32) plus one more to force overflow.
	for i := 0; i < 35; i++ {
		b.Publish(SSEEvent{Type: "notification", Data: "{}"})
	}

	// Drain everything in the buffer. The first events are the
	// originals that got in before overflow; somewhere in there
	// (or as the final entry) is a resync_required canary.
	got := []SSEEvent{}
	for {
		select {
		case evt := <-ch:
			got = append(got, evt)
		default:
			goto drained
		}
	}
drained:
	if len(got) == 0 {
		t.Fatal("no events received; buffer was empty")
	}
	// The last event must be resync_required — the broker drained
	// the channel before posting the canary, so resync_required is
	// the FIRST thing the consumer reads.
	first := got[0]
	if first.Type != "resync_required" {
		t.Errorf("first drained event type = %q; want resync_required", first.Type)
	}
}

// TestBrokerPublish_NoOpAfterOverflow asserts the overflow flag
// suppresses further publishes until ServeHTTP-equivalent drain
// clears it. Otherwise a continuous storm of new events would
// keep the channel pinned and the consumer would never see the
// resync.
func TestBrokerPublish_NoOpAfterOverflow(t *testing.T) {
	b := NewBroker()
	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	// Fill the buffer + force overflow.
	for i := 0; i < 35; i++ {
		b.Publish(SSEEvent{Type: "notification", Data: "{}"})
	}

	// At this point the channel holds exactly one event:
	// resync_required (the original 32 were drained).
	// Publish more — they should NOT enqueue.
	for i := 0; i < 10; i++ {
		b.Publish(SSEEvent{Type: "notification", Data: `{"i":1}`})
	}

	// Drain. We should see exactly one event (the canary), nothing
	// else.
	count := 0
	for {
		select {
		case <-ch:
			count++
		default:
			goto done
		}
	}
done:
	if count != 1 {
		t.Errorf("post-overflow Publish enqueued %d events; want 1 (only the canary)", count)
	}

	// Now simulate ServeHTTP clearing the overflow flag. New
	// publishes should resume normally.
	b.clearOverflow(ch)
	b.Publish(SSEEvent{Type: "notification", Data: "{}"})
	select {
	case evt := <-ch:
		if evt.Type != "notification" {
			t.Errorf("post-clear event type = %q; want notification", evt.Type)
		}
	default:
		t.Error("post-clearOverflow Publish did not enqueue")
	}
}

// TestBrokerPublish_NoOverflowOnHealthyConsumer is the negative
// case — a consumer that drains fast enough never gets a
// resync_required canary.
func TestBrokerPublish_NoOverflowOnHealthyConsumer(t *testing.T) {
	b := NewBroker()
	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	for i := 0; i < 200; i++ {
		b.Publish(SSEEvent{Type: "notification", Data: "{}"})
		// Drain immediately to simulate a healthy consumer.
		<-ch
	}

	// Channel should be empty; no canary.
	select {
	case evt := <-ch:
		t.Errorf("unexpected event after drain: %+v", evt)
	default:
	}
}
