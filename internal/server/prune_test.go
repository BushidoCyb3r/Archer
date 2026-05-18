package server

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestStartPruneLoop_RunsAtBootThenTicks codifies the invariant the
// consolidation (NEW-95 / TODO §1b) must preserve: every loop it
// replaced ran fn once immediately at startup *and* again on every
// interval tick. A regression that drops the boot run (so a
// long-stopped instance waits a full interval before its first sweep)
// or the ticking fails here.
func TestStartPruneLoop_RunsAtBootThenTicks(t *testing.T) {
	var n int64
	startPruneLoop("test", 15*time.Millisecond, func() {
		atomic.AddInt64(&n, 1)
	})

	// Boot run must land effectively immediately (well before one
	// interval elapses) — assert it within a window shorter than the
	// tick so we're proving the at-boot call, not a tick.
	deadline := time.Now().Add(10 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&n) >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got := atomic.LoadInt64(&n); got < 1 {
		t.Fatalf("fn did not run at boot within 10ms (count=%d)", got)
	}

	// Then it must keep ticking: wait for several more invocations.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&n) >= 4 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("fn stopped ticking: count=%d, want >=4", atomic.LoadInt64(&n))
}
