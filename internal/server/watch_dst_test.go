package server

import (
	"testing"
	"time"
)

// TestNextDailyFrom_DSTSpringForward is the LG-7 regression. Rolling the daily
// watch time to tomorrow with Add(24h) lands an hour off on a DST-transition
// day, because that day isn't 24 absolute hours long. On the US spring-forward
// (2026-03-08, clocks jump 02:00→03:00, so the day is 23h), a 03:00 watch
// whose slot has already passed today must next fire at 03:00 *wall-clock*
// tomorrow — not 04:00, which a flat 24h add produces.
func TestNextDailyFrom_DSTSpringForward(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tz database unavailable: %v", err)
	}

	// now is 04:00 on the day before the transition; the 03:00 slot has passed.
	now := time.Date(2026, 3, 7, 4, 0, 0, 0, ny)
	got := nextDailyFrom(now, 3, 0, ny)

	if got.Day() != 8 || got.Hour() != 3 || got.Minute() != 0 {
		t.Errorf("nextDailyFrom across spring-forward = %s; want 2026-03-08 03:00 wall-clock (Add(24h) would give 04:00)", got.Format("2006-01-02 15:04 MST"))
	}

	// Sanity: on an ordinary day the next slot is simply tomorrow at HH:MM.
	plain := time.Date(2026, 6, 1, 12, 0, 0, 0, ny)
	if n := nextDailyFrom(plain, 9, 30, ny); n.Day() != 2 || n.Hour() != 9 || n.Minute() != 30 {
		t.Errorf("nextDailyFrom ordinary day = %s; want 2026-06-02 09:30", n.Format("2006-01-02 15:04"))
	}

	// And when today's slot is still ahead, it fires today.
	if n := nextDailyFrom(plain, 18, 0, ny); n.Day() != 1 || n.Hour() != 18 {
		t.Errorf("nextDailyFrom future-slot-today = %s; want 2026-06-01 18:00", n.Format("2006-01-02 15:04"))
	}
}
