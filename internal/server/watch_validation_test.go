package server

import (
	"testing"
	"time"
)

// TestNextOccurrence_RejectsInvalidTime is F-COR-7: nextOccurrence and
// nextOccurrenceInterval must reject a malformed/out-of-range HH:MM rather
// than coerce it to h=0,m=0 and silently schedule the watch at 00:00. The
// validators returned (bool, error) where the error was always nil, and the
// schedulers guarded on the dead error instead of the validity bool. A
// persisted watch_time can reach these unchecked via DB restore, migration,
// or manual edit (the API path validates, the reload path does not).
func TestNextOccurrence_RejectsInvalidTime(t *testing.T) {
	bad := []string{"25:00", "12:60", "notatime", "1:2:3", "", "ab:cd", "-1:00", "07"}
	for _, b := range bad {
		if _, err := nextOccurrence(b, time.UTC); err == nil {
			t.Errorf("nextOccurrence(%q) returned nil error — invalid time coerced (would schedule 00:00)", b)
		}
		if _, err := nextOccurrenceInterval(b, 4, time.UTC); err == nil {
			t.Errorf("nextOccurrenceInterval(%q, 4) returned nil error — invalid time coerced", b)
		}
	}

	// Valid input still resolves to the right wall-clock time.
	next, err := nextOccurrence("02:30", time.UTC)
	if err != nil {
		t.Fatalf("nextOccurrence(02:30) errored: %v", err)
	}
	if next.Hour() != 2 || next.Minute() != 30 {
		t.Errorf("nextOccurrence(02:30) = %02d:%02d, want 02:30", next.Hour(), next.Minute())
	}
}
