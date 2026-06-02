package store

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestAddNoteIfAbsent_Idempotent is F-COR-3: TI enrichment notes re-fire
// across analysis runs — a new internal host first contacting an
// already-flagged dst is IsNew=true and re-enters the cross-note loop, so
// AddNote would stamp another identical "TI Enrichment — <dst>" note on
// every related finding, growing notes without bound. AddNoteIfAbsent
// collapses a repeat of the same (Author, Text) to a single note while a
// genuinely different note still appends.
func TestAddNoteIfAbsent_Idempotent(t *testing.T) {
	s := newTestStore(t)
	s.SetFindings([]model.Finding{{
		Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.9", DstPort: "443",
		Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-29 09:00:00",
	}})
	id := s.GetFindings()[0].ID

	note := model.Note{
		Text:        "TI Enrichment — 203.0.113.9\n  ⚠ [feed:x] bad",
		Author:      "TI Enrichment",
		AuthorEmail: "auto",
		Timestamp:   "2026-05-29 09:00:00",
	}

	found, added, err := s.AddNoteIfAbsent(id, note)
	if err != nil || !found || !added {
		t.Fatalf("first AddNoteIfAbsent: found=%v added=%v err=%v", found, added, err)
	}

	// Re-fire the identical enrichment on a later run (different Timestamp
	// must not defeat the dedup) — expected to be a no-op.
	repeat := note
	repeat.Timestamp = "2026-05-29 15:00:00"
	if _, added2, _ := s.AddNoteIfAbsent(id, repeat); added2 {
		t.Errorf("identical enrichment note appended a second time — notes accumulate")
	}

	// A distinct enrichment still lands.
	other := model.Note{
		Text:        "TI Enrichment — 198.51.100.1\n  ⚠ [feed:y] bad",
		Author:      "TI Enrichment",
		AuthorEmail: "auto",
	}
	if _, added3, _ := s.AddNoteIfAbsent(id, other); !added3 {
		t.Errorf("distinct enrichment note should append")
	}

	if got := len(s.GetFindings()[0].Notes); got != 2 {
		t.Fatalf("note count = %d, want 2 (one deduped)", got)
	}
}
