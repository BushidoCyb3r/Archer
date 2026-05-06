package server

import (
	"fmt"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// crossNoteByIP attaches `note` to every persisted finding whose DstIP or
// SrcIP equals `ip`, except findings in `skipIDs`. Returns the number of
// findings touched. Filtering out the synthetic "(TI)" / "(network)" /
// "(escalation)" / "(cert)" / "—" placeholders keeps us from cross-noting
// findings that don't actually reference a real IP.
func (s *Server) crossNoteByIP(ip string, note model.Note, skipIDs map[int]bool) int {
	switch ip {
	case "", "—", "(TI)", "(network)", "(escalation)", "(cert)":
		return 0
	}
	all := s.store.GetFindings()
	n := 0
	for _, f := range all {
		if skipIDs[f.ID] {
			continue
		}
		if f.DstIP == ip || f.SrcIP == ip {
			if s.store.AddNote(f.ID, note) {
				n++
			}
		}
	}
	return n
}

// crossAnnotateNewTIHits attaches a system note to every existing finding
// that mentions an IP a freshly-detected automatic TI hit landed on. The
// IsNew filter dedupes across re-runs: once a fingerprint has been seen,
// SetFindings carries it forward as IsNew=false, so this won't pile on
// duplicate notes when the same TI hit re-detects on the next analysis tick.
//
// Skips the TI hit finding itself (which already carries the source/detail
// in its own row) and other Threat Intel Hit rows for the same IP (each
// already names its own source).
func (s *Server) crossAnnotateNewTIHits(findings []model.Finding) {
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	for _, h := range findings {
		if !h.IsNew || h.Type != "Threat Intel Hit" {
			continue
		}
		note := model.Note{
			Text:        fmt.Sprintf("TI Enrichment — %s\n  ⚠ [%s] %s", h.DstIP, h.SourceFile, h.Detail),
			Author:      "TI Enrichment",
			AuthorEmail: "auto",
			Timestamp:   ts,
		}
		skip := map[int]bool{h.ID: true}
		all := s.store.GetFindings()
		for _, f := range all {
			if f.Type == "Threat Intel Hit" {
				skip[f.ID] = true
			}
		}
		s.crossNoteByIP(h.DstIP, note, skip)
	}
}
