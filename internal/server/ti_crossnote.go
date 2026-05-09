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
//
// Per-(dst, source) deduplication: checkTI's per-source fan-out emits N
// TI Hit findings per (dst, source) — one for each internal host that
// contacted the bad dst. Without this dedupe the cross-note loop would
// stamp N copies of the same enrichment note onto every related finding,
// since they all carry the same dst/source. We collapse the new-hits
// stream down to one entry per (dst, source) and use the first one's
// SourceFile/Detail/ID as the representative for the note text.
func (s *Server) crossAnnotateNewTIHits(findings []model.Finding) {
	type key struct{ dst, source string }
	rep := make(map[key]model.Finding)
	for _, h := range findings {
		if !h.IsNew || !model.IsThreatIntelType(h.Type) || h.Type == model.TypeSuspiciousURL {
			// Suspicious URL fires on http.host; the TI Hit (Domain) for the
			// same host already carries the enrichment, so skipping URL here
			// keeps the cross-annotation single-source.
			continue
		}
		k := key{dst: h.DstIP, source: h.SourceFile}
		if _, ok := rep[k]; !ok {
			rep[k] = h
		}
	}
	if len(rep) == 0 {
		return
	}

	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	all := s.store.GetFindings()
	skipTI := make(map[int]bool, len(all))
	for _, f := range all {
		if model.IsThreatIntelType(f.Type) {
			skipTI[f.ID] = true
		}
	}

	for _, h := range rep {
		note := model.Note{
			Text:        fmt.Sprintf("TI Enrichment — %s\n  ⚠ [%s] %s", h.DstIP, h.SourceFile, h.Detail),
			Author:      "TI Enrichment",
			AuthorEmail: "auto",
			Timestamp:   ts,
		}
		s.crossNoteByIP(h.DstIP, note, skipTI)
	}
}
