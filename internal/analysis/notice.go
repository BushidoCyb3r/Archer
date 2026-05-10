package analysis

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

// truncateRunes returns s capped at n runes (not bytes). Used by
// the notice truncator to keep the trailing ellipsis from landing
// inside a multi-byte UTF-8 character.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

func (a *Analyzer) analyzeNotice(files []string) {
	seen := make(map[[3]string]bool)

	noticeFiles := filterFiles(files, "notice")
	for _, f := range noticeFiles {
		a.parseLog(f, func(rec map[string]any) bool {
			src := parser.GetStr(rec, "id.orig_h")
			dst := parser.GetStr(rec, "id.resp_h")
			noteType := parser.GetStr(rec, "note")
			msg := parser.GetStr(rec, "msg")
			ts := parser.GetFloat(rec, "ts")

			if noteType == "" {
				return true
			}

			key := [3]string{src, dst, noteType}
			if seen[key] {
				return true
			}
			seen[key] = true

			noteTypeLow := strings.ToLower(noteType)
			score := 68
			sev := model.SevHigh
			if strings.Contains(noteTypeLow, "attack") ||
				strings.Contains(noteTypeLow, "scan") ||
				strings.Contains(noteTypeLow, "brute") ||
				strings.Contains(noteTypeLow, "sensitive") {
				score = 92
				sev = model.SevCritical
			}

			detail := fmt.Sprintf("Notice: %s", noteType)
			if msg != "" && msg != "-" {
				// Rune-aware truncation. Pre-fix `msg[:197]` could
				// land mid-multi-byte-character on UTF-8 input, and
				// the trailing ellipsis would produce invalid UTF-8.
				// Audit 2026-05-10. Iterate runes, cap at 197 of
				// them, append the ellipsis.
				if utf8.RuneCountInString(msg) > 200 {
					msg = truncateRunes(msg, 197) + "…"
				}
				detail += " | " + msg
			}

			a.add(model.Finding{
				Type:       "Zeek Notice",
				Severity:   sev,
				Score:      score,
				SrcIP:      src,
				DstIP:      dst,
				Detail:     detail,
				Timestamp:  fmtTS(ts),
				SourceFile: f,
			})
			return true
		})
	}
}
