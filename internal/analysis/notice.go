package analysis

import (
	"fmt"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

func (a *Analyzer) analyzeNotice(files []string) {
	seen := make(map[[3]string]bool)

	noticeFiles := filterFiles(files, "notice")
	for _, f := range noticeFiles {
		_ = parser.ParseLog(f, func(rec map[string]any) bool {
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
				if len(msg) > 200 {
					msg = msg[:197] + "…"
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
