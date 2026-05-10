package analysis

import (
	"fmt"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

var highInterestWeird = map[string]bool{
	"bad_HTTP_request":              true,
	"malformed_ssh_identification":  true,
	"RST_with_data":                 true,
	"inappropriate_FIN":             true,
	"DNS_label_too_long":            true,
	"above_hole_data_without_state": true,
	"unsolicited_SYN_response":      true,
}

func (a *Analyzer) analyzeWeird(files []string) {
	seen := make(map[[3]string]bool)

	weirdFiles := filterFiles(files, "weird")
	for _, f := range weirdFiles {
		a.parseLog(f, func(rec map[string]any) bool {
			src := parser.GetStr(rec, "id.orig_h")
			dst := parser.GetStr(rec, "id.resp_h")
			name := parser.GetStr(rec, "name")
			// Zeek's weird.notice field is bool. GetStr produces
			// "true"/"false" by way of json.Marshal on the
			// underlying bool, so the previous detail-line
			// concatenation appended literal "true" or "false"
			// regardless of value, producing "Zeek weird: x | true"
			// for any record (since "false" != "" && != "-"). Use
			// GetBool and only annotate the genuinely-noticed
			// weirds. Audit 2026-05-10 LOW.
			noticed := parser.GetBool(rec, "notice")
			ts := parser.GetFloat(rec, "ts")

			if name == "" {
				return true
			}

			key := [3]string{src, dst, name}
			if seen[key] {
				return true
			}
			seen[key] = true

			score := 22
			sev := model.SevLow
			if highInterestWeird[name] {
				score = 65
				sev = model.SevMedium
			}

			detail := fmt.Sprintf("Zeek weird: %s", name)
			if noticed {
				detail += " (also notice)"
			}

			a.add(model.Finding{
				Type:       "Protocol Anomaly",
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
