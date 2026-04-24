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
		_ = parser.ParseLog(f, func(rec map[string]any) bool {
			src := parser.GetStr(rec, "id.orig_h")
			dst := parser.GetStr(rec, "id.resp_h")
			name := parser.GetStr(rec, "name")
			notice := parser.GetStr(rec, "notice")
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
			if notice != "" && notice != "-" {
				detail += " | " + notice
			}

			a.add(model.Finding{
				Type:      "Protocol Anomaly",
				Severity:  sev,
				Score:     score,
				SrcIP:     src,
				DstIP:     dst,
				Detail:    detail,
				Timestamp: fmtTS(ts),
			})
			return true
		})
	}
}
