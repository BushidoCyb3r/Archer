package analysis

import (
	"fmt"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

func (a *Analyzer) analyzeFiles(files []string) {
	seen := make(map[[2]string]bool)

	fileFiles := filterFiles(files, "files")
	for _, f := range fileFiles {
		_ = parser.ParseLog(f, func(rec map[string]any) bool {
			src := parser.GetStr(rec, "tx_hosts")
			if src == "" {
				// tx_hosts might be an array
				src = parser.GetStr(rec, "id.orig_h")
			}
			dst := parser.GetStr(rec, "rx_hosts")
			mime := strings.ToLower(parser.GetStr(rec, "mime_type"))
			filename := parser.GetStr(rec, "filename")
			ts := parser.GetFloat(rec, "ts")

			// Clean up array-style fields like ["1.2.3.4"]
			src = strings.Trim(src, "[]\"")
			dst = strings.Trim(dst, "[]\"")

			if src == "" {
				return true
			}

			isSusp := false
			reason := ""

			for m := range model.SuspiciousMIMETypes {
				if strings.Contains(mime, m) {
					isSusp = true
					reason = fmt.Sprintf("MIME: %s", mime)
					break
				}
			}

			if !isSusp && filename != "" {
				for ext := range model.SuspiciousFileExts {
					if strings.HasSuffix(strings.ToLower(filename), ext) {
						isSusp = true
						reason = fmt.Sprintf("filename: %s", filename)
						break
					}
				}
			}

			if !isSusp {
				return true
			}

			key := [2]string{src, filename + mime}
			if !seen[key] {
				seen[key] = true
				detail := fmt.Sprintf("%s", reason)
				if filename != "" {
					detail += " | File: " + filename
				}
				a.add(model.Finding{
					Type:       "Suspicious File Download",
					Severity:   model.SevHigh,
					Score:      72,
					SrcIP:      dst,
					DstIP:      src,
					Detail:     detail,
					Timestamp:  fmtTS(ts),
					SourceFile: f,
				})
			}
			return true
		})
	}
}
