package analysis

import (
	"fmt"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

// checkFileHashes scans files.log for md5 / sha1 / sha256 hashes that
// match any enabled feed's Hashes bucket. Runs in Phase 3 alongside
// checkSuspiciousURLs and checkTI (depends on a.feedSources being
// populated by prefetchFeeds). One Threat Intel Hit per (src, hash)
// pair regardless of how many file rows carried the hash; the first
// matching row's filename / mime / hash-algorithm are captured for
// the finding's Detail.
//
// Hash matching is algorithm-agnostic on the analyzer side — the
// bucket combines md5 / sha1 / sha256 into one map, and each row's
// three hash columns are tested against it. A row with all three
// algorithms only fires once on the first match, since the
// fingerprint is the (src, hashvalue) pair.
func (a *Analyzer) checkFileHashes(files []string) {
	if !a.anyFeedHashes() {
		return
	}
	seen := make(map[[2]string]bool)
	for _, f := range filterFiles(files, "files") {
		_ = parser.ParseLog(f, func(rec map[string]any) bool {
			tx := strings.Trim(parser.GetStr(rec, "tx_hosts"), "[]\"")
			rx := strings.Trim(parser.GetStr(rec, "rx_hosts"), "[]\"")
			if tx == "" {
				tx = parser.GetStr(rec, "id.orig_h")
			}
			if rx == "" {
				rx = parser.GetStr(rec, "id.resp_h")
			}
			ts := parser.GetFloat(rec, "ts")
			filename := parser.GetStr(rec, "filename")
			mime := parser.GetStr(rec, "mime_type")

			candidates := []struct{ algo, val string }{
				{"md5", strings.ToLower(parser.GetStr(rec, "md5"))},
				{"sha1", strings.ToLower(parser.GetStr(rec, "sha1"))},
				{"sha256", strings.ToLower(parser.GetStr(rec, "sha256"))},
			}

			for _, c := range candidates {
				if c.val == "" {
					continue
				}
				for _, fs := range a.feedSources {
					if !fs.Hashes[c.val] {
						continue
					}
					// fingerprint by (downloader-side IP, hash) so
					// repeated downloads from the same host fire once
					key := [2]string{rx, c.val}
					if seen[key] {
						return true // skip remaining algos for this row
					}
					seen[key] = true
					feedName := strings.TrimPrefix(fs.Source, "feed:")
					detail := fmt.Sprintf("%s file-hash match: %s %s", feedName, c.algo, c.val)
					if filename != "" {
						detail += " | File: " + filename
					}
					if mime != "" {
						detail += " | MIME: " + mime
					}
					if tags := fs.Tags[c.val]; len(tags) > 0 {
						detail += " | tags: " + strings.Join(tags, ", ")
					}
					a.add(model.Finding{
						Type:       model.TypeTIHitHash,
						Severity:   model.SevHigh,
						Score:      90,
						SrcIP:      rx, // downloader is the src in our convention (matches Suspicious File Download)
						DstIP:      tx,
						Detail:     detail,
						Timestamp:  fmtTS(ts),
						SourceFile: fs.Source,
					})
					return true
				}
			}
			return true
		})
	}
}

// anyFeedHashes is the cheap early-exit guard for checkFileHashes.
// Mirrors anyFeedDomains in shape.
func (a *Analyzer) anyFeedHashes() bool {
	for _, fs := range a.feedSources {
		if len(fs.Hashes) > 0 {
			return true
		}
	}
	return false
}

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
