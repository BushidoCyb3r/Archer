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
		a.parseLog(f, func(rec map[string]any) bool {
			tx := firstAddr(parser.GetStr(rec, "tx_hosts"))
			if tx == "" {
				tx = parser.GetStr(rec, "id.orig_h")
			}
			rx := firstAddr(parser.GetStr(rec, "rx_hosts"))
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

// firstAddr extracts the first address from a Zeek set[addr] field as
// GetStr hands it back: a JSON-log array (`["a","b"]`) or a TSV comma-set
// (`a,b`). Returns "" for an empty set (`[]`). The previous
// strings.Trim(s,"[]\"") mishandled both empty arrays (left "[]" looking
// non-empty until a late trim blanked it) and multi-element arrays (left
// the inter-element `","` as garbage in the address).
func firstAddr(s string) string {
	s = strings.Trim(s, "[]")
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	return strings.Trim(s, "\" ")
}

func (a *Analyzer) analyzeFiles(files []string) {
	// Variable naming previously made the dedup-key bug invisible:
	// `src` held the *sender* (tx_hosts) but the finding's SrcIP was
	// the *receiver* (the downloader). Audit 2026-05-10 NEW-2 caught
	// that the dedup key used `src` (sender), so 100 internal hosts
	// downloading the same file from one external sender collapsed to
	// one finding. Renamed to sender/receiver and the dedup key now
	// includes the receiver, so each victim of a drive-by gets its
	// own finding.
	seen := make(map[[2]string]bool)

	fileFiles := filterFiles(files, "files")
	for _, f := range fileFiles {
		a.parseLog(f, func(rec map[string]any) bool {
			// Trim the set[addr] field first, then fall back — mirrors
			// checkFileHashes. Testing emptiness on the raw GetStr value
			// missed `[]` (GetStr hands back the literal "[]"), so the
			// id.orig_h fallback never fired and the record was dropped.
			sender := firstAddr(parser.GetStr(rec, "tx_hosts"))
			if sender == "" {
				sender = parser.GetStr(rec, "id.orig_h")
			}
			receiver := firstAddr(parser.GetStr(rec, "rx_hosts"))
			if receiver == "" {
				receiver = parser.GetStr(rec, "id.resp_h")
			}
			mime := strings.ToLower(parser.GetStr(rec, "mime_type"))
			filename := parser.GetStr(rec, "filename")
			ts := parser.GetFloat(rec, "ts")

			if sender == "" {
				return true
			}

			isSusp := false
			reason := ""

			for m := range SuspiciousMIMETypes {
				if strings.Contains(mime, m) {
					isSusp = true
					reason = fmt.Sprintf("MIME: %s", mime)
					break
				}
			}

			if !isSusp && filename != "" {
				for ext := range SuspiciousFileExts {
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

			// Dedup by (receiver, file) — one finding per victim per
			// (filename + mime). Multiple internal victims of the same
			// drive-by each get their own finding; repeated downloads
			// of the same file by the same victim collapse to one.
			// Mirrors checkFileHashes' (rx, hash) keying convention.
			key := [2]string{receiver, filename + mime}
			if !seen[key] {
				seen[key] = true
				detail := reason
				if filename != "" {
					detail += " | File: " + filename
				}
				a.add(model.Finding{
					Type:       "Suspicious File Download",
					Severity:   model.SevHigh,
					Score:      72,
					SrcIP:      receiver, // downloader is the SrcIP per our convention
					DstIP:      sender,
					Detail:     detail,
					Timestamp:  fmtTS(ts),
					SourceFile: f,
				})
			}
			return true
		})
	}
}
