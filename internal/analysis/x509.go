package analysis

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

// parseZeekCertTime accepts both wire formats Zeek produces for the
// certificate.not_valid_before / not_valid_after fields. Default Zeek
// JSON output emits the Zeek `time` type as a Unix-epoch float
// ("1700000000.0"); RFC3339 strings appear in some user-customised
// configurations and in our hand-written fixtures pre-NEW-20. Pre-fix
// the analyzer only handled RFC3339, so on real Zeek output both
// time.Parse calls failed and the entire validity-window check (short
// validity for short-lived attacker certs, validity > 10 years for
// self-signed CAs that never rotate) was silently dead. The bug was
// invisible because the golden fixture happened to match the parser's
// wrong expectation rather than upstream's actual behavior — the same
// fixture-vs-reality drift the audit (NEW-24) called out as a class
// failure mode. Audit 2026-05-10 NEW-20.
func parseZeekCertTime(v string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, false
	}
	// Float-as-string is the default Zeek encoding; try it first
	// because it's the production-common path.
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		secs := int64(f)
		nanos := int64((f - float64(secs)) * 1e9)
		return time.Unix(secs, nanos).UTC(), true
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

func (a *Analyzer) analyzeX509(files []string) {
	seen := make(map[[2]string]bool)

	x509Files := filterFiles(files, "x509")
	for _, f := range x509Files {
		a.parseLog(f, func(rec map[string]any) bool {
			subject := parser.GetStr(rec, "certificate.subject")
			issuer := parser.GetStr(rec, "certificate.issuer")
			notBefore := parser.GetStr(rec, "certificate.not_valid_before")
			notAfter := parser.GetStr(rec, "certificate.not_valid_after")
			ts := parser.GetFloat(rec, "ts")

			if subject == "" && issuer == "" {
				return true
			}

			subjectLow := strings.ToLower(subject)
			issuerLow := strings.ToLower(issuer)

			var reasons []string

			// Self-signed
			if subject != "" && issuer != "" && subjectLow == issuerLow {
				reasons = append(reasons, "self-signed (subject==issuer)")
			}

			// Default/generic subject strings
			for _, def := range DefaultCertSubjects {
				if strings.Contains(subjectLow, def) {
					reasons = append(reasons, fmt.Sprintf("default subject (%q)", def))
					break
				}
			}

			// Validity window checks
			if notBefore != "" && notAfter != "" {
				nbf, ok1 := parseZeekCertTime(notBefore)
				nat, ok2 := parseZeekCertTime(notAfter)
				if ok1 && ok2 {
					validity := nat.Sub(nbf)
					if validity < 48*time.Hour {
						reasons = append(reasons, fmt.Sprintf("short validity (%.0fh)", validity.Hours()))
					} else if validity > 10*365*24*time.Hour {
						reasons = append(reasons, "validity > 10 years")
					}
				}
			}

			if len(reasons) == 0 {
				return true
			}

			key := [2]string{subject, issuer}
			if !seen[key] {
				seen[key] = true
				a.add(model.Finding{
					Type:       "Suspicious Certificate",
					Severity:   model.SevMedium,
					Score:      58,
					SrcIP:      "(cert)",
					DstIP:      subject,
					Detail:     fmt.Sprintf("Subject: %s | Issuer: %s | Indicators: %s", subject, issuer, strings.Join(reasons, ", ")),
					Timestamp:  fmtTS(ts),
					SourceFile: f,
				})
			}
			return true
		})
	}
}
