package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

func (a *Analyzer) analyzeX509(files []string) {
	seen := make(map[[2]string]bool)

	x509Files := filterFiles(files, "x509")
	for _, f := range x509Files {
		_ = parser.ParseLog(f, func(rec map[string]any) bool {
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
			for _, def := range model.DefaultCertSubjects {
				if strings.Contains(subjectLow, def) {
					reasons = append(reasons, fmt.Sprintf("default subject (%q)", def))
					break
				}
			}

			// Validity window checks
			if notBefore != "" && notAfter != "" {
				nbf, err1 := time.Parse(time.RFC3339, notBefore)
				nat, err2 := time.Parse(time.RFC3339, notAfter)
				if err1 == nil && err2 == nil {
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
					Type:      "Suspicious Certificate",
					Severity:  model.SevMedium,
					Score:     58,
					SrcIP:     "(cert)",
					DstIP:     subject,
					Detail:    fmt.Sprintf("Subject: %s | Issuer: %s | Indicators: %s", subject, issuer, strings.Join(reasons, ", ")),
					Timestamp: fmtTS(ts),
				})
			}
			return true
		})
	}
}
