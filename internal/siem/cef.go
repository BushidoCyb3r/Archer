// Package siem formats and forwards escalated findings to an external SIEM
// as CEF over UDP syslog. The concrete target is Security Onion's CEF Fleet
// integration; nothing here names it — the wire format is standard CEF.
package siem

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// maxMsgLen caps the Detail carried in the CEF msg extension so the datagram
// stays well under the ~1.5 KB UDP fragmentation threshold; the full detail is
// reachable via the deep-link.
const maxMsgLen = 800

// tsLayouts are the UTC layouts the analyzer emits Finding.Timestamp in
// (second- then minute-precision). Tried in order for the CEF rt field.
var tsLayouts = []string{"2006-01-02 15:04:05", "2006-01-02 15:04"}

// FormatCEF renders one escalated finding as a bare CEF line:
//
//	CEF:0|Archer|Archer|<ver>|<type>|<type>|<sev>|<ext>
//
// No syslog (RFC3164) header — the line begins at "CEF:" so Elastic's
// decode_cef (the Security Onion CEF Fleet integration's input) parses it
// directly, the same way it parses bare-CEF senders. version is the Archer
// build version; deepLink is a URL back to the finding. Event time travels in
// the rt extension (→ @timestamp), so no framing timestamp is needed.
func FormatCEF(f model.Finding, version, deepLink string) string {
	header := strings.Join([]string{
		"CEF:0", "Archer", "Archer",
		cefHeaderEscape(version),
		cefHeaderEscape(f.Type),
		cefHeaderEscape(f.Type),
		strconv.Itoa(cefSeverity(f.Score)),
	}, "|")
	return header + "|" + buildExtensions(f, deepLink)
}

func buildExtensions(f model.Finding, deepLink string) string {
	var b strings.Builder
	add := func(key, val string) {
		if val == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(cefValueEscape(val))
	}
	cs := func(n int, label, val string) {
		if val == "" {
			return
		}
		add(fmt.Sprintf("cs%dLabel", n), label)
		add(fmt.Sprintf("cs%d", n), val)
	}

	add("externalId", strconv.Itoa(f.ID))
	if ms, ok := eventTimeMillis(f.Timestamp); ok {
		add("rt", strconv.FormatInt(ms, 10))
	}
	add("src", f.SrcIP)
	add("dst", f.DstIP)
	if isNumeric(f.DstPort) {
		add("dpt", f.DstPort)
	}
	add("app", f.Service)
	add("msg", truncateDetail(f.Detail, maxMsgLen))
	cs(1, "ArcherScore", strconv.Itoa(f.Score))
	cs(2, "ArcherSensor", f.Sensor)
	cs(3, "ArcherUrl", deepLink)
	cs(4, "ArcherAnalyst", f.Analyst)
	cs(5, "ja3", f.JA3)
	cs(6, "ja4", f.JA4)
	return b.String()
}

// cefSeverity scales Archer's 0–100 score to CEF's 0–10 (round-half-up).
func cefSeverity(score int) int {
	s := (score + 5) / 10
	if s < 0 {
		return 0
	}
	if s > 10 {
		return 10
	}
	return s
}

func cefHeaderEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

func cefValueEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\r", "")
	return strings.ReplaceAll(s, "\n", `\n`)
}

func eventTimeMillis(ts string) (int64, bool) {
	for _, layout := range tsLayouts {
		if t, err := time.Parse(layout, ts); err == nil {
			return t.UTC().UnixMilli(), true
		}
	}
	return 0, false
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.Atoi(s)
	return err == nil
}

// truncateDetail keeps whole pipe-delimited segments up to max chars so the
// msg ends on a complete clause with no ellipsis (full detail via deep-link).
func truncateDetail(s string, max int) string {
	if len(s) <= max {
		return s
	}
	out := ""
	for _, seg := range strings.Split(s, "|") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		cand := seg
		if out != "" {
			cand = out + " | " + seg
		}
		if len(cand) > max {
			break
		}
		out = cand
	}
	if out != "" {
		return out
	}
	head := s[:max]
	if i := strings.LastIndex(head, " "); i > 0 {
		return head[:i]
	}
	return head
}
