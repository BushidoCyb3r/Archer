// Package siem formats and forwards escalated findings to an external SIEM
// as CEF over UDP syslog. The concrete target is Security Onion's CEF Fleet
// integration; nothing here names it — the wire format is standard CEF.
package siem

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// maxMsgLen caps the Detail carried in the CEF msg extension so the datagram
// stays well under the ~1.5 KB UDP fragmentation threshold; the full detail is
// reachable via the deep-link. Kept conservative so the enrichment fields
// (dhost/request/reason/flexString*) still leave the datagram under ~1.5 KB.
const maxMsgLen = 600

// TriageData carries the AI Triage verdict extracted from a briefing note.
// All fields are optional; an empty Verdict means no triage data is available.
type TriageData struct {
	Verdict    string // "LIKELY MALICIOUS", "INVESTIGATE", or "LIKELY BENIGN"
	Confidence string // "high", "medium", or "low"
	Reason     string // one-line reason from the verdict line
	Provider   string // LLM provider name (e.g. "anthropic", "ollama")
}

// FormatCEF renders one escalated finding as a bare CEF line. It is a wrapper
// around FormatCEFEnriched with no triage data — existing call sites are unchanged.
func FormatCEF(f model.Finding, version, deepLink string) string {
	return FormatCEFEnriched(f, nil, version, deepLink)
}

// FormatCEFEnriched renders an escalated finding as a bare CEF line. When
// triage is non-nil and carries a verdict, that verdict is prepended to msg so
// the AI assessment is visible in the SIEM alert listing without any schema
// change: "AI: LIKELY MALICIOUS (high) | <truncated detail>".
func FormatCEFEnriched(f model.Finding, triage *TriageData, version, deepLink string) string {
	header := strings.Join([]string{
		"CEF:0", "Archer", "Archer",
		cefHeaderEscape(version),
		cefHeaderEscape(f.Type),
		cefHeaderEscape(f.Type),
		strconv.Itoa(cefSeverity(f.Score)),
	}, "|")
	return header + "|" + buildExtensions(f, triage, deepLink)
}

// FormatAITriageCEF renders a supplemental bare CEF event for an AI Triage
// briefing on an already-escalated finding. It uses a distinct
// device-event-class-id ("ai_triage") so SIEM detection rules can target it
// specifically. The cs slots carry the verdict, confidence, deep-link, provider,
// and finding type; msg carries the verdict line for immediate readability.
// The event is correlated to the escalation event by externalId (finding ID).
func FormatAITriageCEF(f model.Finding, triage TriageData, version, deepLink string) string {
	header := strings.Join([]string{
		"CEF:0", "Archer", "Archer",
		cefHeaderEscape(version),
		"ai_triage",
		cefHeaderEscape(fmt.Sprintf("AI Triage #%d: %s", f.ID, triage.Verdict)),
		strconv.Itoa(cefSeverity(f.Score)),
	}, "|")

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
	if isIP(f.SrcIP) {
		add("src", f.SrcIP)
	}
	if isIP(f.DstIP) {
		add("dst", f.DstIP)
	}
	if isNumeric(f.DstPort) {
		add("dpt", f.DstPort)
	}
	// msg = verdict line; this is what shows in the SIEM alert listing.
	verdictLine := triage.Verdict
	if triage.Confidence != "" {
		verdictLine += " (" + triage.Confidence + ")"
	}
	if triage.Reason != "" {
		verdictLine += " — " + triage.Reason
	}
	add("msg", truncateDetail(verdictLine, maxMsgLen))
	cs(1, "ArcherScore", strconv.Itoa(f.Score))
	cs(2, "AIVerdict", triage.Verdict)
	cs(3, "AIConfidence", triage.Confidence)
	cs(4, "ArcherUrl", deepLink)
	cs(5, "AIProvider", triage.Provider)
	cs(6, "FindingType", f.Type)
	if ids := attackIDs(f.Type); ids != "" {
		add("flexString1Label", "ATT&CK")
		add("flexString1", ids)
	}
	if f.Timestamp != "" {
		add("flexString2Label", "ArcherEventTime")
		add("flexString2", f.Timestamp)
	}
	return header + "|" + b.String()
}

func buildExtensions(f model.Finding, triage *TriageData, deepLink string) string {
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
	// No rt extension: Security Onion's decode_cef rejects an epoch-millis rt
	// (the whole event is dropped). Omitting it lets @timestamp fall back to
	// ingest time — i.e. when the analyst escalated and Archer forwarded —
	// which is the right time for an escalation alert anyway. The finding's own
	// timestamps remain in msg/Detail and via the deep-link. Do not re-add rt.
	if isIP(f.SrcIP) {
		add("src", f.SrcIP)
	}
	if isIP(f.DstIP) {
		add("dst", f.DstIP)
	}
	if isNumeric(f.DstPort) {
		add("dpt", f.DstPort)
	}
	add("app", f.Service)
	// When an AI Triage verdict is available, prepend it to msg so the
	// assessment is immediately visible in the SIEM alert listing.
	detail := truncateDetail(f.Detail, maxMsgLen)
	if triage != nil && triage.Verdict != "" {
		prefix := "AI: " + triage.Verdict
		if triage.Confidence != "" {
			prefix += " (" + triage.Confidence + ")"
		}
		if detail != "" {
			detail = prefix + " | " + detail
		} else {
			detail = prefix
		}
	}
	add("msg", detail)
	cs(1, "ArcherScore", strconv.Itoa(f.Score))
	cs(2, "ArcherSensor", f.Sensor)
	cs(3, "ArcherUrl", deepLink)
	cs(4, "ArcherAnalyst", f.Analyst)
	cs(5, "ja3", f.JA3)
	cs(6, "ja4", f.JA4)

	// Enrichment via standard CEF keys (map to ECS natively; no cs slot left):
	add("dhost", f.Hostname) // → destination.domain — the C2 pivot
	add("request", f.URI)    // → url.original — HTTP-beacon path
	if f.IOCMatch {          // → event.reason — IOC/TI prioritization signal
		r := f.IOCSource
		if r == "" {
			r = "IOC/TI match"
		}
		add("reason", r)
	}
	if ids := attackIDs(f.Type); ids != "" {
		add("flexString1Label", "ATT&CK")
		add("flexString1", ids)
	}
	// Event time as text (not rt): SO's decode_cef rejects an epoch-millis rt,
	// and a date-typed field risks the same — flexString2 is a plain string.
	if f.Timestamp != "" {
		add("flexString2Label", "ArcherEventTime")
		add("flexString2", f.Timestamp)
	}
	return b.String()
}

// attackIDs returns the comma-joined MITRE ATT&CK technique IDs a finding type
// maps to (e.g. "T1071,T1071.004"), or "" if the type has no mapping.
func attackIDs(findingType string) string {
	techs := model.AttackTechniquesFor(findingType)
	if len(techs) == 0 {
		return ""
	}
	ids := make([]string, len(techs))
	for i, t := range techs {
		ids[i] = t.ID
	}
	return strings.Join(ids, ",")
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

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.Atoi(s)
	return err == nil
}

func isIP(s string) bool {
	if s == "" {
		return false
	}
	// net.ParseIP handles IPv4, IPv6, and IPv4-mapped IPv6 — exactly what
	// decode_cef accepts. Hostnames, CIDRs, and empty strings return false.
	return net.ParseIP(s) != nil
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
