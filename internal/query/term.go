package query

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// term is a leaf predicate: an optional field, an operator, and a value (or a
// [lo,hi] range). A bare term has field == "".
type term struct {
	field  string // canonical field name; "" for a bare term
	op     string // "", ">=", "<=", ">", "<", "=", or "range"
	value  string // for non-range terms (quotes already stripped)
	lo, hi string // for range terms
	phrase bool   // value originated from a quoted phrase
}

// canonicalField maps user-facing aliases to canonical field names and
// reports whether the field is known.
var fieldAlias = map[string]string{
	"src_ip":          "src",
	"dst_ip":          "dst",
	"dst_port":        "port",
	"timestamp":       "ts",
	"connections":     "conns",
	"mean_interval":   "meanint",
	"median_interval": "medint",
	"direction":       "dir",
	"analyst_note":    "note",
	"detected_at":     "detected",
}

var knownFields = map[string]bool{
	"id":   true,
	"type": true, "severity": true, "score": true, "src": true, "dst": true,
	"port": true, "detail": true, "hostname": true, "sensor": true,
	"status": true, "ts": true, "ioc": true, "spectral": true,
	"ja3": true, "ja4": true, "file": true,
	"tscore": true, "dscore": true, "hist": true, "dur": true,
	"conns": true, "meanint": true, "medint": true, "jitter": true,
	"uri": true, "note": true, "analyst": true, "dir": true, "detected": true,
	"channel": true, "benign": true, "service": true, "attack": true,
	"outratio": true, "ai": true,
}

// serviceQueryAliases maps the common protocol name an analyst types to Zeek's
// DPD service string, so `service:<common>` finds findings stamped with Zeek's
// label. Each is a same-field synonym (the alias value is matched against the
// finding's Service), never a cross-field expansion — e.g. there is
// deliberately no winrm→port alias, since WinRM rides HTTP (service "http")
// and a port-based expansion would conflate the service and port axes and
// match unrelated traffic; query WinRM as `port:5985,5986` instead.
var serviceQueryAliases = map[string]string{
	"vnc":          "rfb", // Zeek's RFB analyzer; Lateral Movement labels it "VNC"
	"tls":          "ssl", // Zeek tags all TLS flows "ssl"
	"https":        "ssl",
	"kerberos":     "krb",
	"cifs":         "smb",
	"microsoft-ds": "smb",
}

// parseTerm turns a raw term token into a leaf node.
func parseTerm(raw string) (node, error) {
	field, rest := splitField(raw)
	if field != "" {
		if c, ok := fieldAlias[field]; ok {
			field = c
		}
		if !knownFields[field] {
			return nil, fmt.Errorf("unknown field %q", field)
		}
	}
	t := term{field: field}

	// Range: [lo TO hi]
	if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
		lo, hi, ok := splitRange(rest[1 : len(rest)-1])
		if !ok {
			return nil, fmt.Errorf("malformed range %q", rest)
		}
		t.op = "range"
		t.lo, t.hi = lo, hi
		return t, nil
	}

	// Comparison: >=, <=, >, <, =
	for _, op := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(rest, op) {
			t.op = op
			v := strings.TrimSpace(rest[len(op):])
			// A quoted value carries internal spaces (e.g. a datetime
			// literal ts:>="2026-03-15 08:00:00"); strip the quotes here so
			// the field evaluators see the raw value.
			if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
				v = v[1 : len(v)-1]
			}
			t.value = v
			if t.value == "" {
				return nil, fmt.Errorf("missing value after %q", op)
			}
			return t, nil
		}
	}

	// Quoted phrase.
	if len(rest) >= 2 && strings.HasPrefix(rest, `"`) && strings.HasSuffix(rest, `"`) {
		t.phrase = true
		t.value = rest[1 : len(rest)-1]
		if err := validateFieldValue(field, t.value); err != nil {
			return nil, err
		}
		return t, nil
	}

	// Field term with empty value is an error (e.g. "type:").
	if field != "" && rest == "" {
		return nil, fmt.Errorf("missing value for field %q", field)
	}
	t.value = rest
	if err := validateFieldValue(field, t.value); err != nil {
		return nil, err
	}
	return t, nil
}

// validateFieldValue rejects an out-of-vocabulary value for the closed-set
// fields so a misspelling surfaces as a query error instead of silently
// matching nothing:
//   - type: must be a known finding type (or the `beacons` family selector).
//     type:"Correlatd Activity" / type:Beaon are rejected.
//   - dir: must be one of the four directions (or the `lateral` alias).
//
// A no-op for every free-text / numeric / wildcard field.
// attackMatch reports whether the finding type's ATT&CK techniques match the
// query value on technique ID, tactic, or name. Substring/glob semantics
// (stringPatternMatch) mean attack:T1071 also matches the sub-technique
// T1071.004, and attack:"command and control" matches the tactic.
func attackMatch(findingType, val string) bool {
	for _, tech := range model.AttackTechniquesFor(findingType) {
		if stringPatternMatch(tech.ID, val) ||
			stringPatternMatch(tech.Tactic, val) ||
			stringPatternMatch(tech.Name, val) {
			return true
		}
	}
	return false
}

func validateFieldValue(field, value string) error {
	switch field {
	case "type":
		if strings.EqualFold(value, "beacons") {
			return nil
		}
		if !model.IsKnownFindingType(value) {
			return fmt.Errorf("unknown finding type %q", value)
		}
	case "dir":
		switch strings.ToLower(value) {
		case "outbound", "inbound", "internal", "lateral", "external":
		default:
			return fmt.Errorf("unknown direction %q (want outbound, inbound, internal, lateral, or external)", value)
		}
	}
	return nil
}

// splitField returns the field name and the remainder after the first colon,
// when the token begins with an identifier followed by ':'. Otherwise it
// returns ("", raw) — a bare term.
func splitField(raw string) (string, string) {
	if strings.HasPrefix(raw, `"`) {
		return "", raw
	}
	idx := strings.IndexByte(raw, ':')
	if idx <= 0 {
		return "", raw
	}
	name := raw[:idx]
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return "", raw
		}
	}
	return strings.ToLower(name), raw[idx+1:]
}

// splitRange splits "lo TO hi" (case-insensitive separator) into its bounds,
// requiring both to be non-empty.
func splitRange(s string) (string, string, bool) {
	up := strings.ToUpper(s)
	idx := strings.Index(up, " TO ")
	if idx < 0 {
		return "", "", false
	}
	lo := strings.TrimSpace(s[:idx])
	hi := strings.TrimSpace(s[idx+4:])
	if lo == "" || hi == "" {
		return "", "", false
	}
	return lo, hi, true
}

func (t term) eval(f model.Finding, opLoc *time.Location) bool {
	switch t.field {
	case "":
		return t.evalBare(f)
	case "type":
		if strings.EqualFold(t.value, "beacons") {
			return model.IsBeaconType(f.Type)
		}
		return strings.EqualFold(f.Type, t.value)
	case "severity":
		return strings.EqualFold(string(f.Severity), t.value)
	case "sensor":
		return f.Sensor == t.value
	case "status":
		if strings.EqualFold(t.value, "open") {
			return f.Status == ""
		}
		return strings.EqualFold(string(f.Status), t.value)
	case "detail":
		return stringPatternMatch(f.Detail, t.value)
	case "hostname":
		return stringPatternMatch(f.Hostname, t.value)
	case "file":
		return stringPatternMatch(f.SourceFile, t.value)
	case "service":
		// Zeek DPD service ("http", "ssl", "rdp", …) stamped on every
		// conn-derived finding (beacon, lateral movement, C2 port, strobe,
		// exfil, off-hours, long connection, protocol-on-unexpected-port) with
		// the originating connection's L7; empty when DPD didn't fingerprint
		// the flow. Combine with type: to scope. Wildcard glob, like uri/note.
		// A value alias bridges the common name to Zeek's DPD string (vnc→rfb).
		if stringPatternMatch(f.Service, t.value) {
			return true
		}
		if alias, ok := serviceQueryAliases[strings.ToLower(t.value)]; ok {
			return stringPatternMatch(f.Service, alias)
		}
		return false
	case "attack":
		// MITRE ATT&CK technique the finding's Type maps to. Matches the
		// technique ID (attack:T1071 hits T1071 and its sub-techniques via
		// substring), tactic, or name. Derived from Type, not a stored field.
		return attackMatch(f.Type, t.value)
	case "uri":
		return stringPatternMatch(f.URI, t.value)
	case "note":
		return stringPatternMatch(f.AnalystNote, t.value)
	case "analyst":
		return stringPatternMatch(f.Analyst, t.value)
	case "dir":
		return dirMatch(f.SrcIP, f.DstIP, t.value)
	case "ja3":
		return strings.EqualFold(f.JA3, t.value)
	case "ja4":
		return strings.EqualFold(f.JA4, t.value)
	case "src":
		return ipFieldMatch(f.SrcIP, t)
	case "dst":
		return ipFieldMatch(f.DstIP, t)
	case "port":
		return t.op == "" && portMatch(f.DstPort, t.value)
	case "id":
		return numericMatch(float64(f.ID), t)
	case "score":
		return numericMatch(float64(f.Score), t)
	case "tscore", "dscore", "hist", "dur":
		// Sub-scores are only meaningful for beacon findings; a predicate on
		// any of them implicitly scopes to the beacon family so a bare upper
		// bound can't surface non-beacons whose sub-scores are a structural 0.
		if !model.IsBeaconType(f.Type) {
			return false
		}
		return numericMatch(subScore(f, t.field), t)
	case "conns", "meanint", "medint", "jitter":
		// Beacon timing/volume metrics. Same beacon-scope rule as the
		// sub-scores: these are a structural 0 on every non-beacon, so a
		// bare upper bound (meanint:<10) must not surface them.
		if !model.IsBeaconType(f.Type) {
			return false
		}
		return numericMatch(beaconMetric(f, t.field), t)
	case "outratio":
		// Outbound/inbound payload-byte ratio over the pair's observation
		// window — the query-language version of the beacon chart's
		// upload-heavy flag (which paints a Bytes-mirror bucket red at
		// sent > 2× received; outratio:>=2 is the whole-window analogue).
		// Scoped to findings stamped with byte totals (conn-derived Beacon /
		// Port-Hopping Beacon / Data Exfiltration); everything else has a
		// structural 0 and matches no outratio predicate, same shape as the
		// beacon sub-scores. All-upload pairs (resp 0) evaluate as +Inf so
		// every lower-bound predicate matches them.
		if f.OrigBytes <= 0 && f.RespBytes <= 0 {
			return false
		}
		if f.RespBytes == 0 {
			return numericMatch(math.Inf(1), t)
		}
		return numericMatch(float64(f.OrigBytes)/float64(f.RespBytes), t)
	case "ioc":
		return boolMatch(f.IOCMatch, t.value)
	case "spectral":
		// Matches the structured SpectralRescued flag (set when the
		// Lomb-Scargle path fired), not a Detail substring — the flag is set
		// under the identical condition and survives detail-string wording
		// changes. Spectral is annotation-only as of the timing-axis
		// validation: a match means the finding carries a spectral signal,
		// not that the score was boosted.
		return boolMatch(f.SpectralRescued, t.value)
	case "channel":
		// channel:true scopes to promoted per-channel beacon sub-findings (a
		// non-empty Channel discriminator); channel:false to blends and every
		// other type. A specific channel is found via ja3:<hash>.
		return boolMatch(f.Channel != "", t.value)
	case "benign":
		// benign:true matches findings whose JA3/JA4 client fingerprint has
		// been marked benign on the TLS Fingerprints wall. The flag is stamped
		// by findings_filter just before this runs (it's not a stored field).
		return boolMatch(f.TLSAllowlisted, t.value)
	case "ai":
		// ai:true matches findings that carry an AI-triage briefing note. Read
		// straight off the (populated) Notes slice — the list path filters before
		// projection strips notes, so they're present here.
		has := false
		for _, n := range f.Notes {
			if n.Author == model.AuthorAITriage {
				has = true
				break
			}
		}
		return boolMatch(has, t.value)
	case "ts":
		return tsMatch(f.Timestamp, t, opLoc)
	case "detected":
		// DetectedAt is epoch seconds; 0 means "never assigned" — a finding
		// that can't be placed in time matches no detected predicate, the same
		// shape as an unparseable Timestamp under ts:.
		if f.DetectedAt == 0 {
			return false
		}
		return tsMatchTime(time.Unix(f.DetectedAt, 0).UTC(), t, opLoc)
	}
	return false
}

func subScore(f model.Finding, field string) float64 {
	switch field {
	case "tscore":
		return f.TSScore
	case "dscore":
		return f.DSScore
	case "hist":
		return f.HistScore
	case "dur":
		return f.DurScore
	}
	return 0
}

// beaconMetric reads the raw beacon timing/volume metric for a metric field.
// jitter is the coefficient of variation (stddev/mean) — the raw ratio the
// scorer stored, not the percentage the triage header renders.
func beaconMetric(f model.Finding, field string) float64 {
	switch field {
	case "conns":
		return float64(f.SampleSize)
	case "meanint":
		return f.MeanInterval
	case "medint":
		return f.MedianInterval
	case "jitter":
		return f.Jitter
	}
	return 0
}

func (t term) evalBare(f model.Finding) bool {
	if !t.phrase {
		if ip := parseIPLiteral(t.value); ip {
			return strings.EqualFold(f.SrcIP, t.value) || strings.EqualFold(f.DstIP, t.value)
		}
	}
	hay := strings.ToLower(f.Type + " " + f.SrcIP + " " + f.DstIP + " " + f.DstPort + " " +
		f.Detail + " " + f.Timestamp + " " + string(f.Severity))
	return strings.Contains(hay, strings.ToLower(t.value))
}
