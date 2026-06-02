package query

import (
	"fmt"
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
}

var knownFields = map[string]bool{
	"id":   true,
	"type": true, "severity": true, "score": true, "src": true, "dst": true,
	"port": true, "detail": true, "hostname": true, "sensor": true,
	"status": true, "ts": true, "ioc": true, "spectral": true, "new": true,
	"ja3": true, "ja4": true, "file": true,
	"tscore": true, "dscore": true, "hist": true, "dur": true,
	"conns": true, "meanint": true, "medint": true, "jitter": true,
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
		return t, nil
	}

	// Field term with empty value is an error (e.g. "type:").
	if field != "" && rest == "" {
		return nil, fmt.Errorf("missing value for field %q", field)
	}
	t.value = rest
	return t, nil
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
	case "ioc":
		return boolMatch(f.IOCMatch, t.value)
	case "new":
		return boolMatch(f.IsNewToMe, t.value)
	case "spectral":
		return boolMatch(strings.Contains(f.Detail, "Spectral rescued:"), t.value)
	case "ts":
		return tsMatch(f.Timestamp, t, opLoc)
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
