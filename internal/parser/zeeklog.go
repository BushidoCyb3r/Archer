package parser

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// gzipDecompressLimit caps how many decompressed bytes ParseLog reads from
// a single .gz file. No real Zeek log approaches this; it bounds total work
// per file against a decompression bomb. A var (not const) so tests can
// lower it. See limitErrReader for why this errors rather than truncating.
var gzipDecompressLimit int64 = 4 << 30 // 4 GiB

// errGzipLimit is returned when a gzip stream decompresses past
// gzipDecompressLimit. Surfacing it — rather than EOF-ing silently like a
// bare io.LimitReader — keeps analysts from getting finding counts that
// imply a full scan when the tail was dropped, the same trust-bug class the
// 16 MiB line-cap fix addressed.
var errGzipLimit = errors.New("gzip stream exceeds decompression limit")

// limitErrReader passes through up to `remaining` bytes, then probes for a
// further byte; if the underlying stream has more, Read returns errGzipLimit
// instead of EOF. A stream ending exactly at the limit reads cleanly.
type limitErrReader struct {
	r         io.Reader
	remaining int64
}

func (l *limitErrReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		var probe [1]byte
		if n, _ := l.r.Read(probe[:]); n > 0 {
			return 0, errGzipLimit
		}
		return 0, io.EOF
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

// ParseLog reads a Zeek log file (plain or gzipped, JSON or TSV format)
// and calls yield for each record. Returning false from yield stops iteration.
func ParseLog(path string, yield func(rec map[string]any) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = &limitErrReader{r: gz, remaining: gzipDecompressLimit}
	}

	sc := bufio.NewScanner(r)
	// 16 MiB max line size. Modern HTTP captures regularly exceed
	// 1 MiB on a single record (large query strings, base64-encoded
	// uploads, fat set[string] fields). The previous 1 MiB cap
	// silently truncated everything after the offending line via
	// bufio.ErrTooLong, and the analyzer discarded the error — analysts
	// got finding counts that implied the whole file had been scanned
	// when the parser had bailed. The 16 MiB ceiling is large enough
	// for any realistic Zeek record while still catching truly
	// pathological binary garbage. The error path now propagates so
	// callers can surface it.
	buf := make([]byte, 1<<20)
	sc.Buffer(buf, 16<<20)

	// Peek at first non-comment line to detect format
	var firstDataLine string
	var headerFields []string
	var headerSeen bool

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#fields") {
			// TSV format — parse field names
			parts := strings.Split(line, "\t")
			if len(parts) > 1 {
				headerFields = parts[1:]
			}
			headerSeen = true
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		firstDataLine = line
		break
	}
	if err := sc.Err(); err != nil {
		return err
	}

	// Determine format from first data line
	isTSV := headerSeen && !strings.HasPrefix(firstDataLine, "{")

	processLine := func(line string) (map[string]any, bool) {
		if isTSV {
			return parseTSVLine(line, headerFields)
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil {
			return rec, true
		}
		return nil, false
	}

	// Count data lines seen vs records parsed. A file with data lines that
	// all fail to parse (a TSV missing its #fields header is misdetected as
	// JSON and every json.Unmarshal fails, or a non-Zeek file lands in /logs)
	// otherwise returns nil with zero records — the analyzer then reports a
	// clean scan of a file it read nothing from, the same trust-bug class the
	// line-cap and gzip-limit fixes addressed.
	var dataLines, parsed int

	if firstDataLine != "" {
		dataLines++
		if rec, ok := processLine(firstDataLine); ok {
			parsed++
			if !yield(rec) {
				return nil
			}
		}
	}

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		dataLines++
		rec, ok := processLine(line)
		if !ok {
			continue
		}
		parsed++
		if !yield(rec) {
			return nil
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if dataLines > 0 && parsed == 0 {
		return fmt.Errorf("parsed 0 of %d data lines (unrecognized format — missing #fields header or non-Zeek file?)", dataLines)
	}
	return nil
}

func parseTSVLine(line string, fields []string) (map[string]any, bool) {
	if len(fields) == 0 {
		return nil, false
	}
	parts := strings.Split(line, "\t")
	rec := make(map[string]any, len(fields))
	for i, f := range fields {
		if i < len(parts) {
			rec[f] = parts[i]
		} else {
			rec[f] = "-"
		}
	}
	return rec, true
}

// GetStr extracts a string value from a record, returning "" for missing or "-" values.
func GetStr(rec map[string]any, key string) string {
	v, ok := rec[key]
	if !ok {
		return ""
	}
	switch s := v.(type) {
	case string:
		if s == "-" || s == "(empty)" {
			return ""
		}
		return s
	case json.Number:
		return s.String()
	default:
		b, _ := json.Marshal(v)
		str := strings.Trim(string(b), `"`)
		if str == "-" {
			return ""
		}
		return str
	}
}

// GetStrs extracts a Zeek vector field as a string slice. TSV logs encode
// vectors as a comma-joined string; JSON logs as a real array. Missing,
// "-", and "(empty)" all yield nil.
func GetStrs(rec map[string]any, key string) []string {
	v, ok := rec[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case string:
		if s == "" || s == "-" || s == "(empty)" {
			return nil
		}
		return strings.Split(s, ",")
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok && str != "" && str != "-" {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

// GetFloat extracts a float64 from a record.
func GetFloat(rec map[string]any, key string) float64 {
	v, ok := rec[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(n, 64)
		return f
	}
	return 0
}

// GetInt extracts an int from a record.
func GetInt(rec map[string]any, key string) int {
	v, ok := rec[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

// GetBool extracts a bool from a record.
func GetBool(rec map[string]any, key string) bool {
	v, ok := rec[key]
	if !ok {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return b == "T" || b == "true" || b == "1"
	}
	return false
}

// MatchesLogType returns true if the filename suggests a given Zeek log type.
func MatchesLogType(path, logType string) bool {
	base := path
	// Strip directory
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	// Strip extensions
	base = strings.TrimSuffix(base, ".gz")
	base = strings.TrimSuffix(base, ".log")
	return base == logType || strings.HasPrefix(base, logType+".")
}
