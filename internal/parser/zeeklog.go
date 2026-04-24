package parser

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
)

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
		r = gz
	}

	sc := bufio.NewScanner(r)
	buf := make([]byte, 1<<20)
	sc.Buffer(buf, 1<<20)

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

	if firstDataLine != "" {
		if rec, ok := processLine(firstDataLine); ok {
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
		rec, ok := processLine(line)
		if !ok {
			continue
		}
		if !yield(rec) {
			return nil
		}
	}
	return sc.Err()
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
