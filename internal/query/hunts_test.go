package query

import (
	"html"
	"os"
	"regexp"
	"testing"
)

// dataQueryRE pulls the value out of every `data-query='…'` (or "…") attribute
// in the template. The prebuilt-hunt chip ships each hunt as one such attribute.
var dataQueryRE = regexp.MustCompile(`data-query=(?:'([^']*)'|"([^"]*)")`)

// TestPrebuiltHuntsParse asserts every prebuilt-hunt query shipped in the UI is
// a well-formed query that this package can parse. The hunts live as HTML
// data-query attributes; this reads the actual template so a finding-type
// rename or a malformed preset can't silently ship a hunt that matches nothing.
// It is the automatable contract one layer down from the (untestable) chip UI.
func TestPrebuiltHuntsParse(t *testing.T) {
	const tmpl = "../../web/templates/index.html"
	body, err := os.ReadFile(tmpl)
	if err != nil {
		t.Fatalf("read %s: %v", tmpl, err)
	}

	matches := dataQueryRE.FindAllStringSubmatch(string(body), -1)
	var queries []string
	for _, m := range matches {
		raw := m[1]
		if raw == "" {
			raw = m[2]
		}
		queries = append(queries, html.UnescapeString(raw))
	}

	if len(queries) < 10 {
		t.Fatalf("found %d data-query hunts in %s; expected the prebuilt-hunt menu (>=10)", len(queries), tmpl)
	}

	for _, q := range queries {
		if _, err := Parse(q); err != nil {
			t.Errorf("prebuilt hunt %q does not parse: %v", q, err)
		}
	}
}
