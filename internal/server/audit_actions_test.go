package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestAuditActionVocabulary walks every .go file in this package
// looking for recordAudit / recordAuditLogin / LogAuditEvent call
// sites, extracts the action string passed to each, and asserts
// the string is a known member of knownAuditActions. Closes the
// "free-form string at the emission site" hole NEW-41 flagged —
// pre-fix a typo (`finding_status_chnage`) would silently produce
// a new, fragmented action name that fragmented the audit-log
// vocabulary and broke the action-filter UI. Same shape as the
// NEW-30 _esc consistency test: the rule is the test, not a
// docstring that drifts.
func TestAuditActionVocabulary(t *testing.T) {
	// Three call-shape patterns the codebase uses today. Each
	// captures the action string as group 1.
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`recordAudit\([^,]+,\s*"([^"]+)"`),
		regexp.MustCompile(`recordAuditLogin\([^,]+,\s*"([^"]+)"`),
		regexp.MustCompile(`LogAuditEvent\(store\.AuditEntry\{[^}]*Action:\s*"([^"]+)"`),
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob server package: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no Go files found in package directory")
	}

	found := map[string][]string{} // action → []file
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		// LogAuditEvent literals can wrap across lines — strip
		// newlines + collapse whitespace before regex match.
		flat := regexp.MustCompile(`\s+`).ReplaceAllString(string(body), " ")
		for _, pat := range patterns {
			for _, m := range pat.FindAllStringSubmatch(flat, -1) {
				action := m[1]
				found[action] = append(found[action], f)
			}
		}
	}

	if len(found) == 0 {
		t.Fatal("zero audit actions found — regex no longer matches the codebase shape")
	}

	for action, files := range found {
		if _, ok := knownAuditActions[action]; !ok {
			t.Errorf("action %q used in %v but not in knownAuditActions — add a constant in audit_actions.go", action, files)
		}
	}

	// And the inverse: every constant must be used at least once.
	// A constant that exists but isn't emitted anywhere is dead
	// vocabulary — either remove it or wire the emission.
	for action := range knownAuditActions {
		if _, used := found[action]; !used {
			t.Errorf("known action %q has a constant in audit_actions.go but is never emitted by any handler", action)
		}
	}
}
