package server

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
)

// TestSecretConfigKeys_Complete closes a latent secret-leak trap: secretConfigKeys
// is hand-maintained, so a new credential field added to config.Config but not
// listed there would be silently disclosed to viewer/analyst roles via GET
// /api/config. Rather than re-enumerate the fields by hand (the same trap), this
// walks every Config json tag and asserts each secret-shaped field is redacted.
func TestSecretConfigKeys_Complete(t *testing.T) {
	secretShaped := regexp.MustCompile(`(?i)(api_key|api_id|api_secret|secret|password|token)`)
	listed := make(map[string]bool, len(secretConfigKeys))
	for _, k := range secretConfigKeys {
		listed[k] = true
	}
	tp := reflect.TypeOf(config.Config{})
	for i := 0; i < tp.NumField(); i++ {
		name := strings.SplitN(tp.Field(i).Tag.Get("json"), ",", 2)[0]
		if name == "" || name == "-" {
			continue
		}
		if secretShaped.MatchString(name) && !listed[name] {
			t.Errorf("config field %q (json:%q) looks like a credential but is not in secretConfigKeys — it would leak to non-admin GET /api/config", tp.Field(i).Name, name)
		}
	}
}
