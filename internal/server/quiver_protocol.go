package server

import (
	"encoding/json"
	"net/http"
)

// QuiverProtocolVersion is what this server speaks and prefers. Bumped
// when the wire contract between sensor and server changes in a way old
// clients can't muddle through — see docs/QUIVER.md "Protocol versioning"
// for the bumping rules.
//
// Sensors send their own version in enrollment + checkin; servers
// validate against supportedQuiverProtocols and reject mismatches with
// a structured error so the operator sees "your sensor is on v1, server
// requires v2+" instead of an opaque rsync failure later.
//
// v2 (v0.12.0): per-sensor HMAC-SHA256 secret established at
// enrollment, required on every checkin. Closes NEW-16 — pre-v2 a
// checkin's only credential was the sensor's name (not a secret in
// the design), so anyone who could reach the TLS endpoint and guess
// the name could forge LastSeenAt heartbeats. v1 enrollments are
// dropped because there's no in-band path to retroactively issue an
// HMAC secret to a v1 sensor; the operator's upgrade is to re-enroll
// every sensor on v0.12.0. Audit 2026-05-10 NEW-16.
const QuiverProtocolVersion = 2

// supportedQuiverProtocols enumerates every version this server still
// accepts. Listed as a set for O(1) membership and so the supported
// list can be surfaced in error responses verbatim. v1 dropped in
// v0.12.0 — see protocol-version comment above.
var supportedQuiverProtocols = map[int]bool{
	2: true,
}

// supportedQuiverProtocolList returns the supported set as a sorted
// slice for inclusion in error responses. Stable order keeps the
// sensor-side error messages readable.
func supportedQuiverProtocolList() []int {
	out := make([]int, 0, len(supportedQuiverProtocols))
	for v := range supportedQuiverProtocols {
		out = append(out, v)
	}
	// len rarely > 2 so insertion sort is fine; no math/sort dependency
	// for a typical len-of-1 case.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// resolveQuiverProtocol normalises an incoming sensor's protocol_version
// field. A missing field (the *int is nil) is treated as v1, which is
// no longer supported in v0.12.0 — the resolver returns it explicitly
// so the error response surfaces "sensor reported v1; server requires
// v2" rather than blaming a missing field.
//
// Returns the resolved version and ok=true on success. On unsupported
// versions returns ok=false and the caller should respond with an error.
func resolveQuiverProtocol(version *int) (resolved int, ok bool) {
	v := 1
	if version != nil {
		v = *version
	}
	return v, supportedQuiverProtocols[v]
}

// quiverProtocolErrorJSON encodes the canonical "your protocol version
// isn't supported" response body. Used by enrollment (HTTP 400) and
// checkin (HTTP 200 with status field) — both surface the same
// supported_versions list so the sensor's operator can read which
// versions need to ship.
func quiverProtocolErrorJSON(sentVersion int) map[string]any {
	return map[string]any{
		"error":              "sensor protocol version not supported by this server",
		"sensor_version":     sentVersion,
		"server_version":     QuiverProtocolVersion,
		"supported_versions": supportedQuiverProtocolList(),
	}
}

// quiverProtocolUnsupportedCheckin writes the checkin-flavored response
// for a protocol mismatch: HTTP 200 (so curl -f doesn't swallow the
// body) with status="protocol_unsupported". quiver.sh dispatches on
// status; this lets the sensor distinguish a protocol failure from an
// "unknown" or transient network blip and log accordingly.
func quiverProtocolUnsupportedCheckin(w http.ResponseWriter, sentVersion int) {
	body := quiverProtocolErrorJSON(sentVersion)
	body["status"] = "protocol_unsupported"
	delete(body, "error") // status field replaces the freeform error key for checkin
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
