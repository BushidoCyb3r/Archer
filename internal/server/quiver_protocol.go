package server

import (
	"encoding/json"
	"net/http"
)

// QuiverProtocolVersion is what this server speaks and prefers. Bumped
// when the wire contract between sensor and server changes in a way old
// clients can't muddle through — see doc/QUIVER.md "Protocol versioning"
// for the bumping rules.
//
// Sensors send their own version in enrollment + checkin; servers
// validate against supportedQuiverProtocols and reject mismatches with
// a structured error so the operator sees "your sensor is on v1, server
// requires v2+" instead of an opaque rsync failure later.
const QuiverProtocolVersion = 1

// supportedQuiverProtocols enumerates every version this server still
// accepts. Drop entries when their compatibility window closes; today
// only v1 exists. Listed as a set for O(1) membership and so the
// supported list can be surfaced in error responses verbatim.
var supportedQuiverProtocols = map[int]bool{
	1: true,
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
// field. A missing field (the *int is nil) is treated as v1: that's the
// one-cycle backwards-compat window for sensors that were installed
// before protocol versioning landed. Once every fielded sensor has
// shipped a checkin or re-enrolled with an explicit version, the server
// can flip this to a hard error in a future release; until then,
// missing == v1 keeps existing fleets functional during the upgrade.
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
