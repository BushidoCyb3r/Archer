package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// decodeJSONBody decodes a JSON request body into dst with the given
// byte cap, writing the appropriate error response and returning a
// non-nil error if anything goes wrong.
//
// Error handling rules:
//
//   - Cap exceeded → 413 Request Entity Too Large with a clear
//     "body exceeds N byte cap" message. Pre-v0.14.3 the cap-trip
//     responded with a 400 carrying the raw "http: request body too
//     large" string, which made operators chase JSON-shape questions
//     when the actual issue was a size cap. Per HTTP semantics 413 is
//     the right status. v0.14.3 NEW-40.
//
//   - Any other decode error → 400 Bad Request with a generic
//     "invalid JSON" message. We deliberately do NOT echo the raw
//     decoder error back to the caller — pre-fix several handlers
//     called jsonError(w, err.Error(), …) which would surface
//     internal parse details (offset, character, sometimes type info)
//     to whoever sent the bad request. Generic message + the cap is
//     all the caller needs.
//
// On success the response is untouched and the caller proceeds. On
// failure the response is already written and the caller should
// return immediately.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			jsonError(w, fmt.Sprintf("body exceeds %d byte cap", mbe.Limit), http.StatusRequestEntityTooLarge)
			return err
		}
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return err
	}
	return nil
}
