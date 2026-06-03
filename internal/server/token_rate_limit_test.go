package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTokenOrSession_ThrottlesBogusTokens asserts the X-Archer-Token branch is
// rate-limited: a flood of invalid tokens from one source eventually gets 429
// instead of an unbounded stream of 401s. A valid scraper is never charged
// because the bucket is only consumed on a failed token.
func TestTokenOrSession_ThrottlesBogusTokens(t *testing.T) {
	s := newAuditTestServer(t)
	s.rateLimit = newRateLimiter()

	handler := s.tokenOrSession(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	var got429 bool
	// Bucket capacity is 10; the 11th rapid bogus attempt should trip.
	for i := 0; i < 15; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/sensors/health", nil)
		req.Header.Set("X-Archer-Token", "definitely-not-a-real-token")
		req.RemoteAddr = "192.0.2.7:5555"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		switch w.Code {
		case http.StatusUnauthorized:
			// expected for the first batch
		case http.StatusTooManyRequests:
			got429 = true
		default:
			t.Fatalf("attempt %d: unexpected status %d", i, w.Code)
		}
	}
	if !got429 {
		t.Fatal("bogus-token flood was never throttled — the X-Archer-Token path is not rate-limited")
	}
}
