package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServeHTTP_SecurityHeaders codifies the clickjacking-mitigation
// invariant: every response leaving the server carries the frame-denial
// + baseline hardening headers, on any route and any status code. Nessus
// flagged the absence as "not in all content responses"; the fix lives
// in ServeHTTP so it is route-independent by construction. This asserts
// that property across a 200, a 500, and the mux's own 404 — not just
// the single path the scanner happened to probe (see the
// invariant-not-failure-case discipline).
func TestServeHTTP_SecurityHeaders(t *testing.T) {
	want := map[string]string{
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/boom", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	s := &Server{mux: mux}

	// "/nope" is unregistered so the mux's built-in 404 is exercised —
	// error responses are content responses too.
	for _, path := range []string{"/ok", "/boom", "/nope"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		for h, v := range want {
			if got := w.Header().Get(h); got != v {
				t.Errorf("%s: header %s = %q; want %q", path, h, got, v)
			}
		}
	}
}
