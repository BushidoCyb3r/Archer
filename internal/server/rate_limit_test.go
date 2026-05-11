package server

import (
	"testing"
)

// TestRateLimit_AuditOncePerTrip covers the NEW-47 fix: the
// first refusal on a fresh bucket audits, subsequent refusals on
// the same already-tripped bucket do not. The trip flag clears on
// the next admitted request so a re-trip after legitimate traffic
// resumes audits again.
func TestRateLimit_AuditOncePerTrip(t *testing.T) {
	rl := newRateLimiter()
	src := "192.0.2.10"

	// Burn through the bucket. Every admission must return
	// shouldAudit=false; only refusals can audit.
	for i := 0; i < rateLimitBucketCapacity; i++ {
		allowed, shouldAudit := rl.allow(src)
		if !allowed {
			t.Fatalf("admission %d denied; bucket should still have tokens", i)
		}
		if shouldAudit {
			t.Errorf("admission %d set shouldAudit=true; admissions never audit", i)
		}
	}

	// First refusal: should audit.
	allowed, shouldAudit := rl.allow(src)
	if allowed {
		t.Fatal("expected denial after bucket drained")
	}
	if !shouldAudit {
		t.Error("first refusal on a fresh trip must audit")
	}

	// 100 subsequent refusals: none must audit.
	for i := 0; i < 100; i++ {
		allowed, shouldAudit := rl.allow(src)
		if allowed {
			t.Fatal("legitimate-resumption mid-burst not modeled here")
		}
		if shouldAudit {
			t.Errorf("refusal %d on already-tripped bucket set shouldAudit=true — NEW-47 regression", i)
		}
	}
}

// TestRateLimit_IPv6BucketsAtSlash64 covers NEW-48: two source
// addresses in the same /64 must share a bucket so a residential
// IPv6 attacker rotating through SLAAC privacy addresses can't
// bypass the limit.
func TestRateLimit_IPv6BucketsAtSlash64(t *testing.T) {
	rl := newRateLimiter()
	// Same /64, different host bits.
	srcA := "2001:db8::1"
	srcB := "2001:db8::dead:beef"
	if bucketKey(srcA) != bucketKey(srcB) {
		t.Fatalf("bucket keys differ: %q vs %q", bucketKey(srcA), bucketKey(srcB))
	}

	// Burn the bucket via srcA.
	for i := 0; i < rateLimitBucketCapacity; i++ {
		rl.allow(srcA)
	}
	// srcB must now be refused too — same /64 = same bucket.
	allowed, _ := rl.allow(srcB)
	if allowed {
		t.Error("IPv6 sibling address admitted from a drained /64 bucket — NEW-48 regression")
	}

	// A different /64 must have its own bucket and admit.
	allowed, _ = rl.allow("2001:db8:1::1")
	if !allowed {
		t.Error("different-/64 IPv6 address refused — bucket aggregation too aggressive")
	}
}

// TestRateLimit_IPv4PerAddress covers the inverse of NEW-48: two
// distinct IPv4 addresses must NOT share a bucket. The /64
// aggregation only applies to IPv6.
func TestRateLimit_IPv4PerAddress(t *testing.T) {
	rl := newRateLimiter()
	for i := 0; i < rateLimitBucketCapacity; i++ {
		rl.allow("192.0.2.1")
	}
	allowed, _ := rl.allow("192.0.2.2")
	if !allowed {
		t.Error("distinct IPv4 address refused from another IP's drained bucket")
	}
}

// TestRateLimit_NilSafe covers the nil-receiver no-op path used by
// tests that construct *Server directly. Pre-fix any such test
// would nil-deref on the first request.
func TestRateLimit_NilSafe(t *testing.T) {
	var rl *rateLimiter
	for i := 0; i < 100; i++ {
		allowed, shouldAudit := rl.allow("192.0.2.99")
		if !allowed {
			t.Error("nil limiter denied")
		}
		if shouldAudit {
			t.Error("nil limiter set shouldAudit")
		}
	}
}

// TestRateLimit_TripClearsOnRecovery covers the clear-on-admission
// behaviour: once normal traffic resumes (a request is admitted),
// the trip flag clears so a subsequent re-trip audits again.
// Without this, an attacker who paused long enough for the bucket
// to partially refill and then resumed flooding would silently
// stay un-audited.
func TestRateLimit_TripClearsOnRecovery(t *testing.T) {
	rl := newRateLimiter()
	src := "192.0.2.20"

	// Drain and trip.
	for i := 0; i < rateLimitBucketCapacity; i++ {
		rl.allow(src)
	}
	if _, shouldAudit := rl.allow(src); !shouldAudit {
		t.Fatal("first trip should have audited")
	}

	// Manually pump tokens into the bucket so an admission lands
	// without sleeping (test fast-path).
	rl.mu.Lock()
	rl.buckets[bucketKey(src)].tokens = float64(rateLimitBucketCapacity)
	rl.mu.Unlock()

	// Admit — trip flag clears.
	allowed, _ := rl.allow(src)
	if !allowed {
		t.Fatal("expected admission after manual refill")
	}

	// Re-drain.
	for i := 0; i < rateLimitBucketCapacity-1; i++ {
		rl.allow(src)
	}
	// Next refusal must audit again — the prior trip cleared.
	if _, shouldAudit := rl.allow(src); !shouldAudit {
		t.Error("re-trip after admission did not audit — trip flag did not clear")
	}
}
