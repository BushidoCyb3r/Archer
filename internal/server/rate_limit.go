package server

import (
	"sync"
	"time"
)

// Rate limiting for unauthenticated endpoints.
//
// Three paths feed the audit log without requiring authentication:
//   - /login POST       → login_failure rows
//   - /register POST    → user_register / admin_bootstrap rows
//   - /api/quiver/checkin → sensor_unauthorized_attempt rows
//
// An attacker reaching the listener (internal network, accidentally
// exposed port, sensor segment) could hammer any of these and
// produce arbitrarily many audit_log rows — drowning the real IR
// signal in synthetic noise, growing the table without bound, and
// eventually exhausting the data volume.
//
// Token-bucket per source IP, sized for hunt-kit deployments.
// Excess returns 429 and the bucket trip is itself logged as a
// request_rate_limited audit row so an operator reviewing the log
// can see "we got hammered from X" without the hammering itself
// scaling the log. v0.14.3 NEW-39.
//
// Bucket sizing rationale:
//
//   - 10 tokens per minute per source IP is generous for legitimate
//     traffic (a user mistyping their password three times is
//     fine; a sensor's hourly checkin doesn't come close) and
//     tight enough to prevent log-flood attacks from accumulating
//     interesting volume.
//   - The bucket fills continuously (token = 6 seconds of wall
//     time) so a paused attacker who comes back later doesn't
//     reset; they pick up where they left off.
//   - Per-IP keying means a single source can't drown the log, but
//     a distributed attack still adds rows — at which point the
//     attack is visible AS a distributed event (many source IPs
//     hitting the same per-IP cap).
const (
	rateLimitTokensPerMinute = 10
	rateLimitBucketCapacity  = 10
	rateLimitIdleEviction    = 10 * time.Minute
)

type rateLimitBucket struct {
	tokens   float64
	lastFill time.Time
	lastSeen time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateLimitBucket
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*rateLimitBucket)}
}

// allow returns true if the source IP has tokens remaining and
// consumes one; false if the bucket is empty (rate-limited).
// Refill happens continuously: 1 token per 6 seconds, capped at
// the bucket capacity.
//
// Nil-safe: tests that construct a *Server directly without going
// through New() leave rateLimit unset; those code paths skip the
// limiter rather than panic. Production code always goes through
// New() and gets a non-nil limiter.
func (rl *rateLimiter) allow(srcIP string) bool {
	if rl == nil {
		return true
	}
	if srcIP == "" {
		// No source — don't gate, since we'd otherwise share one
		// bucket across all sourceless requests.
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.buckets[srcIP]
	if !ok {
		b = &rateLimitBucket{
			tokens:   rateLimitBucketCapacity,
			lastFill: now,
		}
		rl.buckets[srcIP] = b
	}
	// Continuous refill: tokens per second × elapsed seconds.
	elapsed := now.Sub(b.lastFill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * (float64(rateLimitTokensPerMinute) / 60.0)
		if b.tokens > rateLimitBucketCapacity {
			b.tokens = rateLimitBucketCapacity
		}
		b.lastFill = now
	}
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictIdle drops buckets that haven't been touched recently so the
// map doesn't grow without bound under a long-running attack from
// many source IPs. Called from a background loop.
func (rl *rateLimiter) evictIdle() {
	cutoff := time.Now().Add(-rateLimitIdleEviction)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for ip, b := range rl.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(rl.buckets, ip)
		}
	}
}

// startRateLimitEvictionLoop runs a background ticker that prunes
// idle buckets every minute. The loop ends when the supplied done
// channel closes (server shutdown).
func (rl *rateLimiter) startEvictionLoop(done <-chan struct{}) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				rl.evictIdle()
			case <-done:
				return
			}
		}
	}()
}
