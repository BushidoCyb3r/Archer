package server

import (
	"net"
	"sync"
	"time"
)

// Rate limiting for unauthenticated endpoints.
//
// Three paths feed the audit log without requiring authentication:
//   - /login POST       → login_failure rows
//   - /register POST    → user_register / admin_bootstrap rows
//   - /api/quiver/checkin → sensor_unauthorized_attempt rows (only
//     on auth-failure outcomes; see NEW-45)
//
// An attacker reaching the listener (internal network, accidentally
// exposed port, sensor segment) could hammer any of these and
// produce arbitrarily many audit_log rows — drowning the real IR
// signal in synthetic noise, growing the table without bound, and
// eventually exhausting the data volume.
//
// Token-bucket per source key, sized for hunt-kit deployments.
// Excess returns 429 and the FIRST trip per bucket is audited as
// request_rate_limited; subsequent excess on the same already-
// tripped bucket does not produce another audit row until normal
// traffic resumes and clears the trip flag. Under sustained attack
// this means O(1) audit rows per IP, not O(N) — closing the
// audit-log-flood path NEW-39 claimed and NEW-47 reopened.
// v0.14.4 NEW-47.
//
// Bucket sizing rationale:
//
//   - 10 tokens per minute per source bucket is generous for
//     legitimate traffic (a user mistyping their password three
//     times is fine; a sensor's hourly checkin doesn't come close)
//     and tight enough to prevent log-flood attacks from
//     accumulating interesting volume.
//   - The bucket fills continuously (1 token = 6 seconds of wall
//     time) so a paused attacker who comes back later doesn't
//     reset; they pick up where they left off.
//   - Per-IP keying with IPv6 /64 prefix aggregation (NEW-48):
//     IPv4 is keyed on the full address; IPv6 is keyed on the /64
//     prefix because a /64 is the smallest allocation unit per
//     customer and sub-/64 rotation comes free with most ISP and
//     cloud deployments (SLAAC privacy extensions, residential
//     temporary addresses). Without /64 aggregation a single
//     residential IPv6 attacker has 2^64 fresh buckets to burn
//     through.
const (
	rateLimitTokensPerMinute = 10
	rateLimitBucketCapacity  = 10
	rateLimitIdleEviction    = 10 * time.Minute
)

type rateLimitBucket struct {
	tokens   float64
	lastFill time.Time
	lastSeen time.Time
	// tripAudited is true once the rate-limit trip on this bucket
	// has produced a request_rate_limited audit row; cleared the
	// next time the bucket admits a legitimate request. Closes the
	// O(N) audit row flood under sustained attack. v0.14.4 NEW-47.
	tripAudited bool
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateLimitBucket
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*rateLimitBucket)}
}

// bucketKey aggregates the source IP into the bucket-key string.
// IPv4 addresses are keyed on the full address. IPv6 addresses are
// keyed on the /64 prefix — see the package comment for the
// rationale. An unparseable source falls back to the input string
// unchanged (treated as opaque). v0.14.4 NEW-48.
func bucketKey(srcIP string) string {
	if srcIP == "" {
		return ""
	}
	ip := net.ParseIP(srcIP)
	if ip == nil {
		return srcIP
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	mask := net.CIDRMask(64, 128)
	return ip.Mask(mask).String() + "/64"
}

// allow returns (allowed, shouldAudit). allowed is true when the
// bucket has tokens to consume; shouldAudit is true exactly once
// per trip (the first refused request on a fresh-or-recovered
// bucket). Subsequent refusals on the same already-tripped bucket
// return (false, false) so an attacker cannot scale audit-log
// volume by sustaining their flood.
//
// On a successful request the trip flag clears: the next refusal
// after legitimate traffic resumes will audit again, giving the
// audit reader a "recovered then re-tripped" signal.
//
// Nil-safe: tests that construct a *Server directly without going
// through New() leave rateLimit unset; those code paths skip the
// limiter rather than panic. Production code always goes through
// New() and gets a non-nil limiter.
func (rl *rateLimiter) allow(srcIP string) (allowed bool, shouldAudit bool) {
	if rl == nil {
		return true, false
	}
	key := bucketKey(srcIP)
	if key == "" {
		return true, false
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		b = &rateLimitBucket{
			tokens:   rateLimitBucketCapacity,
			lastFill: now,
		}
		rl.buckets[key] = b
	}
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
		// Refused. Audit on the first refusal per trip, then quiet.
		if b.tripAudited {
			return false, false
		}
		b.tripAudited = true
		return false, true
	}
	// Admitted: consume a token and clear the trip flag so the next
	// refusal after this admission will audit again.
	b.tokens--
	b.tripAudited = false
	return true, false
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

// startEvictionLoop runs a background ticker that prunes idle
// buckets every minute. The loop ends when the supplied done
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
