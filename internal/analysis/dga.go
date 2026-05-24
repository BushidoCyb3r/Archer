package analysis

import (
	_ "embed"
	"net"
	"strconv"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// DGA (Domain Generation Algorithm) hostname augmentation for the
// beacon detectors.
//
// Why this exists. A beacon to pool.ntp.org is operational noise; the
// same timing shape to kx9j3qm2pflw.com is high-confidence C2. The
// distinction is in the destination *hostname* — algorithmically-
// generated domains have characteristics (high character entropy,
// non-English letter transitions) that a malicious actor's domain-
// generation algorithm produces but legitimate names don't. Bumping
// a beacon's score when its destination looks DGA-shaped is one of
// the highest-leverage detection augmentations available — small
// implementation surface, large analyst-value uplift on the kind of
// finding that justifies the tool's existence.
//
// This is a score augmentation, NOT a standalone detector. Running
// DGA scoring as its own detector would flood the findings table
// with false positives on legitimate algorithmic-looking hostnames
// (CDN cache keys, blob storage IDs, ad-network endpoints, email-
// tracking hashes). As confirming evidence on an already-suspicious
// beacon, the false-positive rate drops dramatically — the beacon's
// timing regularity has already done most of the suspicion work; DGA
// adds "and the destination doesn't look like a real domain."
//
// Where the hostname comes from. The conn-level Beaconing detector
// gets it from sslUIDIndex (TLS SNI). The HTTP Beaconing detector
// gets it directly from the Host header in http.log records. The
// dns.log correlation path (for non-TLS, non-HTTP beacons that
// resolved a name before the analysis window) is deferred to a
// future slice — the v1 trade-off accepts that pure-TCP beacons to
// raw IPs without observable DNS get no DGA scoring.
//
// Scoring shape. The augmentation looks at the registrable domain's
// second-level domain (SLD), not the FQDN. "dvxlk2j9.cloudfront.net"
// scores "cloudfront" → low entropy, English-shaped → not DGA. The
// algorithmic subdomain doesn't trigger the bump because SLD
// extraction correctly identifies the registrable domain. This is
// the most important design choice in this feature: get it right
// and the bulk of legitimate-CDN false positives disappear
// automatically.

//go:embed bigrams.txt
var bigramData string

// englishBigramFreq maps two-character lowercase strings to natural-
// log probabilities derived from a standard English corpus. Loaded
// once at init from the embedded bigrams.txt. Unseen bigrams fall
// back to bigramFloor in bigramLogLikelihood.
var englishBigramFreq map[string]float64

// bigramFloor is the fallback log-probability assigned to any
// bigram absent from englishBigramFreq. Calibrated to be punishing
// enough that DGA strings (where most bigrams hit the floor) average
// well below the suspect threshold, but not so punishing that an
// English word containing one or two uncommon-but-real bigrams (like
// "rf" in surf, "mb" in amber) gets unfairly dragged down. Combined
// with bigramThreshold default -4.5 (config.go DGABigramThreshold),
// the configuration produces a clean separation: average English
// bigrams land around -3.0 to -3.8 (above the threshold), DGA
// bigrams average -5.5 to -6.5 (below). The 1-unit gap between
// English-typical and threshold gives one or two unusual-bigram
// English words headroom before they trip the gate.
const bigramFloor = -5.5

// cdnAllowlistSuffixes covers legitimate algorithmic-shaped
// registrable domains where the SLD itself is the algorithmic-
// looking part rather than the subdomain. Even with correct SLD
// extraction, "azureedge.net" scores "azureedge" → moderate entropy
// → could trip the threshold in some configurations. This list
// short-circuits the DGA bump for known-legitimate registrable
// domains regardless of their scoring shape.
//
// Maintained here in code rather than in operator config because
// these are universally-legitimate-across-deployments. Operator-
// curated allowlist (Store.AllowlistMatcher) still applies on top
// for deployment-specific suppressions.
var cdnAllowlistSuffixes = []string{
	".cloudfront.net",
	".cloudflare.net",
	".cloudflare.com",
	".azureedge.net",
	".azurewebsites.net",
	".azurefd.net",
	".amazonaws.com",
	".s3.amazonaws.com",
	".elasticloadbalancing.amazonaws.com",
	".akamaihd.net",
	".akamaized.net",
	".akamai.net",
	".fastly.net",
	".fastlylb.net",
	".edgekey.net",
	".edgesuite.net",
	".googleusercontent.com",
	".googleapis.com",
	".gstatic.com",
	".doubleclick.net",
	".cdninstagram.com",
	".fbcdn.net",
	".twimg.com",
	".cdn-apple.com",
	".windowsupdate.com",
	".windows.net",
	".sharepoint.com",
	".office.com",
	".office365.com",
	".live.com",
	".herokuapp.com",
	".github.io",
	".githubusercontent.com",
	".pages.dev",
	".workers.dev",
	".vercel.app",
	".netlify.app",
	".bunnycdn.com",
	".b-cdn.net",
	".keycdn.com",
}

// matchesCDNAllowlist reports whether host ends in one of the built-in
// universally-legitimate CDN/cloud suffixes. Shared by the DGA
// augmentation (short-circuits the score bump) and the DNS-cadence
// beacon detector (skips the apex before scoring) so both consult one
// definition of "known-benign algorithmic infrastructure."
func matchesCDNAllowlist(host string) bool {
	lower := strings.ToLower(host)
	for _, suffix := range cdnAllowlistSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func init() {
	englishBigramFreq = make(map[string]float64, 256)
	for _, line := range strings.Split(bigramData, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		englishBigramFreq[strings.ToLower(fields[0])] = v
	}
}

// DGAResult is the per-hostname output of dgaHostnameScore. Returned
// as a struct rather than via multiple values so callers don't have
// to remember positional ordering — the Detail-string renderer in
// the beacon detectors uses Entropy + BigramLogLik independently for
// analyst-facing diagnostics.
type DGAResult struct {
	// Suspect is true when the SLD's entropy is above
	// entropyThreshold AND its bigram log-likelihood is below
	// bigramThreshold AND the host doesn't match the built-in CDN
	// allowlist. Both metrics must agree before the augmentation
	// fires.
	Suspect bool
	// Entropy is the Shannon entropy of the SLD in bits per
	// character. English-shaped names score 2.5-3.5; DGA-shaped
	// names score 3.8-4.5 (uniform character sampling pushes
	// entropy toward log2(26) ≈ 4.7).
	Entropy float64
	// BigramLogLik is the mean natural-log probability over the
	// SLD's character bigrams. English-shaped names average -2.5 to
	// -3.5; DGA-shaped names average -5.0 to -7.5.
	BigramLogLik float64
	// SLD is the second-level domain that was actually scored —
	// useful in the Detail string so analysts can see what the
	// detector decided to look at (vs the full hostname, which may
	// include legitimate algorithmic subdomains).
	SLD string
}

// dgaHostnameScore computes the DGA-suspicion verdict for a
// hostname. Both metrics must cross their thresholds for Suspect to
// be true — either alone produces too many false positives on
// legitimate algorithmic hostnames.
//
// Conservative-by-design: when the hostname matches the built-in
// CDN allowlist suffixes, Suspect is forced to false regardless of
// SLD entropy. When the SLD is too short (< 7 chars), Suspect is
// false — DGAs typically produce 8-25 char SLDs, and entropy
// estimates on tiny strings are unreliable. The result struct
// always carries the computed values so callers can log diagnostics
// even when the verdict is "not suspect."
func dgaHostnameScore(host string, entropyThreshold, bigramThreshold float64) DGAResult {
	var res DGAResult
	if host == "" {
		return res
	}
	// IP-literal defense-in-depth. applyDGAScoring filters IP literals
	// before calling this function (NEW-77), but dgaHostnameScore is
	// package-internal and any future caller bypassing applyDGAScoring
	// would skip the filter and hit extractSLD's IPv6-port collision
	// (e.g. "2001:db8::1" → "2001" as a meaningless SLD). NEW-83 from
	// the nineteenth audit round: enforce the invariant where the
	// consequence happens rather than relying solely on the caller.
	if isIPLiteral(host) {
		return res
	}
	// CDN allowlist short-circuits before SLD scoring. cloudfront
	// algorithmic subdomains (dvxlk2j9.cloudfront.net) would
	// correctly score "cloudfront" as non-DGA via SLD extraction;
	// the suffix list catches the rare case where a CDN's
	// registrable domain itself looks algorithmic.
	if matchesCDNAllowlist(host) {
		return res
	}

	sld := extractSLD(host)
	res.SLD = sld
	if len(sld) < 7 {
		// Below the floor we don't compute — the entropy estimate
		// is unreliable and DGAs produce longer names anyway.
		return res
	}

	res.Entropy = shannonEntropy(sld)
	res.BigramLogLik = bigramLogLikelihood(sld)
	res.Suspect = res.Entropy > entropyThreshold && res.BigramLogLik < bigramThreshold
	return res
}

// bigramLogLikelihood computes the mean natural-log probability of
// the string's character bigrams against the embedded English
// frequency table. Bigrams not in the table fall back to bigramFloor
// (~3.4e-4 in raw probability space), large enough to express "this
// pair is uncommon in English" without underflowing to -Inf when
// the string contains many such pairs.
//
// Returns 0 for strings shorter than 2 chars (no bigrams to score).
func bigramLogLikelihood(s string) float64 {
	if len(s) < 2 {
		return 0
	}
	lower := strings.ToLower(s)
	var sum float64
	var n int
	for i := 0; i < len(lower)-1; i++ {
		bg := lower[i : i+2]
		if v, ok := englishBigramFreq[bg]; ok {
			sum += v
		} else {
			sum += bigramFloor
		}
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// extractSLD returns the second-level domain (the meaningful part of
// the registrable domain). Naive implementation — splits on '.' and
// takes the second-from-last component. Strips trailing ":port" if
// present.
//
// Limitation: doesn't use a Public Suffix List. "kx9j3qm2pflw.co.uk"
// returns "co" rather than "kx9j3qm2pflw" because this implementation
// doesn't know that "co.uk" is a multi-label TLD. The false negative
// on ccTLD-suffix DGAs is acceptable for v1 — most real-world DGAs
// register on .com / .net / .org / .top / .xyz / .info first-level
// TLDs, and PSL integration (via golang.org/x/net/publicsuffix) is
// a v2 follow-up.
//
// Edge cases:
//   - Empty input → empty SLD
//   - No dots → the entire host as SLD (catches single-word
//     "localhost" et al.)
//   - Pure IP address → returns the second-from-last octet, which is
//     a meaningless score; callers should check that the host isn't
//     a literal IP before scoring
//   - Trailing dot → ignored
func extractSLD(host string) string {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".")
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return parts[len(parts)-2]
}

// isIPLiteral returns true when host is a bare IPv4 or IPv6 address.
// The DGA scorer should never run against IP literals — they have no
// meaningful "domain" structure and extractSLD would score a
// meaningless octet.
//
// Backed by net.ParseIP rather than a hand-rolled classifier. v0.16.1
// shipped a heuristic that returned true for any string containing
// only hex characters plus dots/colons; that incorrectly classified
// all-hex hostnames like "face.beef", "abc.def", "cafe.dead" as IPs
// and made applyDGAScoring skip them. The failure mode was a *false
// negative for DGA detection*: an attacker could deliberately craft
// an all-hex DGA name to evade the IP guard and (paradoxically) get
// the DGA bump skipped. NEW-81 from the nineteenth audit round.
//
// Handles three forms:
//
//   - bare IPv4 / IPv6 ("185.43.7.92", "::1", "2001:db8::1")
//   - IPv4-with-port ("185.43.7.92:443") — strip trailing :port
//   - bracketed IPv6-with-port ("[::1]:443") — strip brackets + port
//
// Empty input returns false (treated as "no hostname" by the caller).
func isIPLiteral(host string) bool {
	if host == "" {
		return false
	}
	// Bracketed IPv6 form: [<ip>]:<port>. The brackets disambiguate
	// the IPv6 colons from the port colon and is the canonical
	// representation in HTTP Host headers.
	if host[0] == '[' {
		if end := strings.IndexByte(host, ']'); end > 0 {
			host = host[1:end]
		}
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		// IPv4-with-port: single colon, no IPv6 syntax in front of it.
		// We refuse to strip when host[:i] already contains colons —
		// that's an IPv6 literal we should pass to ParseIP intact.
		if !strings.ContainsRune(host[:i], ':') {
			host = host[:i]
		}
	}
	return net.ParseIP(host) != nil
}

// applyDGAScoring walks emitted Beaconing and HTTP Beaconing findings
// and bumps the score + severity for those whose destination
// Hostname looks DGA-shaped under the operator's configured
// thresholds. Runs once after Phase 2 completes (sslUIDIndex stable,
// HTTP Beaconing already emitted) so all findings are settled before
// the augmentation pass touches them.
//
// The bump is additive: +15 to score (capped at 99), one-step
// severity upgrade (Low→Medium, Medium→High, High→Critical). The
// magnitude is calibrated to materially shift triage priority
// without making DGA the dominant signal — the timing-regularity
// score from the existing detector still drives the bulk of the
// composite.
//
// Allowlist precedence: if the operator's allowlist matches either
// the full Hostname or its SLD, the bump is skipped. The built-in
// CDN-suffix allowlist in cdnAllowlistSuffixes already short-
// circuits inside dgaHostnameScore; this is the second layer for
// per-deployment "we know this destination is legitimate"
// suppressions.
//
// Findings with empty Hostname (pure-IP beacons, or TLS beacons
// whose SNI wasn't indexed in time) skip silently — there's nothing
// to score.
func (a *Analyzer) applyDGAScoring(allowlistMatches func(string) bool) {
	if !a.cfg.DGAEnabled {
		return
	}
	// Defensive guard mirroring the API boundary check: if a direct
	// DB write or half-applied migration left the thresholds in
	// degenerate space, fail closed (skip scoring) rather than
	// flagging every host.
	if a.cfg.DGAEntropyThreshold < 0 || a.cfg.DGAEntropyThreshold > 8 {
		return
	}
	if a.cfg.DGABigramThreshold < -10 || a.cfg.DGABigramThreshold >= 0 {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.findings {
		f := &a.findings[i]
		if f.Type != "Beaconing" && f.Type != "HTTP Beaconing" && f.Type != "DNS Beaconing" {
			continue
		}
		if f.Hostname == "" {
			continue
		}
		// IP-literal short-circuit. TLS SNI (RFC 6066 discourages but
		// doesn't ban it) and malformed HTTP Host headers can carry a
		// bare IP string in the Hostname field; some malware
		// deliberately sets SNI to an IP to bypass naive DPI. Without
		// this guard, extractSLD would treat "185.43.7.92" as a
		// domain and score "43" — meaningless on real IPs, but
		// edge-case strings like "185.k7x9q3.7.92" that happen to
		// look IP-shaped while carrying an algorithmic-looking
		// non-numeric component could trip the bump on a destination
		// that isn't actually a domain. NEW-77 from the eighteenth
		// audit round: the function existed with a docstring naming
		// the invariant but no caller enforced it.
		if isIPLiteral(f.Hostname) {
			continue
		}
		// Operator allowlist precedence — same shape the findings
		// filter applies to the SrcIP/DstIP fields, extended to
		// hostnames so analysts can suppress a known-legitimate
		// algorithmic-looking destination without disabling DGA
		// scoring globally.
		if allowlistMatches != nil && allowlistMatches(f.Hostname) {
			continue
		}
		res := dgaHostnameScore(f.Hostname, a.cfg.DGAEntropyThreshold, a.cfg.DGABigramThreshold)
		if allowlistMatches != nil && res.SLD != "" && allowlistMatches(res.SLD) {
			continue
		}
		if !res.Suspect {
			continue
		}
		// Bump: +15 score (cap 99), one-step severity upgrade.
		newScore := f.Score + 15
		if newScore > 99 {
			newScore = 99
		}
		f.Score = newScore
		switch f.Severity {
		case model.SevLow:
			f.Severity = model.SevMedium
		case model.SevMedium:
			f.Severity = model.SevHigh
		case model.SevHigh:
			f.Severity = model.SevCritical
		}
		// Annotate Detail so analysts know which signal drove the
		// bump. The numbers (entropy, bigram, SLD) are diagnostic
		// — calibration tuning relies on operators seeing the
		// actual values that crossed the threshold.
		f.Detail += " | DGA-suspect destination: " + f.Hostname +
			" (SLD=" + res.SLD +
			", entropy=" + formatFloat(res.Entropy, 2) +
			", bigram=" + formatFloat(res.BigramLogLik, 2) + ")"
	}
}

// formatFloat renders a float with the given precision. Avoids
// pulling fmt into the per-finding hot path here; %f-style format
// strings allocate a buffer each call.
func formatFloat(f float64, prec int) string {
	return strconv.FormatFloat(f, 'f', prec, 64)
}
