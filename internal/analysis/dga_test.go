package analysis

import (
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestDGAScore_KnownDGANames verifies the detector fires on hostnames
// shaped like real DGA output. The threshold pair (entropy > 3.5,
// bigramLLH < -3.0) was calibrated against the embedded bigram table
// so DGA-shaped strings cross both gates simultaneously.
func TestDGAScore_KnownDGANames(t *testing.T) {
	dgaCases := []string{
		"kx9j3qm2pflw.com",
		"xqjzvbnmpwrt.com",
		"qzpfnvxwbmkj.net",
		"vjxkqzpwfnmb.org",
		"zxqpfwnvbmjk.top",
	}
	for _, host := range dgaCases {
		res := dgaHostnameScore(host, 3.5, -4.5)
		if !res.Suspect {
			t.Errorf("%s: expected DGA-suspect; got entropy=%.2f bigram=%.2f sld=%q",
				host, res.Entropy, res.BigramLogLik, res.SLD)
		}
	}
}

// TestDGAScore_LegitimateNames verifies the detector doesn't fire on
// common English-shaped domains. False positives on names like
// google.com or microsoft.com would make the augmentation useless.
func TestDGAScore_LegitimateNames(t *testing.T) {
	legitCases := []string{
		"google.com",
		"microsoft.com",
		"github.com",
		"stackoverflow.com",
		"wikipedia.org",
		"reddit.com",
		"example.com",
		"archer.example",
	}
	for _, host := range legitCases {
		res := dgaHostnameScore(host, 3.5, -4.5)
		if res.Suspect {
			t.Errorf("%s: expected NOT DGA-suspect; got entropy=%.2f bigram=%.2f sld=%q (suspect=true)",
				host, res.Entropy, res.BigramLogLik, res.SLD)
		}
	}
}

// TestDGAScore_CDNAlgorithmicSubdomains is the most important test
// for this feature's real-world value: CDNs and cloud services
// produce algorithmic-looking subdomains in front of legitimate
// registrable domains. SLD extraction must ignore the subdomain and
// score the registrable domain, where "cloudfront" / "azureedge" /
// "s3" / etc. score as non-DGA.
func TestDGAScore_CDNAlgorithmicSubdomains(t *testing.T) {
	cdnCases := []string{
		"dvxlk2j9mvpqrs.cloudfront.net",
		"cdn-7f3a9bc.azurewebsites.net",
		"akm-72-83-241-86.akamaihd.net",
		"track-9a7fbe2c.mailchimp.com",
		"rt-9fk2m4qx.doubleclick.net",
		"d1234567890.amazonaws.com",
		"xyz-bucket-prod.s3.amazonaws.com",
	}
	for _, host := range cdnCases {
		res := dgaHostnameScore(host, 3.5, -4.5)
		if res.Suspect {
			t.Errorf("%s: legitimate CDN with algorithmic subdomain should NOT be DGA-suspect; got entropy=%.2f bigram=%.2f sld=%q",
				host, res.Entropy, res.BigramLogLik, res.SLD)
		}
	}
}

// TestDGAScore_ShortSLDShortCircuits verifies the < 7 char floor.
// DGAs typically produce 8-25 char SLDs, and entropy estimates on
// tiny strings are noisy. Short SLDs return Suspect=false without
// computing.
func TestDGAScore_ShortSLDShortCircuits(t *testing.T) {
	shortCases := []string{
		"a.com",
		"go.dev",
		"abc.com",
		"xkcd.com",   // 4-char SLD, English-shaped but below floor anyway
		"foo.bar.io", // SLD = "bar", 3 chars
	}
	for _, host := range shortCases {
		res := dgaHostnameScore(host, 3.5, -4.5)
		if res.Suspect {
			t.Errorf("%s: SLD below 7-char floor should never be suspect; got %+v", host, res)
		}
	}
}

// TestDGAScore_EdgeCases — empty input, host:port, trailing dot, etc.
// Defensive bounds.
func TestDGAScore_EdgeCases(t *testing.T) {
	cases := []struct {
		host        string
		wantSuspect bool
		description string
	}{
		{"", false, "empty"},
		{"example.com:443", false, "host with port — strip port, score legit SLD"},
		{"example.com.", false, "trailing dot — ignored"},
		{"localhost", false, "no dot — single component"},
		{"127.0.0.1", false, "IPv4 literal — SLD extraction returns numeric, gets scored but isn't DGA-shaped enough"},
	}
	for _, tc := range cases {
		res := dgaHostnameScore(tc.host, 3.5, -3.0)
		if res.Suspect != tc.wantSuspect {
			t.Errorf("%s [%s]: Suspect = %v, want %v (%+v)",
				tc.host, tc.description, res.Suspect, tc.wantSuspect, res)
		}
	}
}

// TestDGAScore_CDNAllowlistSuffixShortCircuits verifies the
// hard-coded CDN suffix list overrides scoring entirely, even when
// the algorithmic-looking part IS the registrable domain itself.
// This is the failsafe for the rare case where SLD extraction
// doesn't unmask a legitimate CDN.
func TestDGAScore_CDNAllowlistSuffixShortCircuits(t *testing.T) {
	host := "something-very-algorithmic-looking.cloudfront.net"
	res := dgaHostnameScore(host, 0.1, 0.0) // intentionally aggressive thresholds
	if res.Suspect {
		t.Errorf("CDN allowlist short-circuit failed: %s scored as suspect with deliberately-loose thresholds %+v", host, res)
	}
}

// TestExtractSLD covers the SLD extraction path explicitly. Naive
// implementation (split on '.') — known to misclassify multi-label
// TLDs like co.uk; that's a documented v1 limitation.
func TestExtractSLD(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		{"example.com", "example"},
		{"www.example.com", "example"},
		{"a.b.example.com", "example"},
		{"example.com:443", "example"},
		{"example.com.", "example"},
		{"localhost", "localhost"},
		{"", ""},
		// Documented limitation: PSL not used.
		{"kx9j3qm2pflw.co.uk", "co"},
	}
	for _, tc := range cases {
		got := extractSLD(tc.host)
		if got != tc.want {
			t.Errorf("extractSLD(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

// TestBigramLogLikelihood_EnglishVsDGA spot-checks the bigram
// distribution: English strings should score around -2.5 to -3.5,
// DGA strings around -5.0 to -7.5. The threshold (-3.0) sits in
// between, separating the populations.
func TestBigramLogLikelihood_EnglishVsDGA(t *testing.T) {
	englishExamples := []string{
		"microsoft",
		"wikipedia",
		"stackoverflow",
		"government",
	}
	for _, s := range englishExamples {
		got := bigramLogLikelihood(s)
		if got < -4.5 {
			t.Errorf("bigramLogLikelihood(%q) = %.2f; English-shaped string should score above -4.5 against the embedded table", s, got)
		}
	}
	dgaExamples := []string{
		"kxqzpfwnvbmj",
		"xqjzvbnmpwrt",
		"zxqpfwnvbmjk",
	}
	for _, s := range dgaExamples {
		got := bigramLogLikelihood(s)
		if got > -5.0 {
			t.Errorf("bigramLogLikelihood(%q) = %.2f; DGA-shaped string should score below -5.0", s, got)
		}
	}
	// Separation check: every DGA example should score strictly
	// lower than every English example. Without separation the
	// threshold-pair gate can't discriminate cleanly.
	for _, eng := range englishExamples {
		engScore := bigramLogLikelihood(eng)
		for _, dga := range dgaExamples {
			dgaScore := bigramLogLikelihood(dga)
			if dgaScore > engScore {
				t.Errorf("separation failure: DGA %q (%.2f) scored higher than English %q (%.2f)",
					dga, dgaScore, eng, engScore)
			}
		}
	}
}

// TestDGAScore_DiagnosticFieldsAlwaysSet verifies the entropy and
// bigram numbers are populated even when Suspect=false (e.g.
// borderline-but-not-quite cases). The Detail-string renderer in
// the beacon detectors uses these values for analyst-facing
// diagnostics regardless of the verdict.
func TestDGAScore_DiagnosticFieldsAlwaysSet(t *testing.T) {
	res := dgaHostnameScore("borderline-name.com", 3.5, -3.0)
	if res.SLD == "" {
		t.Error("SLD should be populated for any non-empty host with extractable SLD")
	}
	if res.Entropy == 0 {
		t.Errorf("Entropy should be computed for SLD above floor; got 0 (sld=%q)", res.SLD)
	}
	// BigramLogLik can be 0 only for SLDs < 2 chars, which is below
	// the < 7 floor — so any path that returns Entropy != 0 should
	// also return BigramLogLik != 0.
	if res.Entropy != 0 && res.BigramLogLik == 0 {
		t.Errorf("BigramLogLik should be computed alongside Entropy; got %.2f / 0", res.Entropy)
	}
}

// TestBigramData_Loaded confirms the embedded bigrams.txt was
// parsed at init. If the file format drifts or the path resolution
// breaks, this catches it loudly.
func TestBigramData_Loaded(t *testing.T) {
	if len(englishBigramFreq) < 100 {
		t.Fatalf("englishBigramFreq has only %d entries; expected 100+ from bigrams.txt — embed may have failed or parser regressed", len(englishBigramFreq))
	}
	// Spot-check a known common bigram.
	if v, ok := englishBigramFreq["th"]; !ok {
		t.Error("englishBigramFreq missing 'th' (most common English bigram)")
	} else if v >= 0 {
		t.Errorf("englishBigramFreq[\"th\"] = %.2f; expected negative log probability", v)
	}
}

// TestCDNAllowlistSuffixes_ExpectedEntries spot-checks that common
// cloud-provider CDN suffixes are present. A regression that
// TestIsIPLiteral covers the classifier the applyDGAScoring loop
// consults before running the per-finding DGA score. The function
// existed in dga.go pre-v0.16.1 but no caller invoked it (NEW-77
// dead-code finding); this test asserts the function correctly
// distinguishes bare IP literals from hostnames with non-hex
// alphabetic characters.
func TestIsIPLiteral(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"185.43.7.92", true},     // bare IPv4
		{"185.43.7.92:443", true}, // IPv4 + port
		{"::1", true},             // IPv6 loopback
		{"2001:db8::1", true},     // IPv6
		{"fe80::1", true},         // hex-only chars are still IP-shaped
		{"example.com", false},    // domain has 'x' / 'm' / 'p' / 'l'
		{"localhost", false},      // 'l' / 's' / 't'
		{"kx9j3qm2pflw.com", false},     // DGA-shaped name, not IP
		{"185.k7x9q3.7.92", false},      // IP-shaped but has 'k' / 'x' / 'q'
		{"", false},                     // empty
	}
	for _, tc := range cases {
		got := isIPLiteral(tc.host)
		if got != tc.want {
			t.Errorf("isIPLiteral(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestApplyDGAScoring_SkipsIPLiteralHostnames codifies NEW-77: when
// the destination Hostname carries a bare IP literal (TLS SNI set to
// an IP, malformed HTTP Host header, etc.), applyDGAScoring must
// short-circuit before extractSLD turns a meaningless octet into a
// score input. Pre-v0.16.1 the isIPLiteral classifier existed in
// source with a docstring naming this invariant but no caller
// enforced it.
func TestApplyDGAScoring_SkipsIPLiteralHostnames(t *testing.T) {
	a := New(defaultCfgWithDGA(), "", nil, nil)

	// Finding with bare-IPv4 SNI. Without the guard, extractSLD
	// returns "43" — the second-from-last component — which is
	// already below the SLD length floor in dgaHostnameScore, so the
	// bug doesn't currently produce a false-positive bump in the
	// common case. The guard is defense-in-depth: a future refactor
	// that lowers the SLD floor, or an edge-case IP shape that
	// happens to bypass the floor, would re-introduce the issue.
	a.findings = append(a.findings, model.Finding{
		Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "185.43.7.92", DstPort: "443",
		Score: 50, Severity: model.SevHigh,
		Hostname: "185.43.7.92",
	})
	before := a.findings[0].Score

	a.applyDGAScoring(nil)

	if a.findings[0].Score != before {
		t.Errorf("IP-literal Hostname triggered DGA score bump: %d → %d", before, a.findings[0].Score)
	}
	if strings.Contains(a.findings[0].Detail, "DGA-suspect") {
		t.Errorf("IP-literal Hostname got DGA-suspect Detail tag: %q", a.findings[0].Detail)
	}
}

// defaultCfgWithDGA wraps config.Default with the DGA defaults
// explicitly populated. Necessary because applyDGAScoring early-
// returns on DGAEnabled=false, and a freshly-constructed Analyzer
// in a test doesn't inherit settings from the operator's
// Settings → Beaconing pane.
func defaultCfgWithDGA() config.Config {
	cfg := config.Default()
	cfg.DGAEnabled = true
	cfg.DGAEntropyThreshold = 3.5
	cfg.DGABigramThreshold = -4.5
	return cfg
}

// accidentally drops one of these would silently re-introduce a
// class of false positives.
func TestCDNAllowlistSuffixes_ExpectedEntries(t *testing.T) {
	expected := []string{
		".cloudfront.net",
		".amazonaws.com",
		".azureedge.net",
		".akamaihd.net",
		".fastly.net",
	}
	have := make(map[string]bool, len(cdnAllowlistSuffixes))
	for _, s := range cdnAllowlistSuffixes {
		have[s] = true
	}
	for _, want := range expected {
		if !have[want] {
			t.Errorf("CDN allowlist missing %q; current list: %s", want, strings.Join(cdnAllowlistSuffixes, ", "))
		}
	}
}
