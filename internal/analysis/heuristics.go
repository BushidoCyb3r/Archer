package analysis

import (
	"regexp"
	"strings"
)

// Detection heuristic tables. These are detection knowledge — what a
// JA3 of cobalt strike looks like, which TLDs free-abuse providers
// hand out — not data-model types. They lived in internal/model
// pre-v0.19.x because that was the only package the rest of the tree
// could import without inducing a cycle; with grep confirming every
// consumer is inside internal/analysis, the maps now sit next to
// their callers.

// KnownC2Ports maps port numbers to C2/malware labels.
var KnownC2Ports = map[int]string{
	1080:  "SOCKS proxy",
	3128:  "HTTP proxy (Squid)",
	4444:  "Metasploit default",
	4445:  "Metasploit alt",
	4899:  "Radmin RAT",
	6666:  "IRC / C2",
	6667:  "IRC",
	6668:  "IRC",
	6669:  "IRC",
	8008:  "C2 generic",
	8888:  "C2 / JupyterLab",
	9001:  "Tor relay",
	9030:  "Tor directory",
	31337: "Back Orifice / Elite",
}

// KnownBadJA4 maps JA4 fingerprints to C2/malware labels. JA4 is the
// structured successor to JA3 (FoxIO, 2023). Unlike MD5 JA3, JA4 encodes
// TLS version, cipher count, extension count, and ALPN in the prefix so
// fingerprints are human-readable and more stable across TLS library
// updates. This map uses only fingerprints from the FoxIO public database
// (github.com/FoxIO-LLC/ja4) that are not shared with common legitimate
// software. Sliver/Havoc share the generic GoLang fingerprint and are
// intentionally excluded to avoid false-positives against Go services.
// Extend from the FoxIO database as additional C2-exclusive fingerprints
// are documented.
var KnownBadJA4 = map[string]string{
	// Cobalt Strike v4.9.1 (default profiles) — four variants covering
	// wininet/winhttp transport × SNI-present/absent. TLS 1.2, no ALPN.
	"t12i190700_d83cc789557e_16bbda4055b2": "Cobalt Strike v4.9.1 wininet (no SNI)",
	"t12i210700_76e208dd3e22_16bbda4055b2": "Cobalt Strike v4.9.1 winhttp (no SNI)",
	"t12d190800_d83cc789557e_16bbda4055b2": "Cobalt Strike v4.9.1 wininet",
	"t12d210800_76e208dd3e22_16bbda4055b2": "Cobalt Strike v4.9.1 winhttp",
	// IcedID — TLS 1.3 loader fingerprint.
	"t13d201100_2b729b4bf6f3_9e7b989ebec8": "IcedID loader",
}

// ja3Shape matches a JA3 hash: exactly 32 lowercase hex digits (an MD5).
// JA4 fingerprints carry a structured prefix (e.g. t13d1516h2_...) and never
// match, so this is a reliable JA3-vs-JA4 discriminator for operator input.
var ja3Shape = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ClassifyFingerprints splits an operator fingerprint IOC list into JA3 and
// JA4 lookup maps (fingerprint -> label), classifying each by shape. Empty and
// comment lines are skipped; values are lowercased to match the analyzer's
// lowercased ja3/ja4 reads. Shared by the analyzer's SetOperatorFingerprints
// and the server's TLS-inventory union so both classify identically.
func ClassifyFingerprints(fps []string) (ja3, ja4 map[string]string) {
	ja3 = map[string]string{}
	ja4 = map[string]string{}
	for _, fp := range fps {
		fp = strings.ToLower(strings.TrimSpace(fp))
		if fp == "" || fp[0] == '#' {
			continue
		}
		if ja3Shape.MatchString(fp) {
			ja3[fp] = "Operator IOC"
		} else {
			ja4[fp] = "Operator IOC"
		}
	}
	return ja3, ja4
}

// KnownBadJA3 maps JA3 hashes to C2 framework labels.
var KnownBadJA3 = map[string]string{
	"72a589da586844d7f0818ce684948eea": "Cobalt Strike beacon",
	"a0e9f5192cc6583673b72155f5a851c1": "Cobalt Strike SMB",
	"e7d705a3286e19ea42f587b344ee6865": "Metasploit/Meterpreter",
	"bc6c386f480f367c02e5d7c0f31d6b3b": "Meterpreter reverse",
	"1aa7bf3b03eb4b20e561a3c9fe46e04a": "Cobalt Strike v4",
	"b386946a5a44d1ddcc843bc75336dfce": "Sliver C2",
	"6bea65232daa92d19e56f2a8c62b2ebf": "Cobalt Strike Malleable",
	"d0ec4b50a944b182f9159c61f5e00da4": "Brute Ratel",
	"f4febc55ea12b31ae17cfb7e8028f33c": "Brute Ratel alt",
}

// SuspiciousTLDs is the set of free/abused TLDs.
var SuspiciousTLDs = map[string]bool{
	".tk": true, ".ml": true, ".ga": true, ".cf": true, ".gq": true,
	".top": true, ".xyz": true, ".pw": true, ".cc": true, ".to": true,
	".biz": true, ".icu": true, ".club": true, ".live": true, ".work": true,
	".date": true, ".download": true, ".racing": true, ".review": true,
	".science": true, ".trade": true, ".win": true, ".stream": true,
	".faith": true, ".men": true, ".loan": true,
}

// WeakTLSVersions is the set of deprecated TLS protocol identifiers.
var WeakTLSVersions = map[string]bool{
	"SSLv2": true, "SSLv3": true, "TLSv10": true, "TLSv11": true,
}

// DoHIPs is the set of known DNS-over-HTTPS resolver IPs.
var DoHIPs = map[string]bool{
	"8.8.8.8": true, "8.8.4.4": true,
	"1.1.1.1": true, "1.0.0.1": true,
	"9.9.9.9": true, "149.112.112.112": true,
	"208.67.222.222": true, "208.67.220.220": true,
	"94.140.14.14": true, "94.140.15.15": true,
	"76.76.19.19": true, "76.223.122.150": true,
}

// DefaultCertSubjects are generic certificate subject strings indicating default tool output.
var DefaultCertSubjects = []string{
	"internet widgits", "example.com", "localhost",
	"default company", "my company", "test", "acme",
	"openssl", "self-signed", "ca-cert",
}

// C2URIPattern is a compiled C2 URI regex with a label.
type C2URIPattern struct {
	Re    *regexp.Regexp
	Label string
}

// C2URIPatterns are compiled at init time.
var C2URIPatterns []C2URIPattern

func init() {
	patterns := []struct{ pattern, label string }{
		{`^/submit\.php$`, "Cobalt Strike /submit.php"},
		{`^/ca$`, "Cobalt Strike /ca"},
		{`^/dpixel$`, "Cobalt Strike /dpixel"},
		{`^/pixel\.gif$`, "Cobalt Strike /pixel.gif"},
		{`^/ptj$`, "Cobalt Strike /ptj"},
		{`^/j\.ad$`, "Cobalt Strike /j.ad"},
		{`^/updates\.rss$`, "Cobalt Strike /updates.rss"},
		{`^/news\.php$`, "Empire /news.php"},
		{`^/admin/get\.php$`, "Empire /admin/get.php"},
		{`^/login/process\.php$`, "Empire /login/process.php"},
		{`^/[a-zA-Z0-9]{8}$`, "Metasploit stager (8-char alphanumeric)"},
	}
	for _, p := range patterns {
		C2URIPatterns = append(C2URIPatterns, C2URIPattern{
			Re:    regexp.MustCompile(p.pattern),
			Label: p.label,
		})
	}
}

// SuspiciousUAPatterns are substrings that identify scripting/automation user agents.
var SuspiciousUAPatterns = []string{
	"python-requests", "python-urllib", "curl/", "wget/",
	"go-http-client", "powershell", "libwww-perl",
}

// SuspiciousFileExts are file extensions that indicate executable/script downloads.
var SuspiciousFileExts = map[string]bool{
	".exe": true, ".dll": true, ".bat": true, ".ps1": true,
	".vbs": true, ".js": true, ".hta": true, ".scr": true,
	".sh": true, ".elf": true, ".com": true, ".msi": true,
}

// SuspiciousMIMETypes are MIME types indicating executable content.
var SuspiciousMIMETypes = map[string]bool{
	"application/x-dosexec":       true,
	"application/x-executable":    true,
	"application/x-elf":           true,
	"application/x-msdos-program": true,
	"application/octet-stream":    true,
}

// LateralMovementPorts are ports used for internal admin protocols.
var LateralMovementPorts = map[int]bool{
	445: true, 3389: true, 135: true, 5985: true, 5986: true, 22: true,
	23: true, 5900: true,
}

// lateralMovementServices maps Zeek DPD service labels for internal admin /
// lateral-movement protocols to a display name. It is the service-side mirror
// of LateralMovementPorts: a flow Zeek fingerprints as one of these between two
// internal hosts is lateral even on a non-standard port (RDP over 443, SSH on
// 8022) — the evasion the port set alone misses, since every standard lateral
// port is already in LateralMovementPorts. Augments the port set, never
// replaces it: WinRM rides `http` and is DPD-blind, so it stays port-only
// (5985/5986 above), and a blank/unrecognized service falls through to the port
// check.
var lateralMovementServices = map[string]string{
	"ssh":     "SSH",
	"rdp":     "RDP",
	"rfb":     "VNC",
	"telnet":  "Telnet",
	"smb":     "SMB",
	"dce_rpc": "WMI/RPC",
}

// expectedServicePorts maps a Zeek DPD service label to the set of ports that
// service is normally expected on. It backs the "Protocol on Unexpected Port"
// detector: Zeek's dynamic protocol detection names the actual L7 protocol
// regardless of port, so http-on-8443 or ssl-on-4444 is visible here even
// though a port-only view would miss it.
//
// Curated, not IANA-exhaustive: each entry lists the genuinely-common ports
// for that protocol so ordinary alt-port deployments (8080 http, 8443 tls,
// 2222 ssh) don't flag, and anything outside the set does. Only services with
// a stable, well-known port footprint are listed — exotic or ephemeral-port
// protocols are intentionally absent so they never produce a finding. Global
// detection knowledge, tuned here on corpus evidence, not in Settings.
//
// Service labels are Zeek's lowercase DPD names. TLS-wrapped variants (imaps,
// smtps, ftps, …) all surface as "ssl" in Zeek, so their ports live under the
// ssl entry rather than under the cleartext protocol.
var expectedServicePorts = map[string]map[int]bool{
	"http": {80: true, 8080: true, 8000: true, 8008: true, 8081: true, 8888: true, 3128: true},
	"ssl":  {443: true, 8443: true, 993: true, 995: true, 465: true, 990: true, 636: true, 989: true, 992: true, 994: true, 5061: true, 853: true},
	"ssh":  {22: true, 2222: true},
	"dns":  {53: true, 5353: true},
	"smtp": {25: true, 587: true, 2525: true},
	"ftp":  {20: true, 21: true, 2121: true},
}

// unexpectedServicePort reports whether Zeek identified a known service running
// on a port outside its expected set. Returns false for an empty service (DPD
// did not fingerprint the flow — the inherent coverage gap), for services not
// in the curated table, and for services on an expected port.
func unexpectedServicePort(service string, port int) bool {
	ports, known := expectedServicePorts[strings.ToLower(service)]
	if !known {
		return false
	}
	return !ports[port]
}
