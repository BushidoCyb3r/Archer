package analysis

import "regexp"

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
}
