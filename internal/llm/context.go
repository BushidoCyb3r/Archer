package llm

// DefaultNetworkContext is prepended to the evidence block for every AI Triage
// enrichment. It is hardcoded and not operator-editable: it frames the platform,
// names the most common false-positive source shapes, and enforces the
// finding-level-before-host-level evaluation rule that prevents the model from
// using a host's general compromise activity to confirm a separate finding's
// pattern-match claim.
const DefaultNetworkContext = `Platform context: Archer network threat detection, analyzing Zeek logs (conn, dns, http, ssl, x509, files, notice logs) from a monitored network segment. Findings are machine-generated — the detector's claim must be independently evaluated against the evidence, not accepted at face value.

Known false-positive source shapes — evaluate these before calling MALICIOUS:
- Software package managers (yum/dnf, apt, pip, npm, cargo, brew, Windows Update, WSUS) contact official mirrors and CDNs on regular schedules; RPM, DEB, and wheel URI paths can satisfy Cobalt Strike checksum8 or other URI pattern detectors by coincidence. A URI pattern match on a domain consistent with a package repository is weak evidence alone.
- Cloud backup, sync, and endpoint agents (CrowdStrike, Defender, Carbon Black, Splunk UF, Elastic Agent, backup clients) produce regular beacon-shaped traffic to vendor infrastructure with tight intervals and consistent data sizes.
- NTP (UDP/123), DNS resolvers (UDP/TCP 53), OCSP/CRL endpoints, and CDN health-check probes produce timing profiles that match beacon detectors; these are almost always benign.
- Internal service-to-service traffic on non-standard ports — monitoring, admin, orchestration — is commonly flagged as lateral movement or protocol anomaly but is expected infrastructure behavior.
- .edu, .gov, and well-known CDN/cloud domains are high-prior benign destinations; a detector hit against them requires a finding-specific behavioral signal before MALICIOUS is warranted.

Evaluation order: examine this specific connection's own evidence — destination domain/IP, URI structure, port, TLS fingerprint, response behavior — before reaching for host-level context. The host's broader compromise activity (beacon roll-ups, lateral movement findings, Host Risk Score) tells you about the host's posture; it does NOT validate a separate finding's detector claim. If the verdict rests on a pattern match plus host-level corroboration only, with no finding-specific behavioral signal, call it INVESTIGATE and state explicitly what finding-specific evidence would confirm malicious (e.g. a C2-shaped HTTP response, a non-repository DNS resolution for the URI host, a TI hit on the destination).`
