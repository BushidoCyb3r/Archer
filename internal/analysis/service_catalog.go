package analysis

import "strings"

// Zeek's dynamic protocol detection (DPD) labels each connection's
// application-layer protocol in conn.log's `service` field, independent of the
// port the flow used. That field is sometimes empty (DPD didn't fingerprint
// the flow) and sometimes carries several comma-separated labels for one flow
// (`smb,gssapi,ntlm`, `ssl,http`). This file is the single place that
// understands those labels: it normalizes the raw field into a clean label set
// and maps each label to a coarse protocol category.
//
// It is the foundation for service-aware conn detection — keying detectors on
// the protocol Zeek actually saw rather than the destination port alone. The
// category mapping is detection knowledge, curated here and tuned on corpus
// evidence; it is not a per-deployment setting. It augments the port
// heuristics (KnownC2Ports, LateralMovementPorts, expectedServicePorts), never
// replaces them: DPD coverage is uneven (VNC needs a Zeek package, WinRM rides
// `http`, many UDP services are unlabeled), so a blank or unrecognized label
// means "no DPD result," never "not that protocol."

// serviceCategory is a coarse grouping of DPD service labels, letting
// conn-based detectors reason about a flow's protocol class without
// enumerating every label.
type serviceCategory string

const (
	svcRemoting     serviceCategory = "remoting"      // interactive/admin access: ssh, rdp, vnc, telnet
	svcWeb          serviceCategory = "web"           // http, ssl
	svcMail         serviceCategory = "mail"          // smtp, pop3, imap
	svcFileTransfer serviceCategory = "file-transfer" // ftp, tftp, smb
	svcDatabase     serviceCategory = "database"      // mysql, postgresql, mongodb, redis
	svcInfra        serviceCategory = "infra"         // dns, dhcp, ntp, kerberos, ldap, dce_rpc
	svcOther        serviceCategory = "other"         // DPD-recognized but uncategorized here
)

// serviceCategoryByLabel maps a single lowercased Zeek DPD service label to
// its category. Labels absent here fall through to svcOther via
// serviceCategoryOf. TLS-wrapped variants (imaps, ftps, smtps, …) all surface
// as "ssl" in Zeek, so the cleartext mail/file-transfer labels below classify
// the plaintext flows only — the encrypted ones land under "ssl"/web.
var serviceCategoryByLabel = map[string]serviceCategory{
	"ssh":    svcRemoting,
	"rdp":    svcRemoting,
	"rfb":    svcRemoting, // VNC
	"telnet": svcRemoting,

	"http": svcWeb,
	"ssl":  svcWeb,

	"smtp": svcMail,
	"pop3": svcMail,
	"imap": svcMail,

	"ftp":      svcFileTransfer,
	"ftp-data": svcFileTransfer,
	"tftp":     svcFileTransfer,
	"smb":      svcFileTransfer,

	"mysql":      svcDatabase,
	"postgresql": svcDatabase,
	"mongodb":    svcDatabase,
	"redis":      svcDatabase,

	"dns":      svcInfra,
	"dhcp":     svcInfra,
	"ntp":      svcInfra,
	"snmp":     svcInfra,
	"ldap":     svcInfra,
	"krb":      svcInfra,
	"krb_tcp":  svcInfra,
	"kerberos": svcInfra,
	"gssapi":   svcInfra,
	"ntlm":     svcInfra,
	"dce_rpc":  svcInfra,
	"radius":   svcInfra,
}

// splitServices normalizes a raw Zeek conn.log `service` field into a
// deduplicated, lowercased slice of DPD labels in first-seen order. An empty
// field (DPD produced no result) yields nil; a comma-separated list
// (`smb,gssapi,ntlm`) yields one entry per distinct label. Surrounding
// whitespace and empty segments are dropped.
func splitServices(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		label := strings.ToLower(strings.TrimSpace(part))
		if label == "" {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		out = append(out, label)
	}
	return out
}

// serviceCategoryOf returns the category for a single DPD label, or svcOther
// for a label DPD produced that the catalog doesn't classify (and for an empty
// label). Callers that need to distinguish "no DPD result" from "uncategorized
// protocol" check the label or splitServices output first.
func serviceCategoryOf(label string) serviceCategory {
	if c, ok := serviceCategoryByLabel[strings.ToLower(strings.TrimSpace(label))]; ok {
		return c
	}
	return svcOther
}

// serviceExpectedOnPort reports whether Zeek's DPD identified a protocol on a
// port where that protocol legitimately runs (per expectedServicePorts) — the
// positive signal that a flow is the benign protocol the port is known for. It
// cross-checks the port-only heuristics: a known-C2 port carrying its expected
// protocol (http on 8888/8008/3128) is most likely that service, not an
// implant. Multi-label fields match if any label is expected on the port;
// false for a blank or unrecognized service, or a recognized service on an
// unexpected port (that mismatch is the Protocol on Unexpected Port signal).
func serviceExpectedOnPort(raw string, port int) bool {
	for _, label := range splitServices(raw) {
		if ports, known := expectedServicePorts[label]; known && ports[port] {
			return true
		}
	}
	return false
}

// serviceCategories returns the distinct categories present in a raw service
// field (which may carry several labels), in first-seen order. It is nil for
// an unfingerprinted flow; svcOther appears only when a recognized label is
// uncategorized, never for an empty field.
func serviceCategories(raw string) []serviceCategory {
	labels := splitServices(raw)
	if len(labels) == 0 {
		return nil
	}
	var out []serviceCategory
	seen := map[serviceCategory]struct{}{}
	for _, l := range labels {
		c := serviceCategoryOf(l)
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}
