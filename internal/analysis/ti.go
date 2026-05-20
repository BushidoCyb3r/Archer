package analysis

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/parser"
)

// prefetchFeeds fetches threat intel feeds concurrently and caches results on the Analyzer.
// This runs as the first analysis step so downstream steps (checkTI, checkSuspiciousURLs) can
// reuse the data without a second network round-trip.
//
// Pre-populated caches are honored as-is: if a cache is non-nil it is treated as
// already loaded and the corresponding network fetch is skipped. Tests use this
// to inject deterministic feeds and avoid live HTTP calls. An empty (but non-nil)
// map means "feed loaded, no entries" — the same shape a fetch would produce on
// an empty upstream — and is distinct from nil ("not yet loaded").
func (a *Analyzer) prefetchFeeds(_ []string) {
	client := &http.Client{Timeout: 30 * time.Second}
	var wg sync.WaitGroup
	if a.feodoIPs == nil {
		wg.Add(1)
		go func() { defer wg.Done(); a.feodoIPs = a.fetchFeodo(client) }()
	}
	if a.urlhausIPs == nil || a.urlhausHosts == nil {
		wg.Add(1)
		go func() { defer wg.Done(); a.urlhausIPs, a.urlhausHosts = a.fetchURLhaus(client) }()
	}
	wg.Wait()

	// MISP / OpenCTI feed indicators. Snapshotted into feedSources for
	// the duration of this run so the matcher cache invalidations from a
	// concurrent feed refresh don't perturb mid-run state.
	if a.feedProvider != nil {
		a.feedSources = a.feedProvider.EnabledFeedIndicators()
	} else {
		a.feedSources = nil
	}
}

// checkSuspiciousURLs scans HTTP logs for requests to hosts listed in
// URLhaus or any enabled MISP/OpenCTI feed's domain indicators. One
// Suspicious URL finding per (src, host) pair regardless of how many
// requests; the URI of the first request is captured for context.
func (a *Analyzer) checkSuspiciousURLs(files []string) {
	if len(a.urlhausHosts) == 0 && !a.anyFeedDomains() {
		return
	}
	seen := make(map[[2]string]bool)
	for _, f := range filterFiles(files, "http") {
		a.parseLog(f, func(rec map[string]any) bool {
			src := parser.GetStr(rec, "id.orig_h")
			dst := parser.GetStr(rec, "id.resp_h")
			host := parser.GetStr(rec, "host")
			uri := parser.GetStr(rec, "uri")
			ts := parser.GetFloat(rec, "ts")
			dstPort := parser.GetInt(rec, "id.resp_p")
			if host == "" || src == "" {
				return true
			}
			h := host
			if idx := strings.LastIndex(h, ":"); idx >= 0 && strings.Count(h, ":") == 1 {
				h = h[:idx]
			}
			if a.urlhausHosts[h] {
				key := [2]string{src, h}
				if !seen[key] {
					seen[key] = true
					a.add(model.Finding{
						Type:      "Suspicious URL",
						Severity:  model.SevCritical,
						Score:     96,
						SrcIP:     src,
						DstIP:     dst,
						DstPort:   fmt.Sprint(dstPort),
						Detail:    fmt.Sprintf("URLhaus malware distribution host: %s | URI: %s", host, uri),
						Timestamp: fmtTS(ts),
					})
				}
			}
			lc := strings.ToLower(h)
			for _, fs := range a.feedSources {
				if !fs.Domains[lc] {
					continue
				}
				key := [2]string{src, fs.Source + "|" + lc}
				if seen[key] {
					continue
				}
				seen[key] = true
				feedName := strings.TrimPrefix(fs.Source, "feed:")
				detail := fmt.Sprintf("%s domain match: %s | URI: %s", feedName, host, uri)
				if tags := fs.Tags[lc]; len(tags) > 0 {
					detail += " | tags: " + strings.Join(tags, ", ")
				}
				a.add(model.Finding{
					Type:      "Suspicious URL",
					Severity:  model.SevHigh,
					Score:     90,
					SrcIP:     src,
					DstIP:     dst,
					DstPort:   fmt.Sprint(dstPort),
					Detail:    detail,
					Timestamp: fmtTS(ts),
				})
			}
			return true
		})
	}
}

// anyFeedDomains reports whether any enabled feed source carries at
// least one domain indicator. Cheap O(feeds) check that lets the HTTP
// scan early-exit when neither URLhaus nor any feed has anything to
// match against.
func (a *Analyzer) anyFeedDomains() bool {
	for _, fs := range a.feedSources {
		if len(fs.Domains) > 0 {
			return true
		}
	}
	return false
}

// tiIPObs records a single (dst-ip, src) observation for TI hit fan-out.
// One entry per distinct src per dst; repeated contacts from the same src
// bump count but don't allocate (bounds memory under pathological volumes
// and gives count as a useful signal in the finding's Detail).
type tiIPObs struct {
	port  string
	ts    float64
	proto string // "conn" | "http" | "ssl" | "finding"
	count int
}

// tiDomainObs is the domain-keyed analogue of tiIPObs. uri is captured for
// HTTP-sourced observations so the resulting finding can show the analyst
// the exact path that triggered the hit, not just the host.
type tiDomainObs struct {
	ts    float64
	proto string // "dns" | "http" | "finding"
	qtype string // dns only
	uri   string // http only — first URI we saw this src request from this host
	port  string // http only — actual resp port; falls back to "80" in emit if empty
	count int
}

func (a *Analyzer) checkTI(files []string) {
	// Use pre-fetched feeds from prefetchFeeds step
	feodoIPs := a.feodoIPs
	urlhausIPs := a.urlhausIPs
	urlhausHosts := a.urlhausHosts

	// Two-phase design. Phase A is a cheap dst-only sweep (one bool per
	// distinct external IP/domain) used purely to feed the feed-match
	// loops and the OTX/AbuseIPDB rate-capped lookups. Phase B is a
	// targeted per-source sweep that ONLY allocates per-(dst, src)
	// observation entries for dsts that actually matched a feed (the
	// "winners"). Without this split, Phase B's allocations were the
	// dominant memory cost on large datasets — millions of map entries
	// for dsts that never matched anything, GC-thrashing against
	// GOMEMLIMIT. With the split, the heavy structures are bounded by
	// the feed-hit count, which is small for any sane dataset.
	//
	// Both phases parallelize file scans across the analyzer's worker
	// pool (parallelEach handles bounding by CPU count and memory budget).

	conns := filterFiles(files, "conn")
	dnsLogs := filterFiles(files, "dns")
	httpLogs := filterFiles(files, "http")
	sslLogs := filterFiles(files, "ssl")

	// ── Phase A: dst-only collection ───────────────────────────────────────
	dstIPSet := make(map[string]bool)
	dstDomainSet := make(map[string]bool)
	var muA sync.Mutex
	addDstIP := func(ip string) {
		muA.Lock()
		dstIPSet[ip] = true
		muA.Unlock()
	}
	addDstDomain := func(d string) {
		muA.Lock()
		dstDomainSet[d] = true
		muA.Unlock()
	}

	a.parallelEach(conns, func(path string) {
		a.parseLog(path, func(rec map[string]any) bool {
			dst := parser.GetStr(rec, "id.resp_h")
			if dst != "" && !isPrivateIP(dst) && isIPAddr(dst) {
				addDstIP(dst)
			}
			return true
		})
	})
	a.parallelEach(dnsLogs, func(path string) {
		a.parseLog(path, func(rec map[string]any) bool {
			q := parser.GetStr(rec, "query")
			if q != "" && !isIPAddr(q) {
				addDstDomain(q)
			}
			return true
		})
	})
	a.parallelEach(httpLogs, func(path string) {
		a.parseLog(path, func(rec map[string]any) bool {
			host := parser.GetStr(rec, "host")
			if host == "" {
				return true
			}
			if i := strings.LastIndex(host, ":"); i >= 0 && strings.Count(host, ":") == 1 {
				host = host[:i]
			}
			if host == "" {
				return true
			}
			if isIPAddr(host) {
				addDstIP(host)
			} else {
				addDstDomain(host)
			}
			return true
		})
	})

	// Source 4 (existing findings) into the dst-only set. Synthetic dsts
	// don't appear in the log scans above but can still match feeds.
	a.mu.RLock()
	for _, f := range a.findings {
		dst := f.DstIP
		if dst == "" || isPrivateIP(dst) ||
			dst == "(network)" || dst == "(escalation)" || dst == "(cert)" {
			continue
		}
		if isIPAddr(dst) {
			dstIPSet[dst] = true
		} else {
			dstDomainSet[dst] = true
		}
	}
	a.mu.RUnlock()

	// ── Feed matching → winners ────────────────────────────────────────────
	type tiHit struct {
		dst    string
		source string
		detail string
		score  int
		sev    model.Severity
	}
	var hits []tiHit

	// Match against FeodoTracker
	for ip := range dstIPSet {
		if feodoIPs[ip] {
			hits = append(hits, tiHit{
				dst:    ip,
				source: "FeodoTracker",
				detail: fmt.Sprintf("FeodoTracker botnet C2 IP: %s — Emotet/TrickBot/Dridex infrastructure", ip),
				score:  99,
				sev:    model.SevCritical,
			})
		}
	}

	// Match against URLhaus
	for ip := range dstIPSet {
		if urlhausIPs[ip] {
			hits = append(hits, tiHit{
				dst:    ip,
				source: "URLhaus",
				detail: fmt.Sprintf("URLhaus malware distribution IP: %s", ip),
				score:  97,
				sev:    model.SevCritical,
			})
		}
	}
	for host := range dstDomainSet {
		if urlhausHosts[host] {
			hits = append(hits, tiHit{
				dst:    host,
				source: "URLhaus",
				detail: fmt.Sprintf("URLhaus malware distribution domain: %s", host),
				score:  97,
				sev:    model.SevCritical,
			})
		}
	}

	// Match against MISP / OpenCTI feeds. One bucket per enabled feed,
	// already type-segregated. Hit detail mentions the feed name and
	// any upstream-supplied tags so the analyst can see provenance
	// without cross-referencing back to MISP/OpenCTI.
	for _, fs := range a.feedSources {
		for ip := range dstIPSet {
			matched := false
			if fs.IPs[ip] {
				matched = true
			} else if len(fs.CIDRs) > 0 {
				if parsed := net.ParseIP(ip); parsed != nil {
					for _, cidr := range fs.CIDRs {
						if cidr.Contains(parsed) {
							matched = true
							break
						}
					}
				}
			}
			if !matched {
				continue
			}
			hits = append(hits, tiHit{
				dst:    ip,
				source: fs.Source,
				detail: feedHitDetail(fs.Source, ip, fs.Tags[ip]),
				score:  90,
				sev:    model.SevHigh,
			})
		}
		for d := range dstDomainSet {
			lc := strings.ToLower(d)
			if !fs.Domains[lc] {
				continue
			}
			hits = append(hits, tiHit{
				dst:    d,
				source: fs.Source,
				detail: feedHitDetail(fs.Source, d, fs.Tags[lc]),
				score:  90,
				sev:    model.SevHigh,
			})
		}
	}

	// OTX and AbuseIPDB require a client (only if keys are configured)
	client := &http.Client{Timeout: time.Duration(a.cfg.TITimeoutSec) * time.Second}

	// OTX — cap at 20 IPs
	if a.cfg.OTXAPIKey != "" && len(dstIPSet) > 0 {
		for _, ip := range pickN(dstIPSet, 20) {
			detail, score := a.checkOTX(client, ip, a.cfg.OTXAPIKey)
			if detail != "" {
				sev := model.SevHigh
				if score >= 7 {
					sev = model.SevCritical
				}
				hits = append(hits, tiHit{
					dst: ip, source: "OTX",
					detail: detail,
					score:  int(math.Min(float64(70+score*3), 99)),
					sev:    sev,
				})
			}
		}
	}

	// AbuseIPDB — cap at 10 IPs
	if a.cfg.AbuseIPDBAPIKey != "" && len(dstIPSet) > 0 {
		for _, ip := range pickN(dstIPSet, 10) {
			detail, score := a.checkAbuseIPDB(client, ip, a.cfg.AbuseIPDBAPIKey)
			if detail != "" {
				sev := model.SevHigh
				if score >= 80 {
					sev = model.SevCritical
				}
				hits = append(hits, tiHit{
					dst: ip, source: "AbuseIPDB",
					detail: detail,
					score:  int(math.Min(float64(50+score/5), 99)),
					sev:    sev,
				})
			}
		}
	}

	// No hits → no Phase B work, no findings to emit. Early exit means
	// we don't allocate any of the per-source bookkeeping at all on the
	// (very common) "clean dataset" path.
	if len(hits) == 0 {
		return
	}

	// Build the winners filter set — small, bounded by len(hits).
	winnerIPs := make(map[string]bool)
	winnerDomains := make(map[string]bool)
	for _, h := range hits {
		if isIPAddr(h.dst) {
			winnerIPs[h.dst] = true
		} else {
			winnerDomains[h.dst] = true
		}
	}

	// ── Phase B: targeted per-source collection ────────────────────────────
	// Allocates per-(dst, src) entries ONLY when the dst is in the winner
	// set. The fast-path check happens before any other parser.GetXxx
	// calls so non-matching records pay almost nothing per record.
	dstIPs := make(map[string]map[string]*tiIPObs)
	dstDomains := make(map[string]map[string]*tiDomainObs)
	var muB sync.Mutex

	addIPObs := func(dst, src, port, proto string, ts float64) {
		if !winnerIPs[dst] || src == "" {
			return
		}
		muB.Lock()
		defer muB.Unlock()
		bySrc, ok := dstIPs[dst]
		if !ok {
			bySrc = make(map[string]*tiIPObs)
			dstIPs[dst] = bySrc
		}
		if cur, ok := bySrc[src]; ok {
			cur.count++
			if ts > 0 && (cur.ts == 0 || ts < cur.ts) {
				cur.ts = ts
			}
			if proto == "ssl" && cur.proto == "conn" {
				cur.proto = proto
			}
			return
		}
		bySrc[src] = &tiIPObs{port: port, ts: ts, proto: proto, count: 1}
	}

	addDomainObs := func(dst, src, qtype, proto, uri, port string, ts float64) {
		if !winnerDomains[dst] || src == "" {
			return
		}
		muB.Lock()
		defer muB.Unlock()
		bySrc, ok := dstDomains[dst]
		if !ok {
			bySrc = make(map[string]*tiDomainObs)
			dstDomains[dst] = bySrc
		}
		if cur, ok := bySrc[src]; ok {
			cur.count++
			if ts > 0 && (cur.ts == 0 || ts < cur.ts) {
				cur.ts = ts
			}
			if cur.uri == "" && uri != "" {
				cur.uri = uri
			}
			return
		}
		bySrc[src] = &tiDomainObs{ts: ts, proto: proto, qtype: qtype, uri: uri, port: port, count: 1}
	}

	// Source 1 (targeted): conn.log, only for winning dsts.
	a.parallelEach(conns, func(path string) {
		a.parseLog(path, func(rec map[string]any) bool {
			dst := parser.GetStr(rec, "id.resp_h")
			if !winnerIPs[dst] {
				return true
			}
			src := parser.GetStr(rec, "id.orig_h")
			port := fmt.Sprint(parser.GetInt(rec, "id.resp_p"))
			ts := parser.GetFloat(rec, "ts")
			addIPObs(dst, src, port, "conn", ts)
			return true
		})
	})

	// Source 1b (targeted): ssl.log, only for winning IPs. Runs after the
	// conn scan so the conn→ssl proto upgrade in addIPObs fires correctly.
	a.parallelEach(sslLogs, func(path string) {
		a.parseLog(path, func(rec map[string]any) bool {
			dst := parser.GetStr(rec, "id.resp_h")
			if !winnerIPs[dst] {
				return true
			}
			src := parser.GetStr(rec, "id.orig_h")
			port := fmt.Sprint(parser.GetInt(rec, "id.resp_p"))
			ts := parser.GetFloat(rec, "ts")
			addIPObs(dst, src, port, "ssl", ts)
			return true
		})
	})

	// Source 2 (targeted): dns.log, only for winning domains.
	// id.orig_h is the host that issued the query. NOTE: in environments
	// with an internal DNS forwarder/resolver, this will be the resolver's
	// IP, not the workstation that triggered the lookup — Zeek can't see
	// past the resolver from the wire alone. Attribution still lands on
	// "the host that did the lookup Zeek observed", which is at least one
	// hop short of the workstation but better than no attribution.
	a.parallelEach(dnsLogs, func(path string) {
		a.parseLog(path, func(rec map[string]any) bool {
			q := parser.GetStr(rec, "query")
			if !winnerDomains[q] {
				return true
			}
			src := parser.GetStr(rec, "id.orig_h")
			qtype := parser.GetStr(rec, "qtype_name")
			ts := parser.GetFloat(rec, "ts")
			addDomainObs(q, src, qtype, "dns", "", "", ts)
			return true
		})
	})

	// Source 3 (targeted): http.log. Both winnerIPs (Host header is a
	// bare IP) and winnerDomains (Host header is a name) are checked.
	a.parallelEach(httpLogs, func(path string) {
		a.parseLog(path, func(rec map[string]any) bool {
			host := parser.GetStr(rec, "host")
			if host == "" {
				return true
			}
			if i := strings.LastIndex(host, ":"); i >= 0 && strings.Count(host, ":") == 1 {
				host = host[:i]
			}
			if host == "" {
				return true
			}
			if isIPAddr(host) {
				if !winnerIPs[host] {
					return true
				}
				src := parser.GetStr(rec, "id.orig_h")
				port := fmt.Sprint(parser.GetInt(rec, "id.resp_p"))
				ts := parser.GetFloat(rec, "ts")
				addIPObs(host, src, port, "http", ts)
			} else {
				if !winnerDomains[host] {
					return true
				}
				src := parser.GetStr(rec, "id.orig_h")
				uri := parser.GetStr(rec, "uri")
				ts := parser.GetFloat(rec, "ts")
				addDomainObs(host, src, "", "http", uri, fmt.Sprint(parser.GetInt(rec, "id.resp_p")), ts)
			}
			return true
		})
	})

	// Source 4 (targeted): existing findings, attribution-only — pull the
	// finding's SrcIP if the dst happens to be a winner. Catches dsts
	// reported by detectors that don't read from conn/dns/http directly,
	// or that produce a synthetic dst the log scans above can't see.
	a.mu.RLock()
	for _, f := range a.findings {
		dst := f.DstIP
		if dst == "" {
			continue
		}
		isIP := isIPAddr(dst)
		if isIP && !winnerIPs[dst] {
			continue
		}
		if !isIP && !winnerDomains[dst] {
			continue
		}
		src := f.SrcIP
		switch src {
		case "(TI)", "(network)", "(escalation)", "(cert)":
			src = ""
		}
		if src == "" {
			continue
		}
		if isIP {
			addIPObs(dst, src, f.DstPort, "finding", 0)
		} else {
			addDomainObs(dst, src, "", "finding", "", "", 0)
		}
	}
	a.mu.RUnlock()

	// Dedup hits by destination. Multiple TI sources can flag the same
	// dst — MISP + FeodoTracker + OTX commonly overlap on well-known
	// botnet IPs. Pre-fix the emit loop below ran once per (dst, source)
	// pair AND once per src contacting that dst, producing N findings
	// with identical Fingerprint (Type, SrcIP, DstIP, DstPort) for one
	// real detection. SetFindings's carry-forward branch returned the
	// same old.ID for all N, the second INSERT collided on the UNIQUE
	// primary key, and the entire saveFindings transaction rolled back —
	// leaving the DB stuck in its pre-Analyze state (visible as
	// "rollups disappear after rebuild" because the in-memory s.findings
	// did get updated but never reached disk).
	//
	// Merge keeps the highest-scored row's score and severity (Feodo's
	// 99/Critical beats a generic feed's 90/High). Detail concatenates
	// every source's evidence so the analyst still sees provenance from
	// all matching sources. SourceFile (the TI source label, repurposed
	// for /api/findings provenance) joins source labels with " + ".
	mergedDsts := make(map[string]tiHit, len(hits))
	for _, h := range hits {
		e, ok := mergedDsts[h.dst]
		if !ok {
			mergedDsts[h.dst] = h
			continue
		}
		if h.score > e.score {
			e.score = h.score
			e.sev = h.sev
		}
		e.source = e.source + " + " + h.source
		e.detail = e.detail + " | " + h.detail
		mergedDsts[h.dst] = e
	}

	// Sort dsts for deterministic emit order — a.add assigns sequential
	// IDs in call order, so a stable iteration order keeps fresh IDs
	// stable across re-runs on identical input. Mirrors the srcKeys
	// pattern in risk.go (NEW-68).
	dsts := make([]string, 0, len(mergedDsts))
	for d := range mergedDsts {
		dsts = append(dsts, d)
	}
	sort.Strings(dsts)

	// ── Per-source fan-out emit ────────────────────────────────────────────
	// Emit one Threat Intel Hit per distinct src that contacted the bad
	// dst, with real port/timestamp/URI/qtype context in the Detail. Only
	// when no src attribution is available do we fall back to the
	// SrcIP="(TI)" placeholder — that's the "I know this dst is bad but
	// can't tell you who talked to it" case (e.g. dst pulled from a
	// synthetic finding with no per-host scope).
	nowTS := time.Now().UTC().Format("2006-01-02 15:04:05")
	for _, dst := range dsts {
		h := mergedDsts[dst]
		isIP := isIPAddr(h.dst)
		var srcCount int
		if isIP {
			srcCount = len(dstIPs[h.dst])
		} else {
			srcCount = len(dstDomains[h.dst])
		}

		tiType := model.TypeTIHitDomain
		if isIP {
			tiType = model.TypeTIHitIP
		}

		if srcCount == 0 {
			a.add(model.Finding{
				Type:       tiType,
				Severity:   h.sev,
				Score:      h.score,
				SrcIP:      "(TI)",
				DstIP:      h.dst,
				Detail:     h.detail,
				Timestamp:  nowTS,
				SourceFile: h.source,
			})
			continue
		}

		if isIP {
			for src, obs := range dstIPs[h.dst] {
				detail := h.detail + tiIPEvidence(obs.proto, obs.port, obs.count)
				ts := nowTS
				if obs.ts > 0 {
					ts = fmtTS(obs.ts)
				}
				a.add(model.Finding{
					Type:       tiType,
					Severity:   h.sev,
					Score:      h.score,
					SrcIP:      src,
					DstIP:      h.dst,
					DstPort:    obs.port,
					Detail:     detail,
					Timestamp:  ts,
					SourceFile: h.source,
				})
			}
		} else {
			for src, obs := range dstDomains[h.dst] {
				detail := h.detail + tiDomainEvidence(obs.proto, obs.qtype, obs.uri, obs.count)
				port := obs.port
				if port == "" {
					switch obs.proto {
					case "dns":
						port = "53"
					case "http":
						port = "80"
					}
				}
				ts := nowTS
				if obs.ts > 0 {
					ts = fmtTS(obs.ts)
				}
				a.add(model.Finding{
					Type:       tiType,
					Severity:   h.sev,
					Score:      h.score,
					SrcIP:      src,
					DstIP:      h.dst,
					DstPort:    port,
					Detail:     detail,
					Timestamp:  ts,
					SourceFile: h.source,
				})
			}
		}
	}
}

// feedHitDetail formats the per-finding Detail line for a MISP /
// OpenCTI feed match. Source is "feed:<name>"; tags (if any) are
// upstream labels — surfaced inline so analysts see provenance and
// upstream context without bouncing to MISP. Format mirrors the
// built-in URLhaus / Feodo lines for visual consistency.
func feedHitDetail(source, ind string, tags []string) string {
	feedName := strings.TrimPrefix(source, "feed:")
	if len(tags) == 0 {
		return fmt.Sprintf("%s indicator match: %s", feedName, ind)
	}
	return fmt.Sprintf("%s indicator match: %s — tags: %s", feedName, ind, strings.Join(tags, ", "))
}

// tiIPEvidence formats the per-source observation context appended to a
// Threat Intel Hit's Detail field for IP-based matches.
func tiIPEvidence(proto, port string, count int) string {
	switch proto {
	case "conn":
		return fmt.Sprintf(" — observed via conn on port %s (%d session(s))", port, count)
	case "http":
		return fmt.Sprintf(" — observed via HTTP on port %s (%d request(s))", port, count)
	case "ssl":
		return fmt.Sprintf(" — observed via TLS on port %s (%d session(s))", port, count)
	case "finding":
		return " — pulled from a prior detection's destination context (no fresh log evidence in this run)"
	}
	return ""
}

// tiDomainEvidence formats the per-source observation context appended to
// a Threat Intel Hit's Detail field for domain-based matches.
func tiDomainEvidence(proto, qtype, uri string, count int) string {
	switch proto {
	case "dns":
		if qtype == "" {
			qtype = "DNS"
		}
		return fmt.Sprintf(" — DNS %s query (%d lookup(s))", qtype, count)
	case "http":
		if uri == "" {
			return fmt.Sprintf(" — HTTP Host header (%d request(s))", count)
		}
		return fmt.Sprintf(" — HTTP request to %s (%d request(s))", uri, count)
	case "finding":
		return " — pulled from a prior detection's destination context (no fresh log evidence in this run)"
	}
	return ""
}

// pickN returns up to limit keys from a string-keyed set. Used to rate-cap
// the OTX/AbuseIPDB API loops: those services have free-tier quotas a
// single analysis run can chew through, so we sample rather than enumerate.
// Map iteration order is non-deterministic — the sample varies across runs
// on the same dataset; that is intentional.
func pickN(m map[string]bool, limit int) []string {
	out := make([]string, 0, limit)
	for k := range m {
		out = append(out, k)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// All four functions below carry status-aware error reporting.
// Pre-fix any non-2xx response (401 bad key, 429 rate limited, 503
// upstream sick) silently fell through to "no hit" because the
// JSON decoder happily decoded the (often empty / HTML-error /
// short-circuit) response body into the empty target struct, and
// the caller used count==0 to mean "clean." Operators looked at a
// finding-detail panel showing OTX clean and concluded the dataset
// was clean. Audit 2026-05-10 NEW-1; same trust-bug class as the
// parser swallowing fix one release earlier. Now: status checked
// before the body is decoded; failures route through
// Analyzer.recordTIError so they surface in the SSE status banner
// and accumulate in TIErrors() for end-of-run reporting.

func (a *Analyzer) fetchFeodo(client *http.Client) map[string]bool {
	const source = "Feodo Tracker"
	resp, err := client.Get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
	if err != nil {
		a.recordTIError(source, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		a.recordTIError(source, fmt.Errorf("HTTP %d", resp.StatusCode))
		return nil
	}
	ips := make(map[string]bool)
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips[line] = true
	}
	return ips
}

func (a *Analyzer) fetchURLhaus(client *http.Client) (ips, hosts map[string]bool) {
	const source = "URLhaus"
	ips = make(map[string]bool)
	hosts = make(map[string]bool)
	// csv_online = only currently-active URLs (much smaller than full history)
	resp, err := client.Get("https://urlhaus.abuse.ch/downloads/csv_online/")
	if err != nil {
		a.recordTIError(source, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		a.recordTIError(source, fmt.Errorf("HTTP %d", resp.StatusCode))
		return
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}
		// URL is in field index 2
		rawURL := strings.Trim(parts[2], `"`)
		// Extract host
		h := extractHost(rawURL)
		if h == "" {
			continue
		}
		if isIPAddr(h) {
			ips[h] = true
		} else {
			hosts[h] = true
		}
	}
	return
}

func (a *Analyzer) checkOTX(client *http.Client, ip, apiKey string) (string, float64) {
	const source = "OTX"
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", ip)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-OTX-API-KEY", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		a.recordTIError(source, err)
		return "", 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		a.recordTIError(source, fmt.Errorf("HTTP %d (lookup of %s)", resp.StatusCode, ip))
		return "", 0
	}
	var data struct {
		PulseInfo struct {
			Count int `json:"count"`
		} `json:"pulse_info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		a.recordTIError(source, fmt.Errorf("decode (lookup of %s): %w", ip, err))
		return "", 0
	}
	if data.PulseInfo.Count == 0 {
		return "", 0
	}
	return fmt.Sprintf("OTX: %d threat pulses for %s", data.PulseInfo.Count, ip), float64(data.PulseInfo.Count)
}

func (a *Analyzer) checkAbuseIPDB(client *http.Client, ip, apiKey string) (string, float64) {
	const source = "AbuseIPDB"
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		a.recordTIError(source, err)
		return "", 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		a.recordTIError(source, fmt.Errorf("HTTP %d (lookup of %s)", resp.StatusCode, ip))
		return "", 0
	}
	var data struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			TotalReports         int    `json:"totalReports"`
			CountryCode          string `json:"countryCode"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		a.recordTIError(source, fmt.Errorf("decode (lookup of %s): %w", ip, err))
		return "", 0
	}
	score := float64(data.Data.AbuseConfidenceScore)
	if score == 0 {
		return "", 0
	}
	return fmt.Sprintf("AbuseIPDB: confidence=%d%% reports=%d country=%s", data.Data.AbuseConfidenceScore, data.Data.TotalReports, data.Data.CountryCode), score
}

// isIPAddr reports whether s is a literal IP address. Used inside
// checkTI to route bucket queries between IP and domain matchers.
//
// Pre-fix this counted dots and treated 3 dots as IPv4 (and 2+ colons
// as IPv6). 3-dot FQDNs like cdn.staging.example.com or
// subdomain.team.acme.io fell into the IP bucket and never got
// matched against the domain feeds — a malicious 3-label hostname
// on URLhaus would silently miss. Audit 2026-05-10 NEW-3.
//
// net.ParseIP is the canonical answer: returns nil for any string
// that isn't a literal v4 or v6 address. One round-trip through
// the stdlib parser per call; cheap relative to the surrounding
// matcher work.
func isIPAddr(s string) bool {
	return net.ParseIP(s) != nil
}

// extractHost returns the host of a URL string, dropping scheme,
// userinfo, port, and path. Pre-fix the hand-rolled trim chain
// missed `user:pass@host` URLs — the early colon in the userinfo
// was misread by the port-strip step (which checks for "no other
// colon before the last colon"), leaving `user:pass@evil.com`
// unmatched against URLhaus / feed buckets. Audit 2026-05-10.
// net/url.Parse handles all of this; falls back to the legacy
// trim chain if the input lacks a scheme (URLhaus's CSV occasionally
// emits scheme-less host strings).
func extractHost(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		if h := u.Hostname(); h != "" {
			return h
		}
	}
	// Fallback for scheme-less inputs that net/url.Parse won't
	// recognise as URLs (treats them as paths).
	for _, scheme := range []string{"https://", "http://"} {
		if strings.HasPrefix(rawURL, scheme) {
			rawURL = rawURL[len(scheme):]
			break
		}
	}
	if i := strings.Index(rawURL, "@"); i >= 0 {
		rawURL = rawURL[i+1:]
	}
	if i := strings.Index(rawURL, "/"); i >= 0 {
		rawURL = rawURL[:i]
	}
	if i := strings.LastIndex(rawURL, ":"); i >= 0 && !strings.Contains(rawURL[:i], ":") {
		rawURL = rawURL[:i]
	}
	return rawURL
}
