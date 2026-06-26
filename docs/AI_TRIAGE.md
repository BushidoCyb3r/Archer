# AI Triage Enrichment

An operator's guide to the opt-in AI triage feature: what it does, what
leaves the box when you use it, and how to choose a provider for your
deployment. The feature surface (endpoints, config keys, the `ai:` query
field) is in `README.md` → AI Enrichment; this doc is the *trust-boundary
and operations* companion.

> **Annotation-only.** AI triage writes an `AI Triage` note and never
> changes a finding's score, severity, or status. The model's verdict is
> decision support an analyst can override — it is not a detector and does
> not feed detection. `internal/server/enrich_annotation_only_test.go`
> locks this invariant.

---

## What it does

The **AI Triage** button (finding detail footer + the row right-click
menu) sends the evidence already collected for one finding to a configured
LLM and asks for a verdict-first briefing (`LIKELY BENIGN` /
`INVESTIGATE` / `LIKELY MALICIOUS`, with confidence and next checks). The
briefing is saved as a note. No new data is gathered — the model sees only
what the detectors and TI enrichment already produced for that finding,
plus structural context (host class, port meaning) and the analyzer's own
roll-ups.

It is a deliberate, single-finding action. **Bulk escalate never fans out
enrichment** — that would be a rate-limit and cost footgun. An optional
setting (`llm_auto_on_escalate`) runs it automatically on a *single*
escalate. A re-run while one is already in flight for the same finding is
suppressed (no duplicate briefings).

---

## The egress trust boundary

This is the one feature in Archer where finding context can leave the box.
Read this before pointing it at a cloud provider.

**Redacted before send (never leaves the box):**

- **Internal IP addresses** — RFC 1918, IPv4/IPv6 link-local, IPv6 ULA,
  loopback, *plus* every CIDR/IP in **Settings → Organization Hosts**
  (`org_internal_cidrs`). Each is replaced with a stable `HOST_n` token and
  expanded back to the real address in the saved note.
- **Internal hostnames** — any name that is, or is a subdomain of, a suffix
  you list in **Organization Hosts → internal domains**
  (`org_internal_domains`). This is the hostname analog of the CIDRs and is
  **off by default**: with no internal domains configured, hostnames are
  not redacted at all.

**Sent (by design):**

- **External threat indicators** — the C2 destination IPs, domains, JA3/JA4
  fingerprints, URIs. These are the point of the briefing, and they already
  leave the box on the TI-enrichment path. An external name never matches an
  internal suffix, so configuring internal domains does not redact your
  indicators.

**Not redacted — the residue to know about:**

- **Free-text analyst and TI notes**, and detector `Detail` prose, are sent
  so the model has the full workup. Internal *IPs* and *configured internal
  hostnames* inside them are tokenized, but free text can still carry
  internal context the redactor can't recognize deterministically — a bare
  single-label host (`DC01`), a username, an asset tag, a ticket number. If
  that matters for your data-handling rules, **use a local/enclave provider**
  (below); the redaction is a strong reducer, not a guarantee over arbitrary
  prose.

`org_internal_cidrs` and `org_internal_domains` are load-bearing for this
boundary: an internal host in a public IP range that you forgot to list, or
an internal domain you didn't add, will be treated as external and sent.
Keep both lists complete.

---

## Choosing a provider

| Provider | Where the evidence goes | Use when |
|---|---|---|
| `ollama` | A model on your local/LAN host | Air-gapped; you want zero off-box egress |
| `dod` | The US DoD GenAI platform, inside the accredited boundary | Accredited/NIPRNet-class networks needing frontier-grade synthesis without leaving the enclave |
| `custom` | Any OpenAI-compatible gateway you run | Self-hosted gateway / proxy on your network |
| `anthropic` / `openai` / `gemini` | The vendor's cloud API | You accept sending **redacted** evidence off-box |

The three self-hosted providers (`ollama`/`dod`/`custom`) keep all context
on your own network and are the air-gapped / accredited answer. The three
cloud providers send the redacted evidence to a third party.

Cloud providers are required to use `https` (cleartext `http` is rejected
at config-save, except to loopback for a local TLS-terminating proxy) so
the API key and evidence are never sent in the clear. Self-hosted providers
may use `http` on a trusted local/enclave network.

---

## Operating it

- **Enable** in Settings → AI Enrichment (admin only). The provider
  settings are validated on save — an enabled-but-unbuildable provider is
  rejected loudly rather than failing on the first click.
- **Timeout** (`llm_timeout_sec`) is bounded to 0–600s. `0` uses the 30s
  default.
- **Audit trail.** Every enrichment dispatch writes a `finding_ai_enrich`
  audit row naming the actor, the finding, the provider, and whether the
  egress was `local` or `cloud`. For accredited deployments this is the
  record of what left the enclave.
- **Prompt injection.** The evidence contains strings observed on the wire
  (SNI/Host headers, URIs, log text) which an adversary on the monitored
  network can influence. The system prompt instructs the model to treat all
  evidence as untrusted data, and the annotation-only invariant means a
  manipulated verdict can never move a finding's score or status — but treat
  the briefing as decision support, not ground truth.

---

## Quick checklist before enabling a cloud provider

1. Is a local/enclave provider (`ollama`/`dod`/`custom`) viable instead? If
   so, prefer it.
2. Are `org_internal_cidrs` and `org_internal_domains` complete for your
   environment?
3. Do your analysts' notes routinely contain internal identifiers the
   redactor won't catch? If so, the cloud path may not fit your data rules.
4. Is the base URL `https`?
