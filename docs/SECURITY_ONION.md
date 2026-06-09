# Configuring a SIEM receiver (Security Onion)

Archer can forward each **escalated** finding to an external SIEM as **bare CEF
over UDP**. This guide configures **Security Onion** as the receiver. Archer
itself names the feature generically ("SIEM forwarding") — the CEF / port /
firewall specifics live here.

> **Version note.** This guide was validated end-to-end against a **Security
> Onion 3.1** grid. The CEF-integration and firewall *model* below is stable
> across recent Security Onion releases, but **exact SOC Console menu labels and
> firewall-chain names can differ between versions** — treat your version's own
> **Elastic Fleet** and **Firewall** documentation as authoritative for the
> clicks. The actionable goal never changes: *the CEF integration listening on
> UDP 9003, and Archer's egress IP allowed to that port.* (The official SO docs
> currently publish the 2.4 guides, e.g. the UniFi CEF walkthrough at
> <https://docs.securityonion.net/en/2.4/unifi.html>, which is the same CEF
> integration Archer targets.)

Archer reuses Security Onion's supported **Common Event Format (CEF)** Elastic
Fleet integration — the same UDP-ingest pattern SO documents for UniFi. No SOC
Cases API, no custom Logstash pipeline. Forwarded findings land in **Hunt /
Dashboards** as fully-fielded ECS records.

**How it works:** when an analyst escalates a finding, Archer sends one UDP
datagram to the SIEM — a single bare CEF line that begins at `CEF:0|Archer|...`
(no RFC3164 syslog header, so the CEF integration's `decode_cef` input parses it
directly). The send is **best-effort and fire-and-forget** (UDP, no retry); if
no SIEM is configured, escalation behaves exactly as before.

---

## Before you begin

You need:

- **Admin** access to the SO Console and to the Archer host.
- The **SO node IP** that will run the CEF integration (the manager / receiving
  node).
- **Archer's egress IP as Security Onion will see it** — read the note below,
  this is the single most common setup mistake.

### Which Archer IP to allow (Docker SNAT)

Archer runs inside a Docker container, so Security Onion does **not** see the
container's internal IP — outbound traffic is source-NAT'd to the **Archer
host's** egress IP. Find that exact IP on the Archer host:

```bash
ip route get <SO-node-IP>
```

The `src` value in the output is the address SO will see on every Archer
datagram, and the address you must allow in the firewall host group (Step 2).
Example:

```
$ ip route get 10.0.0.2
10.0.0.2 via 10.0.0.1 dev eth0 src 10.0.0.4 ...
                                       ^^^^^^^^^^  ← use this IP
```

---

## Step 1 — Add the CEF integration (Elastic Fleet)

In the SO Console, go to **Elastic Fleet → Agent policies** and select your grid
policy (e.g. `so-grid-nodes_general`):

1. Click **Add integration**.
2. Search for **"Common Event Format (CEF)"** and select it.
3. Click **Add Common Event Format (CEF)**.
4. Configure the inputs:
   - **Disable** "Collect CEF application logs (input: logfile)"
   - **Disable** "Collect CEF application logs (input: tcp)"
   - **Enable** "Collect CEF application logs (input: udp)"
   - Change **"Syslog Host"** from `localhost` to **`0.0.0.0`** (so it listens
     on all interfaces, not just loopback).
   - **"Syslog Port"** defaults to **`9003`** — leave it.
5. Click **Save and continue**, then **Save and deploy changes**.

> If you already ingest UniFi system logs, this CEF integration is **already
> running on UDP 9003** — Archer reuses it. You do not need a second integration;
> skip to Step 2 and just make sure Archer's IP is allowed through the firewall.

---

## Step 2 — Allow Archer through the Security Onion firewall

Security Onion drops anything not explicitly allowed. You need to allow
**Archer's egress IP** (the `src` from *Before you begin*) to reach the
receiving node on **UDP 9003**. Two ways:

### Option A — SOC Console (Administration → Configuration → `firewall`)

1. Open the **Options** menu and enable **"Show advanced settings"**.
2. **Host group** — `firewall` → `hostgroups` → `customhostgroup0`. Add
   **Archer's egress IP** and save. *(If UniFi already uses `customhostgroup0`,
   add Archer's IP to it or use the next free `customhostgroupN`.)*
3. **Port group** — `firewall` → `portgroups` → `customportgroup0` → `udp`.
   Ensure **`9003`** is listed and save. *(If you set up UniFi, 9003 is already
   here.)*
4. **Bind them to the node** — `firewall` → `role` → select the **receiving node
   type** → `chain` → select the chain → `hostgroups` → `customhostgroup0` →
   `portgroups` → enter **`customportgroup0`** and save.
   - **Which chain?** Security Onion's general firewall guide binds custom rules
     to the **`DOCKER-USER`** chain (grid services, including the Fleet
     integrations, are container-published). The UniFi CEF walkthrough references
     **`INPUT`**. Use whichever your Security Onion version's firewall
     documentation specifies — the goal is the same: Archer's IP → UDP 9003 on
     this node.
5. Open **Options → SYNCHRONIZE GRID** to apply immediately.

### Option B — CLI (on the Security Onion manager)

```bash
sudo so-firewall includehost customhostgroup0 <archer-egress-IP>
sudo so-firewall apply
```

(Confirm `customhostgroup0` is the host group bound to the UDP-9003 port group on
the receiving node; adjust the group name to match your grid.)

> **Capture happens before the firewall drop.** A `tcpdump` on the SO node will
> show Archer's packets arriving on the wire **even while the firewall is
> dropping them**. So "I can see the packets in tcpdump" does **not** mean they
> were accepted — confirm the host group contains Archer's egress IP and the
> firewall rule is bound on the node (Step 2, Option A → bind step).

---

## Step 3 — Configure Archer

Open **Settings** (gear icon — admin only) and find the **SIEM forwarding**
section:

- **Forward escalated findings to a SIEM** — enable the checkbox.
- **SIEM host (IP)** — the **SO node IP** (an IP, not a hostname — Archer's
  egress is matched to the firewall host group by IP).
- **SIEM port** — **`9003`**.
- Click **Save**.

The setting takes effect **immediately** (no restart). **No credential is
needed** — UDP carries none, and the firewall host group is the trust boundary.

---

## Step 4 — Verify

1. **Watch the wire on the SO node** while you escalate a finding:

   ```bash
   sudo tcpdump -nA -i any 'udp and port 9003 and host <archer-egress-IP>'
   ```

2. In Archer, **escalate a finding** — it must be a fresh **open → escalated**
   transition (re-escalating an already-escalated finding does **not** re-send;
   see *Re-sending* below).

3. The capture should show a datagram from Archer beginning at
   `CEF:0|Archer|Archer|<version>|...`.

4. In the SO Console → **Hunt** (or **Dashboards / Discover**), search:

   ```
   observer.vendor:Archer
   ```

   The finding appears with `source.ip` / `destination.ip` / `destination.port`,
   the finding type in `event.code` / `cef.name`, and the Archer fields under
   `cef.extensions.*`. The **`ArcherUrl`** field is a clickable deep-link back to
   the finding in Archer.

5. To confirm ingestion **and surface any parse error**, query the CEF index
   directly on the SO node:

   ```bash
   sudo curl -s --config /opt/so/conf/elasticsearch/curl.config \
     "https://localhost:9200/logs-cef.log-*/_search?pretty" \
     -H 'Content-Type: application/json' -d '{
     "size": 5, "sort": [{"@timestamp":"desc"}],
     "query": {"term": {"observer.vendor": "Archer"}},
     "_source": ["@timestamp","observer.vendor","event.code","source.ip",
                 "destination.ip","message","error.message","_ignored"]
   }'
   ```

   Success = Archer documents returned with **no** `error.message` and **no**
   `_ignored`.

---

## Field reference

The CEF **header** is `CEF:0|Archer|Archer|<archer-version>|<type>|<type>|<sev>|`
and maps to:

| CEF header field | ECS |
|---|---|
| Device Vendor / Product = `Archer` | `observer.vendor` / `observer.product` |
| Device Version (`<archer-version>`) | `observer.version` |
| Signature ID / Name = the finding type | `event.code` / `cef.name` |
| Severity (`<sev>`, the 0–100 score scaled to 0–10) | `event.severity` |

CEF **extensions** (only sent when the source value is present):

| CEF key | Source | ECS / location |
|---|---|---|
| `src` / `dst` / `dpt` | finding 5-tuple | `source.ip` / `destination.ip` / `destination.port` |
| `app` | Zeek DPD L7 service | `network.application` |
| `dhost` | destination hostname/domain | `destination.domain` — the C2 pivot |
| `request` | HTTP-beacon URI | `url.original` |
| `reason` | IOC / TI source (e.g. `Feed: URLhaus`) | `event.reason` |
| `msg` | the finding's detail line (≤ 600 chars) | `message` |
| `externalId` | Archer finding id | `cef.extensions.externalId` |
| `cs1`..`cs6` (labelled) | `ArcherScore`, `ArcherSensor`, `ArcherUrl`, `ArcherAnalyst`, `ja3`, `ja4` | `cef.extensions.deviceCustomString1..6` |
| `flexString1` (label `ATT&CK`) | MITRE ATT&CK technique id(s) | `cef.extensions.flexString1` |
| `flexString2` (label `ArcherEventTime`) | the finding's event time, as text | `cef.extensions.flexString2` |

Heavier evidence — beacon intervals, sub-scores, correlations, and the live
TI-enrichment lookups escalation triggers — stays in Archer, one click away via
`ArcherUrl`.

---

## Notes & caveats

- **Bare CEF, not syslog-wrapped.** Archer's line starts at `CEF:0|`. The CEF
  integration's `decode_cef` input only parses lines that begin with `CEF:` — a
  syslog-framed (`<134>… host CEF:0|…`) line would be dropped. (This is the same
  reason UniFi's bare CEF works.)
- **No CEF `rt`.** `decode_cef` rejects an epoch-millis `rt` and silently drops
  the whole event, so Archer does **not** send `rt`. The finding's event time
  rides as text in `flexString2`, and `@timestamp` is the **ingest time** — which
  equals the escalation/forward time (the right time for an escalation alert).
- **Forwarded events are logs, not alerts.** They land in the `cef.log` dataset
  (visible in Hunt / Dashboards / Discover), **not** SO's **Alerts** queue. To
  raise them as alerts, add a Sigma / detection rule keyed on
  `observer.vendor:Archer`.
- **Best-effort, fires once.** The forward fires once, on the open → escalated
  transition, over UDP with no retry. If the SIEM or the firewall rule was not
  ready when a finding was escalated, that one datagram is gone — see below.

### Re-sending a finding that was escalated before setup

Because the forward fires only on the transition **into** escalated, a finding
that is already escalated will not re-send (the Escalate button is greyed out
for it). To push it after fixing setup: **Acknowledge** the finding, then
**Escalate** it again — that is a fresh transition and fires a new forward.

---

## Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| **No packets** in `tcpdump` on the SO node when you escalate | Archer isn't sending, or wrong host/port, or you re-escalated an already-escalated finding | Confirm Settings → SIEM forwarding is enabled with the SO IP + 9003; escalate a *fresh* finding; on the Archer host check `docker compose logs archer \| grep -i "SIEM forward"` for a `SIEM forward failed` line (a send error). |
| **`tcpdump` shows packets, but nothing in Hunt** | Firewall is dropping them — almost always the host group is missing Archer's **egress** IP | Re-check Step 2: the host group must contain the `ip route get <SO-IP>` `src` value (Docker SNAT), and the firewall rule must bind that host group to `customportgroup0` (UDP 9003) on the node. Synchronize the grid. |
| **Events ingest but a field is missing/odd** | A finding-specific value; inspect the raw event | In Hunt, expand the event and read `cef.extensions.*`; query the `logs-cef.log-*` index (Step 4.5) and check `error.message` / `_ignored`. |
| **A finding you escalated earlier never arrived** | It was escalated before the receiver/firewall was ready; the one forward was lost | **Acknowledge → Escalate** it again (see *Re-sending* above). |
