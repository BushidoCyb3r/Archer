# Configuring a SIEM receiver (Security Onion)

Archer can forward each escalated finding to an external SIEM as CEF over UDP
syslog. This guide configures **Security Onion** as the receiver. Archer itself
calls this feature generically ("SIEM forwarding") — the CEF / syslog / port
specifics live here.

Archer reuses Security Onion's supported **CEF** Elastic Fleet integration
(the same syslog-ingest pattern SO documents for UniFi:
https://docs.securityonion.net/en/2.4/unifi.html). No Cases API, no custom
Logstash pipeline. Forwarded findings land in Hunt/Dashboards as fully-fielded
ECS records.

## On Security Onion

1. **Enable the CEF integration.** In the SO Console, add/confirm the **CEF**
   Elastic Fleet integration. Set its `Syslog host` to `0.0.0.0` so it listens
   on all interfaces (default CEF port is **UDP 9003**).
2. **Allow Archer through the firewall.**
   - Add a custom **hostgroup** containing Archer's IP.
   - Add a custom **portgroup** for **UDP 9003**.
   - Apply both to the receiving node's INPUT chain.

## In Archer

Settings → **SIEM forwarding** (admin only):

- **Forward escalated findings to a SIEM** — enable.
- **SIEM host (IP)** — the Security Onion node's IP.
- **SIEM port** — `9003`.

No credential is needed: UDP syslog carries none, and the firewall hostgroup is
the trust boundary.

## Verify

Escalate a finding in Archer, then in Security Onion confirm it appears in Hunt
/ Dashboards (search by `source.ip` / `destination.ip`, the CEF `externalId`,
or the `cs*` Archer fields). The `ArcherUrl` field is a deep-link back to the
finding in Archer.

## Field reference

Each forwarded finding is one CEF event: `src`/`dst`/`dpt` (5-tuple),
`app` (Zeek L7 service), `msg` (the finding's detail), `externalId` (Archer
finding id), `rt` (event time), and custom strings `ArcherScore`,
`ArcherSensor`, `ArcherUrl`, `ArcherAnalyst`, `ja3`, `ja4`. Heavier evidence
(intervals, correlations, sub-scores) stays in Archer, one click away via
`ArcherUrl`.
