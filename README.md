<p align="center">
  <img src="docs/archer-logo.png" alt="Archer — Silent Hunter" width="720">
</p>

# Archer — Network Threat Detection & Analyst Workbench

[![CI](https://github.com/BushidoCyb3r/Archer/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/BushidoCyb3r/Archer/actions/workflows/ci.yml)

Pre-1.0 — see [CHANGELOG.md](CHANGELOG.md) for the current release and the [Versioning](#versioning) section below for the stability contract.

Archer is a self-hosted, open-source network threat detection platform that processes Zeek log files to identify adversarial behaviors including C2 beaconing, data exfiltration, lateral movement, DNS tunneling, malicious TLS fingerprints, and more. It provides a browser-based analyst workbench for reviewing, annotating, and escalating findings — including live threat intelligence enrichment via VirusTotal, CrowdSec, AlienVault OTX, AbuseIPDB, GreyNoise, and Censys.

---

## Table of Contents

- [Features](#features)
- [Detection Coverage](#detection-coverage)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installing Prerequisites](#installing-prerequisites)
- [Quick Start](#quick-start)
- [Air-Gapped Installation](#air-gapped-installation)
- [Log File Layout](#log-file-layout)
- [Configuration](#configuration)
- [Threat Intelligence](#threat-intelligence)
- [Quiver Sensors](#quiver-sensors)
- [User Roles](#user-roles)
- [Web Interface](#web-interface)
- [API Reference](#api-reference)
- [Versioning](#versioning)
- [Resetting to Factory State](#resetting-to-factory-state)
- [Running Without Docker](#running-without-docker)
- [License](#license)

---

## Features

- **Multi-log analysis** — ingests conn, DNS, HTTP, SSL, X.509, files, weird, and notice logs in TSV or JSON/NDJSON format, including gzip-compressed files
- **Bounded memory detection** — beacon analyzers use streaming aggregates and reservoir sampling so peak memory is a function of unique pair count, not total record count; Docker entrypoint auto-derives `GOMEMLIMIT` from the container's cgroup so the Go runtime applies back-pressure before OOM
- **Persistent findings** — findings survive restarts, rebuilds, and re-analyses; analyst annotations (status, notes, assignee) are carried over by fingerprint match; findings are preserved even when the logs that produced them are later archived, and are only removed when an admin explicitly prunes them
- **Delta detection** — new findings are flagged so analysts can focus on what changed since the last run
- **Raw-log pivot** — clicking a finding opens a Source Records dialog that scans the original Zeek logs (plus the archive) for matching records and renders the full standard schema with resizable, horizontally-scrollable columns; one-click **Export CSV** flattens every loaded record (with a leading `_log_type` column) for offline analysis
- **In-app campaign graph** — right-click any campaign and pick **View campaign in Graph** to render a force-directed network graph of the involved hosts and destination, severity-coloured and sized by finding volume; clicking a node jumps the findings table to that IP
- **Advanced filtering** — in addition to search/severity/type/min-score, filters include Src IP/CIDR, Dst IP/CIDR, sensor, and a time range; all filters are server-side
- **Virtualized findings table** — the table renders only what's on screen, so result sets of any size stay smooth without truncation
- **Per-tab exports** — every tab has its own CSV and JSON export. Findings/Acknowledged/Escalated/IOC Hits export only the visible subset (server-side, honoring all active filters). Campaigns and Hosts export their aggregations directly. A separate "All" export grabs every finding in the database. Right-click any single campaign row to export just that one campaign — useful for loading into a graphical viewer for stakeholder presentations.
- **Log archive & retention** — admin-configurable: files older than N days automatically move from `/logs` to `/data/archive` after each watch analysis; findings are preserved by default (or optionally pruned past the same cutoff)
- **Dataset fingerprint skip** — watch-mode re-analyses short-circuit when the set of files + their sizes + mtimes is unchanged from the last successful run; recurring runs over a static dataset return in milliseconds (matters more once you tighten the cadence dropdown to hourly)
- **Preflight memory warning** — before each run Archer compares the total log size against `GOMEMLIMIT` and surfaces a status-bar warning when the run is projected to approach or exceed the budget
- **Live threat intelligence** — manual escalation queries VirusTotal, CrowdSec CTI, AlienVault OTX, AbuseIPDB, GreyNoise (Community API works without a key), and Censys; results are consolidated into a single TI Enrichment note per escalation (per-IP grouping with hit/clean indicators), with live SSE toasts as each lookup completes
- **Archive IOC scan** — admin-triggered retroactive scan over `/data/archive` against the current IOC list and TI feeds (Feodo / URLhaus / Suspicious URL); skips the heavy beacon/exfil/lateral phases so a 100+ GB archive scans in minutes. New IOC matches surface as findings exactly like a regular run; existing analyst state is preserved by fingerprint merge.
- **Cell-aware right-click menu** — click-anchor arrow at one of the menu's four corners (↖↗↙↘) points back at the click point regardless of which way the menu had to flip to fit the viewport; column-aware items (Pivot / Lookup / Add to Allowlist / Add to IOC) adapt to whichever IP cell was clicked so there's no Src-vs-Dst picker; state-aware disabling (Acknowledge greys for already-acked findings, "Add to IOC" greys when the IP's already on the list); tab-aware (Acknowledge / Escalate / Suppress hidden on Campaigns and Hosts tabs since those operate on synthesised aggregate rows, not findings); role-gated (write actions hidden for viewers); 8 external-lookup destinations (VT, AbuseIPDB, Shodan, CrowdSec, Censys, GreyNoise, URLscan.io, OTX)
- **Notes export** — Export TXT button on every finding bundles the finding's metadata header plus the full notes thread (including consolidated TI Enrichment notes) into a single self-contained `.txt` file
- **Automatic free TI feeds** — Feodo Tracker C2 IPs and URLhaus malware hosts are fetched and cross-referenced during every analysis run without requiring API keys
- **Role-based access control** — admin, analyst, and viewer roles with per-endpoint enforcement
- **Analyst workbench** — acknowledge, escalate, suppress, add notes, and copy tcpdump/Suricata filter strings directly from the UI
- **Watch mode** — admin-configurable scheduled analysis. Cadence dropdown (Daily / Every 12h / Every 6h / Every 4h / Hourly) lets you tighten the loop to match Quiver's hourly shipping rather than waiting for a once-a-day window. Anchor time + IANA timezone persist independently of the enable/disable toggle. **Two-tier execution:** the first watch tick of each UTC day runs the full analysis pipeline (statistical detectors need the long temporal window for beaconing, HTTP analysis, etc.); subsequent same-day ticks run an incremental TI/IOC pass over only the log files modified since the last run — typically seconds instead of the full-window minutes-to-hours.
- **Disk-usage telemetry** — `/api/disk-usage` walks `/logs` per-sensor, totals `/data/archive`, and reports free space on each volume (5-minute server-side cache). Surfaces in Settings → Log Archive (full per-sensor breakdown) and the Sensors modal (Size column). Low-disk banner appears at the top of the page when any tracked volume drops below 10% free.
- **Quiver sensors** — optional companion agent that ships Zeek logs from any Linux sensor host into Archer over rsync-on-ssh. Enrollment is one curl one-liner per sensor (TLS-pinned), pubkey-pinned per-sensor authorized_keys, hourly randomized push window, live Sensors modal showing health/missed-slot status, single-step disenroll + log-tree purge. Auto-installs prerequisites on Debian/Ubuntu/RHEL/Oracle/Rocky/Alma/SLES/Alpine. See [docs/QUIVER.md](docs/QUIVER.md) for the full operator guide.
- **Campaign & host views** — see which destinations are contacted by multiple internal hosts and view per-host composite risk scores
- **Resource-aware deployment** — `start.sh` automatically allocates 80% of host CPU and 70% of host RAM to the container; RAM is held to a tighter cap so burst spikes have absorption headroom before they could OOM-kill the container. The entrypoint then wires the Go runtime memory limit to 90% of whatever budget it gets

---

## Detection Coverage

Archer runs five parallel analysis phases across all supported log types.

### Network Connections (`conn.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **Beaconing** | Statistically regular connections to an external host — multi-dimensional scoring using inter-arrival time regularity (Bowley skewness + MAD), data size consistency, 24-hour histogram analysis, and temporal persistence | CRITICAL / HIGH |
| **Strobe** | Unusually high connection count to a single destination (default: ≥ 1000) — indicative of port scanning or automated tooling | HIGH |
| **Data Exfiltration** | Large outbound transfer (default: ≥ 5 MB) with a high outbound/inbound ratio (default: ≥ 10:1) | HIGH |
| **Lateral Movement** | Internal-to-internal traffic on administrative ports: SMB (445), RDP (3389), WMI (135), WinRM (5985/5986), SSH (22) | HIGH |
| **Off-Hours Transfer** | External data transfer outside configured business hours (default: 22:00–06:00 UTC) exceeding the configured threshold | MEDIUM |
| **Long Connection** | TCP/UDP session duration exceeding the configured minimum (default: 1 hour) — indicative of reverse shells and VPN tunnels | MEDIUM / HIGH / CRITICAL |

### DNS (`dns.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **DNS Tunneling** | High-entropy, long DNS labels (default: > 40 chars, entropy > 3.5) with deep nesting (default: > 5 levels), or a high count of unique subdomains per apex domain — detects iodine, DNScat2, dns2tcp | HIGH |
| **DNS NXDOMAIN Flood** | High rate of non-existent domain responses (default: ≥ 200) — indicative of DGA-based malware | HIGH |
| **Suspicious TLD** | Queries to free or commonly abused TLDs: `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.top`, `.xyz`, `.pw`, `.cc`, `.to`, and others | MEDIUM |
| **DoH Bypass** | DNS-over-HTTPS queries to known public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9, etc.) on port 443 — malware evading DNS logging and response policy zones | MEDIUM |

### HTTP (`http.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **HTTP Beaconing** | Same multi-dimensional beacon scoring applied to HTTP request patterns per (source, host, URI) triple — catches C2 over CDN infrastructure where multiple IPs share one domain | CRITICAL / HIGH |
| **Cobalt Strike URI** | Checksum8 algorithm match: URI byte sum modulo 256 equals 92 (x86 stager) or 93 (x64 stager) | CRITICAL |
| **C2 URI Pattern** | Regex match against default framework URI patterns: Cobalt Strike (`/submit.php`, `/ca`, `/dpixel`, `/pixel.gif`, `/ptj`, `/j.ad`, `/updates.rss`), Empire (`/news.php`, `/admin/get.php`, `/login/process.php`), Metasploit (8-character alphanumeric stager paths) | CRITICAL |
| **Domain Fronting** | SSL SNI does not match HTTP Host header — CDN abuse used to hide C2 destination | CRITICAL |
| **Suspicious User Agent** | Scripting and automation user agents: python-requests, curl, wget, go-http-client, PowerShell, libwww-perl | LOW |
| **Suspicious File Download** | Executable MIME types (`application/x-dosexec`, `application/x-elf`, etc.) or executable extensions (`.exe`, `.dll`, `.ps1`, `.vbs`, `.bat`, `.hta`, `.scr`, `.sh`, `.elf`, `.msi`) | HIGH |

### TLS / SSL (`ssl.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **Malicious JA3** | TLS ClientHello fingerprint matches known C2 frameworks: Cobalt Strike beacon, Cobalt Strike SMB, Metasploit/Meterpreter, Sliver, Brute Ratel, and others | CRITICAL |
| **SSL No-SNI on C2 Port** | Established TLS connection with no SNI on known C2 ports (4444, 4899, 6666–6669, 8008, 8888, 9001, 9030, 31337) | HIGH |
| **Weak TLS** | Deprecated protocol versions: SSLv2, SSLv3, TLSv1.0, TLSv1.1 | MEDIUM |
| **SSL No-SNI** | Established TLS connection with no SNI on standard ports — supporting indicator | LOW |

### X.509 Certificates (`x509.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **Suspicious Certificate** | Self-signed certificates (subject equals issuer), generic or default subject strings, or anomalous validity windows (< 48 hours or > 10 years) | MEDIUM |

### Protocol Anomalies (`weird.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **Protocol Anomaly** | Zeek-flagged protocol violations: `bad_HTTP_request`, `malformed_ssh`, `RST_with_data`, `DNS_label_too_long`, and others | MEDIUM / LOW |

### Zeek Notices (`notice.log`)

| Detection Type | Description | Severity |
|---|---|---|
| **Zeek Notice** | Detections from Zeek policy scripts: `Sensitive_Signature`, `Scan`, `Attack`, `Brute_Force` | CRITICAL / HIGH |

### Threat Intelligence

| Detection Type | Description | Severity |
|---|---|---|
| **TI Hit (IP)** | Source or destination IP matched against Feodo Tracker C2 IPs, URLhaus malware-distribution IPs, OTX / AbuseIPDB lookups, or any configured MISP/OpenCTI feed's IP/CIDR indicators during analysis; or confirmed malicious by a TI service during analyst escalation | CRITICAL (built-in feeds) / HIGH (MISP/OpenCTI feeds) |
| **TI Hit (Domain)** | DNS query name or HTTP host matched against URLhaus malware-distribution domains or any configured MISP/OpenCTI feed's domain indicators | CRITICAL (URLhaus) / HIGH (MISP/OpenCTI feeds) |
| **TI Hit (Hash)** | `files.log` md5 / sha1 / sha256 matched against any configured MISP/OpenCTI feed's hash indicators. Only fires when Zeek's hashing analyzers are loaded *and* the file traverses an unencrypted protocol Zeek can reassemble (HTTP, SMB, FTP, SMTP, IRC) — see [docs/FEEDS.md](docs/FEEDS.md) for the full coverage map | HIGH |
| **Suspicious URL** | HTTP destination host matched against URLhaus malware distribution hosts or any configured MISP/OpenCTI feed's domain indicators | CRITICAL (URLhaus) / HIGH (MISP/OpenCTI feeds) |

For MISP/OpenCTI integration — adding a feed, configuration options, the per-feed TLS-verify bypass, indicator types that match (and ones that don't), aging behavior, and troubleshooting — see **[docs/FEEDS.md](docs/FEEDS.md)**. Feeds are admin-curated through the Feeds topbar dialog; findings carry per-feed provenance via the `SourceFile: feed:<name>` field.

### Composite Scoring

| Detection Type | Description | Severity |
|---|---|---|
| **Host Risk Score** | Weighted composite score (0–100) aggregated across all findings for a given source IP. Weights: Cobalt Strike URI +40, Malicious JA3 +40, Domain Fronting +32, TI Hit (IP/Domain/Hash) +35 each, HTTP Beaconing +28, Beaconing +30, Data Exfiltration +25, Lateral Movement +20, Strobe +15, Long Connection +10. Surfaced in the **Hosts** tab (not the Findings tab — that tab is reserved for discrete network events). Click any host row to open the underlying score breakdown. | CRITICAL / HIGH / MEDIUM / LOW |

---

## Architecture

```
archer/
├── entrypoint.sh               # Derives GOMEMLIMIT from cgroup before exec
├── cmd/archer/main.go          # Entry point — flags, wiring, HTTP server, signal handler
├── internal/
│   ├── analysis/               # Detection engines (one file per log type)
│   │   ├── conn.go             # Beaconing, strobe, exfil, lateral, long-conn, C2 port (streaming + reservoir)
│   │   ├── dns.go              # Tunneling, DGA, suspicious TLDs, DoH bypass
│   │   ├── http_analysis.go    # HTTP beaconing (reservoir-sampled), Cobalt Strike, domain fronting
│   │   ├── ssl.go              # JA3, no-SNI, weak TLS
│   │   ├── x509.go             # Certificate anomalies
│   │   ├── files.go            # Suspicious file downloads
│   │   ├── weird.go            # Protocol anomalies
│   │   ├── notice.go           # Zeek notice alerts
│   │   ├── ti.go               # Threat intelligence feed lookups
│   │   ├── risk.go             # Host risk composite scoring
│   │   └── analyzer.go         # Pipeline orchestration (pause/cancel/progress, memory-bounded worker pool)
│   ├── config/config.go        # Tunable thresholds + watch + archive settings with defaults
│   ├── model/                  # Finding, Severity, Status, User, Note types
│   ├── server/
│   │   ├── server.go           # Route registration
│   │   ├── handlers_api.go     # All REST API handlers
│   │   ├── handlers_ui.go      # Index template renderer (no-store)
│   │   ├── handlers_quiver.go  # Sensor-facing endpoints: install.sh, enroll, checkin
│   │   ├── handlers_sensors.go # Admin Sensors modal endpoints (list, tokens, disenroll, purge, schedule)
│   │   ├── authorized_keys.go  # Per-sensor authorized_keys management with parent-owner chown
│   │   ├── tls.go              # Self-signed ed25519 cert bootstrap + pinned-pubkey fingerprint
│   │   ├── findings_filter.go  # Shared query-param filter used by list + exports
│   │   ├── findings_raw.go     # Raw-log pivot: finds source records for a finding
│   │   ├── archive.go          # Aged-log archive worker + finding prune
│   │   ├── watch.go            # Watch mode scheduler, dataset fingerprint skip, preflight check, launchAnalysis
│   │   ├── auth.go             # Session management, role middleware
│   │   ├── upload.go           # Log file ingestion
│   │   ├── sse_broker.go       # Server-Sent Events fan-out
│   │   └── quiver_assets/      # Embedded sensor scripts (install.sh, quiver.sh, quiver-uninstall.sh)
│   └── store/
│       ├── store.go            # Findings, allowlist, IOC list, suppressions, config — SQLite persistence
│       ├── sensors.go          # Sensors, enrollment_tokens, unauthorized_attempts — SQLite persistence
│       └── userstore.go        # User accounts, sessions — SQLite persistence
├── entrypoint.sh               # sshd host-key bootstrap, /home/quiver/.ssh perms, GOMEMLIMIT, exec archer
├── sshd_config                 # Sensor-facing sshd config — pubkey-only, AllowUsers quiver
└── web/
    ├── templates/index.html    # Single-page application shell
    └── static/
        ├── css/archer.css
        └── js/
            ├── app.js          # Main application state machine
            ├── sse.js          # SSE connection manager with auto-reconnect
            ├── detail.js       # Finding detail pane renderer
            ├── table.js        # Findings table — virtual scrolling, sort
            ├── chart.js        # Beacon inter-arrival time chart
            ├── campaigns.js    # Campaign aggregation view
            ├── sensors.js      # Sensors modal — enrolled, tokens, unauthorized, health
            ├── graph.js        # In-app campaign graph (Cytoscape wrapper)
            ├── cytoscape.min.js # Vendored Cytoscape.js (MIT, lazy-loaded)
            ├── notifications.js
            ├── dialog.js       # Modal dialog helpers
            └── resize.js       # Pane resize drag handle
```

All state is persisted in a single SQLite database at `/data/archer.db`. There are no external service dependencies at runtime beyond optional TI API keys.

---

## Requirements

- **Docker** and **Docker Compose** (recommended deployment method)
- OR **Go 1.21+** for building and running from source without Docker

---

## Installing Prerequisites

### Docker and Docker Compose

Docker is required for the recommended deployment path. Docker Compose is included with Docker Desktop on Mac and Windows, and is installed as a plugin on Linux.

#### Ubuntu / Kali Linux

```bash
# Add Docker's official GPG key
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to apt sources
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update

# Install Docker Engine and Compose plugin
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
sudo systemctl enable --now docker
```

> **Kali Linux note:** Kali is Ubuntu/Debian-based. If `UBUNTU_CODENAME` is not set in `/etc/os-release`, the sources entry will fall back to `VERSION_CODENAME`. If the repository step fails, replace the `Suites:` value manually with the current Ubuntu LTS codename (e.g. `noble`).

#### Debian

```bash
# Add Docker's official GPG key
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to apt sources
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: $(. /etc/os-release && echo "$VERSION_CODENAME")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update

# Install Docker Engine and Compose plugin
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
sudo systemctl enable --now docker
```

#### Fedora

```bash
# Add the Docker repository
sudo dnf config-manager addrepo --from-repofile https://download.docker.com/linux/fedora/docker-ce.repo

# Install Docker Engine and Compose plugin
sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
sudo systemctl enable --now docker
```

> **Fedora note:** When prompted during installation, verify the GPG key fingerprint matches `060A 61C5 1B55 8A7F 742B 77AA C52F EB6B 621E 9F35` before accepting.

#### RHEL / Rocky Linux

```bash
# Remove any conflicting older packages
sudo dnf remove docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine podman runc

# Install the dnf plugin manager
sudo dnf -y install dnf-plugins-core

# Add the Docker repository
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo

# Install Docker Engine and Compose plugin
sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
sudo systemctl enable --now docker

# Verify
sudo docker run hello-world
```

> **Rocky Linux / AlmaLinux note:** These are RHEL-compatible rebuilds, so the RHEL repository above is the correct one to use. If `dnf config-manager` is not found, install it with `sudo dnf -y install dnf-plugins-core` first. When prompted during installation, accept the Docker GPG key only after verifying the fingerprint matches `060A 61C5 1B55 8A7F 742B 77AA C52F EB6B 621E 9F35`.

#### macOS

Docker Desktop for Mac includes Docker Engine, Docker Compose, and a GUI dashboard.

1. Download Docker Desktop from the official Docker website: `https://www.docker.com/products/docker-desktop/`
   - Choose **Mac with Apple Silicon** (M1/M2/M3/M4) or **Mac with Intel Chip** depending on your hardware
2. Open the downloaded `.dmg` file and drag **Docker** to your Applications folder
3. Launch **Docker** from Applications
4. Accept the terms of service and wait for Docker to finish starting — the whale icon in the menu bar will stop animating when ready

Verify from a terminal:

```bash
docker --version
docker compose version
```

> **Note:** On macOS, `start.sh` calls `sudo docker compose`. Docker Desktop on Mac does not require `sudo` for most operations, but the script will still work — macOS will simply ask for your password if needed.

#### Windows

Docker Desktop for Windows includes Docker Engine and Docker Compose.

**System requirements:**
- Windows 10 64-bit (version 22H2 or later) or Windows 11
- WSL 2 (Windows Subsystem for Linux 2) — required and installed automatically by Docker Desktop

**Installation steps:**

1. Download Docker Desktop from the official Docker website: `https://www.docker.com/products/docker-desktop/`
   - Choose **Docker Desktop for Windows**
2. Run the installer (`Docker Desktop Installer.exe`)
3. When prompted, ensure **Use WSL 2 instead of Hyper-V** is checked (recommended)
4. Follow the installer prompts and restart your computer when asked
5. After restart, launch **Docker Desktop** from the Start menu and wait for it to finish initializing

**Enable WSL 2 (if not already enabled):**

Open PowerShell as Administrator and run:

```powershell
wsl --install
wsl --set-default-version 2
```

Restart your computer after this step.

**Running Archer on Windows:**

Archer's shell scripts (`start.sh`, `reset.sh`) are written for Bash. On Windows, run them from inside a **WSL 2 terminal** (Ubuntu or Debian recommended):

```bash
# Inside a WSL 2 terminal
cd /mnt/c/path/to/Archer
sudo ./start.sh
```

Alternatively, run Docker Compose commands directly from PowerShell or Command Prompt:

```powershell
docker compose up -d --build
```

Verify from PowerShell or Command Prompt:

```powershell
docker --version
docker compose version
```

---

#### Verify Docker on Linux

```bash
docker --version
docker compose version
```

You should see output similar to:

```
Docker version 26.1.0, build 6e0c0c5
Docker Compose version v2.27.0
```

#### Optional: run Docker without sudo (Linux only)

By default, Docker on Linux requires `sudo`. To allow your user to run Docker commands without it:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

Log out and back in for the group change to take full effect. Note that `start.sh` still uses `sudo docker compose` explicitly for compatibility — this step is optional.

---

### Go (only needed if running without Docker)

Go is only required if you want to build and run Archer directly on the host without Docker.

#### Linux (all distributions)

```bash
# Download the latest Go release (check https://go.dev/dl/ for the current version)
curl -LO https://go.dev/dl/go1.23.0.linux-amd64.tar.gz

# Remove any previous Go installation and extract the new one
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz

# Add Go to your PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile
```

For ARM64 systems (e.g. Raspberry Pi, Apple Silicon in a Linux VM), replace `amd64` with `arm64` in the download URL.

#### macOS

The easiest method on macOS is Homebrew:

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Go
brew install go
```

Alternatively, download the `.pkg` installer directly from `https://go.dev/dl/` and run it — Go will be installed to `/usr/local/go` and added to your PATH automatically.

#### Windows

1. Download the Windows installer (`.msi`) from `https://go.dev/dl/`
   - Choose the `windows-amd64` package
2. Run the installer and follow the prompts — Go is installed to `C:\Program Files\Go` and added to your PATH automatically
3. Open a new Command Prompt or PowerShell window for the PATH change to take effect

To build Archer on Windows, use the **Developer PowerShell** or a WSL 2 terminal:

```powershell
go build -o archer.exe ./cmd/archer
```

#### Verify the installation

```bash
go version
```

Expected output:

```
go version go1.23.0 linux/amd64
```

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/BushidoCyb3r/Archer.git
cd Archer
```

### 2. Place your Zeek logs

Archer expects logs in the `logs/` directory **inside the cloned repository folder on the host machine**. Docker bind-mounts this directory into the container at `/logs` — any files you place there are immediately visible to Archer without a rebuild or restart.

```
/home/user/Archer/          ← cloned repo on the host
└── logs/                   ← place your Zeek logs here
    ├── campaign-apt29/
    │   ├── conn.log
    │   ├── dns.log
    │   ├── http.log
    │   └── ssl.log
    └── campaign-lateral-2026/
        ├── conn.log.gz
        └── dns.log.gz
```

Each subdirectory under `logs/` is treated as a distinct **sensor** (or, for hand-imported datasets, the directory name is the sensor label) and is shown as such throughout the UI. Files can be uncompressed (`.log`) or gzip-compressed (`.log.gz`, `.gz`). Quiver-enrolled sensors automatically populate `logs/<sensor-name>/YYYY-MM-DD/...` via rsync — see [Quiver Sensors](#quiver-sensors).

### 3. Start Archer

One command. No configuration required.

```bash
sudo ./start.sh up
```

`start.sh` measures the host (and the Docker daemon's view, in case it's smaller), allocates 80% of available CPU and 70% of available RAM to the container, builds the image, and starts Archer. Drop the tool on a 16 GB laptop and it scales down; drop it on a 256 GB analysis box and it scales up. No env vars to set, no memory values to guess. The summary at the end prints the host's actual reachable IP (from the default-route source address) so the URL is paste-ready for analysts on the same LAN.

```
Host resources:   16 CPUs  |  32768 MB RAM
Archer limits:    12.8 CPUs  |  22937m RAM  (CPU 80% / RAM 70%)

Archer is running at http://192.0.2.10:8080
```

Three ports are exposed:

| Host port | Container port | Purpose |
|---|---|---|
| 8080 | 8080 | Analyst UI (HTTP, LAN-side) |
| 8443 | 8443 | Quiver sensor checkin + install.sh (HTTPS, pinned-pubkey at enrollment) |
| 2222 | 22 | Quiver sensor rsync-over-ssh (mapped off port 22 so a host-side sshd isn't disturbed) |

Ports 8443 and 2222 only matter if you're using Quiver to ship logs from sensors. If you're hand-importing logs into `./logs`, ignore them.

**Everyday operations** — same script:

```bash
sudo ./start.sh up        # build + start (or rebuild after code changes)
sudo ./start.sh down      # stop
sudo ./start.sh restart   # restart without rebuild
sudo ./start.sh logs      # tail container logs
sudo ./start.sh status    # show running state + live memory/CPU usage
```

<details>
<summary>Advanced: running without start.sh</summary>

If you're managing your own Docker environment (CI, orchestrated hosts, existing `.env` workflow), you can bypass `start.sh` and run compose directly. The container sizes itself based on whatever `ARCHER_MEMORY` / `ARCHER_CPUS` you supply; Archer's entrypoint always derives `GOMEMLIMIT` from the cgroup memory cap at runtime, so the Go runtime is correctly budgeted regardless of how you start it.

```bash
# Accept the conservative 4 GB default (fine for demo datasets, too small for large deployments):
sudo docker compose up -d

# Or set your own limits:
ARCHER_MEMORY=32g ARCHER_CPUS=8 sudo docker compose up -d
```

Note: bare `docker compose up -d` gives the container only 4 GB of RAM regardless of host size — the default in `docker-compose.yml` is a safety floor, not a host-aware size. On a big VM, either use `./start.sh up` or set `ARCHER_MEMORY` explicitly.

</details>

### 4. Register your admin account

Navigate to `http://localhost:8080`. The first user to register automatically receives the **admin** role.

### 5. Analyze

1. Drop Zeek logs into `logs/<name>/<date>/` on the host (or let
   Quiver sensors rsync them in automatically). The sidebar **Logs**
   tree shows what's been picked up.
2. Click **Analyze logs** to run the full detection pipeline.
3. Findings appear in real time as the pipeline progresses.

For analyst-laptop bundles or third-party hand-offs without a live
sensor: drop the bundle into `logs/<handoff-name>/<date>/` on the
host (mount, `docker cp`, or SCP via the Quiver SSH dropbox at
port 2222). Same `Analyze logs` button picks them up.

---

## Air-Gapped Installation

Archer's runtime has no hard internet dependencies — once installed, the analyzer reads logs from disk, the analyst UI is local, sensors push over LAN, and findings are stored in SQLite on the host. The only outbound traffic at runtime is **threat-intel feed prefetching** (FeodoTracker, URLhaus) and **manual escalation lookups** (OTX / AbuseIPDB / VirusTotal / CrowdSec / GreyNoise / Censys); both fail gracefully when offline, and every other detector — Beaconing, Cobalt Strike URI, JA3, Lateral Movement, Suspicious URL via local IOC list, etc. — works fine without network.

**The catch is the build.** A fresh `git clone` + `docker compose build` reaches out to three places: Docker Hub for the `golang:1.25-alpine` and `alpine:3.20` base images, the Alpine package mirror for `apk add` (rsync, openssh-server, tini, ca-certificates, tzdata, rrsync), and the Go module proxy for ~11 module dependencies in `go.sum`. None of those resolve in an air-gapped environment without preparation.

The cleanest pattern is to **build on a connected box, ship the resulting Docker image as a tarball, load it on the air-gapped target.** The image is the artifact; you stop trying to rebuild on the isolated side.

### Build + ship workflow

On a connected box with Docker installed:

```bash
git clone <archer-repo-url>
cd Archer
docker compose build               # populates archer:latest in local Docker
docker save archer:latest -o archer-image.tar   # ~80 MB
```

Copy `archer-image.tar` plus the `Archer/` source tree (for `docker-compose.yml`, `start.sh`, `reset.sh`, the Quiver scripts, etc.) to the air-gapped host via whatever sneakernet you use — USB, scp from a connected jump host, signed transfer, etc.

On the air-gapped host (Docker installed, no internet):

```bash
docker load -i archer-image.tar    # loads archer:latest from the tarball
cd Archer
./start.sh up                      # uses the loaded image, no build, no pulls
```

`start.sh` handles the resource sizing as described in [Quick Start](#quick-start) and brings up the stack against the loaded image. No outbound HTTP fires. The container starts, sshd binds 2222, the analyst UI binds 8080, and you're operational.

### What still works offline

| Capability | Works air-gapped? | Notes |
|---|---|---|
| Log ingest from `/logs` | ✓ | Sensors push over LAN, or admin drops files manually |
| All statistical detectors (Beaconing, HTTP, DNS, SSL, etc.) | ✓ | Closed-form math, no external calls |
| IOC list matching | ✓ | Admin maintains the list locally via Settings → IOC List |
| Allowlist + suppressions | ✓ | Local |
| Findings, notes, escalations, exports | ✓ | All local SQLite + browser |
| Quiver sensor enrollment | ✓ | TLS handshake is internal LAN traffic, pinned-pubkey |
| Quiver sensor install on RHEL/Debian/etc. | ⚠ | Sensor's `install.sh` uses the local distro package manager (`apt`/`dnf`/etc.) to install rsync/openssh-client/cron — those need to resolve from the sensor's own internal package mirror or be pre-installed |
| FeodoTracker + URLhaus feed prefetch | ✗ | Outbound HTTPS to `feodotracker.abuse.ch` and `urlhaus.abuse.ch`. Fails silently per analysis run; no findings from these feeds. |
| Escalation lookups (OTX/AbuseIPDB/VT/etc.) | ✗ | Outbound HTTPS per service. Manual escalation surfaces "request failed" results in the consolidated TI Enrichment note instead of hits. |

### Bringing TI feeds into an air-gapped install

If you want TI matching to work air-gapped, the practical path is to **mirror the two free feeds locally** (FeodoTracker IP blocklist and URLhaus active-URL CSV are plain text + CSV downloads), serve them from an internal HTTP endpoint, and either patch `internal/analysis/ti.go`'s `fetchFeodo` / `fetchURLhaus` URLs to point at the mirror — OR populate the local IOC list from the same files via a periodic internal job and rely on IOC-list matching (which works air-gapped) as the substitute for live feed lookups.

The escalation services (OTX, AbuseIPDB, VirusTotal, CrowdSec, GreyNoise, Censys) all require their own API endpoints; there's no "mirror" pattern for these short of running an internal API gateway with cached responses. For most air-gapped deployments these stay disabled.

### When you actually need to rebuild on the air-gapped side

If your operational model requires building from source on the isolated host (e.g. you're patching analyzer code in the field), the path is heavier:

1. Pre-pull both base images on a connected box, save as tarballs, sneakernet over: `docker pull golang:1.25-alpine && docker pull alpine:3.20 && docker save golang:1.25-alpine alpine:3.20 -o base-images.tar`
2. Vendor Go modules into the repo before transit: `cd Archer && go mod vendor` — this drops all module sources into `./vendor/` so the build doesn't need the Go module proxy. You'll also need to add `-mod=vendor` to the `go build` line in the Dockerfile.
3. Solve the `apk add` problem — Alpine doesn't ship a self-contained "all-packages" snapshot. The realistic options are: (a) host an internal Alpine package mirror, (b) bake the needed packages into a custom base image built on the connected side and shipped as a tarball alongside the source, or (c) skip the Alpine package step and embed the binaries directly into a `FROM scratch` image.

Most teams find option 1 (build connected, ship the tarball) is dramatically less work than option 2-3 (rebuild on the air-gapped side). Use the rebuild path only when you have a specific reason to need source-on-target.

---

## Log File Layout

Archer reads Zeek-format logs. Files may be uncompressed (`.log`) or gzip-compressed (`.log.gz`, `.gz`). Both TSV (tab-separated with `#fields` header) and JSON/NDJSON formats are supported.

The directory immediately under the configured logs root is used as the **sensor name** displayed throughout the UI. Deeper nesting is allowed but only the first level is used as the label:

```
/logs/<sensor-name>/[subdirs/]<file>.log
```

Supported log filenames: `conn`, `dns`, `http`, `ssl`, `x509`, `files`, `weird`, `notice` (with or without `.log` suffix, with or without `.gz`).

---

## Configuration

All thresholds are configurable at runtime through the **Settings** dialog (admin only). Changes are persisted in SQLite and survive restarts.

### Analysis Thresholds

| Parameter | Default | Description |
|---|---|---|
| `beacon_min_connections` | `10` | Minimum connection count before beacon scoring is applied |
| `http_beacon_min_requests` | `8` | Minimum HTTP request count before HTTP beacon scoring is applied |
| `long_conn_min_hours` | `1.0` | Minimum session duration (hours) for a long connection alert |
| `strobe_min_connections` | `1000` | Minimum connections to a single destination to trigger a strobe alert |
| `exfil_min_bytes_mb` | `5.0` | Minimum outbound transfer (MB) required for an exfiltration alert |
| `exfil_ratio_threshold` | `10.0` | Minimum outbound/inbound byte ratio for an exfiltration alert |
| `off_hours_start` | `22` | Start of off-business hours (24-hour UTC) |
| `off_hours_end` | `6` | End of off-business hours (24-hour UTC) |
| `off_hours_min_mb` | `1.0` | Minimum transfer (MB) outside business hours to trigger an alert |
| `dns_tunnel_label_len` | `40` | DNS label character length threshold for tunneling detection |
| `dns_tunnel_entropy` | `3.5` | Shannon entropy threshold for DNS label content |
| `dns_tunnel_min_depth` | `5` | Minimum subdomain nesting depth for tunneling detection |
| `dns_nxdomain_threshold` | `200` | NXDOMAIN response count threshold for DGA detection |
| `dns_unique_subdomain_min` | `50` | Unique subdomain count threshold per apex domain |

### Deployment

**`start.sh` commands:**

```bash
sudo ./start.sh           # Build and start (default)
sudo ./start.sh up        # Build and start
sudo ./start.sh down      # Stop and remove containers
sudo ./start.sh restart   # Restart without rebuilding
sudo ./start.sh logs      # Tail container logs
sudo ./start.sh status    # Show container status and live resource usage
```

**Docker environment variables:**

| Variable | Default | Description |
|---|---|---|
| `TZ` | `UTC` | Container timezone |
| `GOMAXPROCS` | `0` | CPU cores available to the Go runtime (`0` = all) |
| `ARCHER_CPUS` | `9999` (none) or `start.sh` output | CPU limit enforced by Docker |
| `ARCHER_MEMORY` | `4g` or `start.sh` output | Memory limit enforced by Docker (cgroup cap) |
| `GOMEMLIMIT` | auto | Go soft memory budget — set by `entrypoint.sh` at startup to 90% of the cgroup memory cap. Passing an explicit value overrides the auto-derivation. |

---

## Threat Intelligence

### Free Feeds (No API Key Required)

These feeds are fetched automatically at the start of every analysis run:

| Feed | Coverage |
|---|---|
| **Feodo Tracker** | Active C2 server IPs for Emotet, TrickBot, QakBot, Dridex, and other banking malware |
| **URLhaus** | Active malware distribution URLs and hosting domains |

### Escalation Lookup Services

Configure credentials in the **Settings** dialog. **GreyNoise** is the only service that runs without any configuration — its Community API works unauthenticated (rate-limited to ~50 requests/hour). Adding a free GreyNoise key raises the limit. Every other service in this table is gated on a configured key.

| Service | Auth | Lookup Type | What is Checked |
|---|---|---|---|
| **VirusTotal** | API key | IP addresses and domains | Malicious engine detection count from `last_analysis_stats` |
| **CrowdSec CTI** | API key | IP addresses only | Overall reputation score from the smoke feed |
| **AlienVault OTX** | API key | IP addresses and domains | Threat pulse count and reputation score |
| **AbuseIPDB** | API key | IP addresses only | Abuse confidence score (0–100%) and total report count (last 90 days) |
| **GreyNoise** | optional Community key | IP addresses only | Classification (benign/malicious/unknown), `noise:true` (background internet scanner — likely not targeted), `riot:true` (known benign service like Google/AWS) |
| **Censys** | API ID + API Secret (Basic auth) | IP addresses only | Number of services + sample ports (HTTPS, SSH, …), country, last-observed timestamp. Informational only — Censys doesn't return a malicious verdict. |

The Settings UI presents Censys as a single combined `id:secret` field — the ID half is plaintext (it's an identifier, not a credential by itself), the secret half is masked.

### Escalation Workflow

When an analyst escalates a finding, Archer opens a dialog to:

1. Select which artifact to look up — **Dst IP**, **Src IP**, or both
2. Select which TI services to query (only services with configured credentials are shown; GreyNoise is always shown because it works unauthenticated)

Lookups run in the background. For each service queried:
- A real-time **toast notification** is pushed to the browser as each lookup completes
- A final summary toast indicates total hit count when all lookups complete
- Once every lookup has settled, a **single consolidated TI Enrichment note** is written to the finding — grouped per IP, with each result prefixed `⚠` (hit) or `✓` (clean):

  ```
  TI Enrichment Results — 2 IP(s), 1 hit(s)

  [1.2.3.4]
    ⚠ [VirusTotal] 5 engines flagged 1.2.3.4 as malicious
    ✓ [GreyNoise] 1.2.3.4 background internet scanner (Censys Scanner) — likely not targeted
    ✓ [CrowdSec] 1.2.3.4 - no threats found
    ✓ [Censys] 1.2.3.4 - 4 services [443/HTTPS, 22/SSH, 80/HTTP] (location: US, last seen 2026-05-01)

  [5.6.7.8]
    ✓ [VirusTotal] 5.6.7.8 - no malicious detections
  ```

Results are classified as `[HIT]` (threat confirmed) or `[CLEAN]` (no threats found) and stored permanently regardless of outcome. The full thread can be exported as a self-contained `.txt` file via **Export TXT** at the top of the Notes section — useful for incident reports and stakeholder handoffs.

**Cross-annotation onto sibling findings.** When a TI lookup returns substantive information about an IP — a hit (Feodo / URLhaus / OTX / VirusTotal / AbuseIPDB / CrowdSec / GreyNoise classification) or a substantive non-hit (GreyNoise labelling the IP as `riot:true` Google/AWS/CiscoOpenDNS infrastructure, Censys returning a service list) — Archer also appends a per-IP `TI Enrichment` note to every other finding that mentions that IP. An analyst opening a beacon finding will see "GreyNoise: known benign service Google DNS" inline instead of having to notice a separate `TI Hit (IP)` row. "No record found", "lookup failed", and "request failed" lines are kept on the originating finding only — they have no signal worth surfacing on related findings. The same applies to automatic TI hits emitted during the analyzer's TI phase: every newly-detected `TI Hit (IP)` / `TI Hit (Domain)` / `TI Hit (Hash)` cross-notes the IP across all other findings that mention it, gated on `IsNew` so re-runs don't duplicate notes. (`Suspicious URL` is excluded from cross-annotation — the matching `TI Hit (Domain)` for the same host already carries the enrichment.)

### Archive IOC Scan

Admins can retroactively re-scan archived logs against the current IOC list and TI feeds. Settings → Log Archive → **Scan Archive for IOCs**. The scan walks `/data/archive`, runs only the IOC + Feodo + URLhaus + Suspicious-URL phases (skipping beacon/exfil/lateral/etc.), and produces standard findings via the same fingerprint-merge that regular runs use. Useful when a freshly added threat-intel feed should be checked against historical data that's already aged out of `/logs/`.

---

## Quiver Sensors

Quiver is the optional sensor-side companion that ships Zeek logs from any Linux host into Archer. Each enrolled sensor pushes hourly via rsync-on-ssh; Archer treats every sensor as its own per-sensor log tree at `/logs/<sensor-name>/`, so analyzers, campaigns, and the host risk model keep per-sensor scope automatically.

**Quick enrollment.** As an Archer admin, open the **Sensors** modal in the header → **+ Enroll new sensor** → **Generate token**. Copy the curl one-liner; on the sensor (as root):

```sh
sudo curl -fsSL -k --pinnedpubkey "sha256//<fingerprint>" \
    https://<archer-host>:8443/quiver/install.sh | sudo bash -s -- <TOKEN>
```

The script auto-installs missing dependencies (rsync, openssh-client, cronie/cron, sudo, util-linux), creates a `quiver` system user, generates an ed25519 keypair, registers with Archer, drops `/etc/cron.d/quiver`, and runs a full first-sync. The Archer dialog flips from "Waiting…" to "✓ Enrolled as `<name>`" the moment the server records the enrollment.

**Supported distros.** Debian, Ubuntu, Kali, RHEL/Oracle/Rocky/Alma 7+, Fedora, openSUSE/SLES, and Alpine. SELinux contexts are restored on RHEL-family hosts so cron can exec the daily script under enforcing mode.

**Cadence.** Sensors push every hour at a server-assigned random minute-of-hour. Each push ships only the last 24 hours of completed `.gz` files (rsync mtime-skips already-shipped files).

**Initial backfill window.** During `install.sh`, the operator is prompted for how many days of historical Zeek logs the sensor should ship on its first push — Enter for all available history (legacy default), or a positive integer N to ship only the last N days. The choice is persisted to `/etc/quiver/config` as `INITIAL_BACKFILL_DAYS=` and is honored only by the FIRST_SYNC=1 invocation; recurring cron pushes always use the 24h window. For non-interactive deployments, set `INITIAL_BACKFILL_DAYS=N` in the environment before piping the install script and the prompt is skipped. Useful when a sensor has months of local Zeek history but the operator only wants the recent slice ingested into Archer.

**Sensors modal.** Three tables visible to all authenticated users; admin-only writes:

- **Enrolled Sensors** — name, host, status, slot, last seen (in your watch-mode timezone), Health (`✓ on time` / `pending` / `⚠ missed` / `never`), and admin actions (Slot reassign, Disenroll, Purge after disenroll).
- **Pending Tokens** — outstanding tokens awaiting use or revocation. Used tokens are filtered out automatically (they show up as Enrolled Sensors). Admin can Revoke before use.
- **Unauthorized Attempts** — checkins from sensor names Archer doesn't recognize, with source IP, attempt count, and first/last-seen timestamps. Auto-prunes after 30 days unless pinned. From here an admin can **Enroll this** (pre-fills the override name) or **Dismiss**.

**Architecture summary.** Two separate channels: HTTPS on port 8443 with TLS-pinned curl for enrollment + daily checkins (pull-control), and rsync-over-ssh on host port 2222 with per-sensor `authorized_keys` lines pinning each session to `command="rrsync -wo /logs/<name>/"` (push). Disenrollment works without a sensor-side daemon — the next hourly checkin returns `{"status":"disenrolled"}` and the script self-cleans.

**Persistence.** Sensor rows, tokens, unauthorized attempts, the SSL fingerprint, sshd host keys, and the per-sensor `authorized_keys` lines all live in named volumes (`archer-data`, `archer-sshd`, `archer-quiver`) and the host bind `./logs/`. `./start.sh up` rebuilds the image but never loses sensor state.

For the full operator guide — architecture diagrams, sensor-side artifact layout, distro-specific notes, troubleshooting, and the sensor-facing endpoint reference — see **[docs/QUIVER.md](docs/QUIVER.md)**.

---

## User Roles

The first user to register automatically becomes an **admin** and is signed in immediately. Subsequent registrations create a **pending** account with the **viewer** role; the new user cannot sign in until an administrator approves them from the **Users** dialog. Approved viewers can be promoted to **analyst** or **admin** by an admin via the same dialog.

| Capability | Admin | Analyst | Viewer |
|---|:---:|:---:|:---:|
| View findings, campaigns, hosts | ✓ | ✓ | ✓ |
| View watch mode status | ✓ | ✓ | ✓ |
| Acknowledge / escalate findings | ✓ | ✓ | — |
| Add analyst notes | ✓ | ✓ | — |
| Run TI escalation lookups | ✓ | ✓ | — |
| Start / pause / stop analysis | ✓ | ✓ | — |
| Scan and clear log files | ✓ | ✓ | — |
| Edit allowlist and IOC list | ✓ | ✓ | — |
| Manage suppressions | ✓ | ✓ | — |
| Update analysis thresholds | ✓ | — | — |
| Manage API keys | ✓ | — | — |
| Configure watch mode (anchor time / timezone / cadence) | ✓ | — | — |
| Scan archive for IOCs | ✓ | — | — |
| View disk-usage telemetry | ✓ | ✓ | ✓ |
| View Sensors modal (read-only tables) | ✓ | ✓ | — |
| Enroll / disenroll / purge sensors | ✓ | — | — |
| Generate / revoke enrollment tokens | ✓ | — | — |
| Reassign sensor push slot | ✓ | — | — |
| Dismiss unauthorized-attempt rows | ✓ | — | — |
| Set sensor-facing host override | ✓ | — | — |
| Create / delete users | ✓ | — | — |
| Promote / demote user roles | ✓ | — | — |

Sessions are stored in SQLite with a 24-hour expiry, httpOnly cookies, and `SameSite=Strict` enforcement.

---

## Web Interface

### Sidebar

| Section | Controls |
|---|---|
| **Logs** | Shows the configured log directory and a read-only preview tree of `<sensor>/<date>/` directories under `/logs`. Click a sensor to expand its dates with file counts and total size. The tree refreshes automatically when an analyze pass finishes, so newly-arrived (rsync'd or hand-dropped) logs appear without a page reload. |
| **Analysis** | **Analyze logs** starts the detection pipeline against everything currently under `/logs`. Disabled when the tree is empty. A progress bar and step indicator update in real time via SSE. **Pause** and **Stop** are available during a run. The analyzer checks for cancellation at phase boundaries (not in tight loops), so there can be a noticeable delay between clicking **Stop** and the run actually winding down — the button visibly switches to "Stopping…" and the status line shows *"Cancellation requested — waiting for analyzer to wind down…"* until the run exits. Manual analyze runs the full pipeline and preserves analyst state (notes / acks / escalations) via fingerprint merge — useful during active hunts when you want a fresh detection pass without losing your annotations. |
| **Threat Intel** | Displays a count of TI hits found in the last analysis. |
| **Watch Mode** | All users see whether watch mode is enabled and a compact three-line schedule preview: cadence + anchor + timezone abbreviation on the head (e.g. *"Every 6h, anchor 12:00 EDT"*), then *"Next: today 06:00 — incremental TI/IOC"* for sub-daily cadences (or *"— full pipeline"* when the next tick is the daily slot), then a third line *"Full pipeline: tomorrow 00:00"* when the next tick is incremental — so an analyst knows whether beacon detection will refresh at the next tick or wait until the daily slot. Times use relative dates (today/tomorrow/weekday) and the timezone abbreviation is shown once, not repeated. Admins pick a **Cadence** first (Daily / Every 12h / Every 6h / Every 4h / Hourly); the time control beneath it adapts: full HH:MM picker labeled `Run at` for Daily, `First run at` for the multi-hour cadences, and a minute-of-hour numeric input under Hourly (the server only uses the minute portion there). Cadence, time, and timezone auto-save on change and persist independently of the enable/disable toggle. |
| **Allowlist** | Edit the list of IPs and domains to exclude from all findings. One entry per line. Findings matching an allowlisted IP are hidden across all tabs immediately after saving. |
| **IOC List** | Edit the list of known-bad IPs and domains. Findings with a src/dst IP matching this list are tagged and appear in the IOC Hits tab. |
| **Suppressions** | View all active suppressions with their target, context, and expiry time. Individual suppressions can be removed here; expired suppressions are pruned automatically. |

### Finding Tabs

The first four tabs (Findings / Acknowledged / Escalated / IOC Hits) all view the same network-event finding set with different status filters. The last two (Campaigns / Hosts) are aggregations built client-side from the same data. Per-host roll-up findings (`Host Risk Score`) are excluded from the four findings tabs and from the bell — they live in the Hosts tab where the score actually means something to the analyst.

| Tab | Contents |
|---|---|
| **Findings** | All open (unacknowledged, non-escalated) network-event findings |
| **Acknowledged** | Network-event findings marked as reviewed |
| **Escalated** | Network-event findings sent to threat intelligence or escalated for response |
| **IOC Hits** | Network-event findings where src or dst IP matches the IOC list, plus all `TI Hit (IP)` / `TI Hit (Domain)` / `TI Hit (Hash)` / `Suspicious URL` findings |
| **Campaigns** | Destinations contacted by two or more distinct internal source IPs — potential shared C2 infrastructure |
| **Hosts** | Per-host composite risk scores aggregated across all finding types. Click any row to open the underlying `Host Risk Score` finding's detail panel (composite score, contributing detection types, weighting breakdown). Right-click for the standard pivots. |

### Findings Table

Columns: **Score**, **Severity**, **Type**, **Source** (IP + port), **Destination**, **Port**, **Time (UTC)**, **Status**, **Sensor**, **Detail**. All columns are sortable. Findings timestamps are always rendered in UTC for consistency across analysts in different time zones.

**Basic filters** (always visible): free-text search across IP addresses, domain names, types, and detail strings; severity level; detection type; minimum score.

**Advanced filters** (collapsible panel, state remembered): **Src IP/CIDR**, **Dst IP/CIDR**, **Dst Port**, **Sensor**, **From**, and **To** (time-range pickers). All filters are server-side and compose freely.

**Exports**: every tab has its own CSV and JSON download.

- **⬇ Export current tab ▾** in the filter bar dispatches based on the active tab — Findings/Ack/Esc/IOC do a server-side export honoring all active filters plus the tab's status filter; Campaigns and Hosts emit their client-side aggregations directly. CSV or JSON for any tab.
- **⬇ Export all ▾** in the filter bar exports every finding in the database, ignoring filters and tab. CSV or JSON.
- **Single campaign export** — right-click any row in the Campaigns tab and pick **Export campaign ▸** to get a hub-and-spoke graph (one node per source IP plus a destination hub) ready for graph viewers. Submenu offers four formats:
  - **CSV** — edge list with `Source`, `Target`, `Port`, `MaxScore`, `FindingTypes` columns; works with [Cytoscape Web](https://js.cytoscape.org/) and any spreadsheet
  - **Graphology JSON** — [Graphology serialization](https://graphology.github.io/serialization.html) format (`{attributes, nodes, edges}`)
  - **GEXF** — Gephi's native XML format, the most reliable choice for [Gephi Lite](https://gephi.org/gephi-lite/) and desktop Gephi
  - **GraphML** — XML format consumed by Cytoscape Desktop, yEd, and most desktop graph tools (note: Cytoscape Web does not accept GraphML — use the CSV export for it)
- **In-app graph view** — right-click any campaign row and pick **View campaign in Graph** to open the network inline. Uses an embedded Cytoscape.js renderer (lazy-loaded on first open) with severity-coloured nodes/edges, node sizes that scale with finding count, force-directed `cose` layout, fit-to-view and re-layout controls. Clicking a node jumps the findings table to a finding involving that IP — the graph doubles as a navigation surface.

Filter-bar dropdowns produce server-streamed downloads for findings tabs and client-side Blob downloads for Campaigns/Hosts; right-click campaign exports are always client-side.

**Delta mode**: **New Only** / **Show All** toggle to focus on findings that appeared in the most recent analysis.

### Right-Click Menu (any findings tab)

The context menu reshapes itself based on what was right-clicked, the user's role, and the finding's current state:

- **Click-anchor arrow** at one of the menu's four corners (↖↗↙↘) — JS measures the menu after reveal and clamps it inside the viewport with an 8px margin, then places the arrow at the corner closest to the click point so the menu always has a visual reference back to where you right-clicked.
- **Column-aware section** — if the right-click landed on a Source or Destination cell, the menu offers `Pivot to <ip>`, `Add <ip> to Allowlist`, `Add <ip> to IOC List`, and `Lookup <ip> ↗ ▸`. The same right-click on any other cell hides the column-aware items entirely and shows only row-level actions, since there's no clear single target.
- **External lookups** (8 destinations, all open in a new tab): VirusTotal, AbuseIPDB, Shodan, CrowdSec, Censys, GreyNoise, URLscan.io, AlienVault OTX. Censys and GreyNoise free tiers require an account; URLscan and OTX direct-link reads work without one.
- **Row-level actions**: Copy PCAP Filter, Copy Row, Source Records, Beacon Chart (visible for `Beaconing` and `HTTP Beaconing` finding types), Acknowledge, Escalate, Suppress ▸ (1d/7d/14d/30d).
- **State-aware disabling**: greyed and click-blocked when an action no longer applies — `Acknowledge` for already-acknowledged findings, `Escalate` for already-escalated ones, `Add to Allowlist`/`IOC` when the resolved IP is already on the respective list. Tooltips explain the reason on hover.
- **Role-gated**: write actions (Ack, Escalate, Suppress, Add to Allowlist/IOC) are hidden entirely for viewer-role users so the menu never offers a click that would dead-end at a 403.
- **Tab-gated**: Acknowledge / Escalate / Suppress are hidden on the Campaigns and Hosts tabs (and the separator above them collapses with them). Those actions operate on a single finding's status and don't make sense on a synthesised aggregate row.
- **Campaign-only items** (View campaign in Graph, Export campaign ▸) appear when right-clicking a row in the Campaigns tab.

### Detail Pane

Selecting a finding opens the detail pane, which shows:

- Full finding metadata and description
- **Acknowledge** — marks the finding as reviewed
- **Escalate** — opens the TI escalation dialog
- **Beacon Chart** — three-view canvas dialog for `Beaconing` and `HTTP Beaconing` findings: **Timeline** (one vertical tick per connection event on a fit-to-span time axis — eyeball test for regularity), **Interval histogram** (distribution of inter-arrival gaps with a dashed mean-interval reference line — tall single peak confirms a beacon's heartbeat), **Bytes** (legacy bytes-sent-per-bucket chart, useful for cross-checking exfil suspicion alongside a beacon). A stats strip above the canvas shows connection count / mean interval / jitter (CV) / span; a per-view PNG / JPEG export dropdown snaps the active canvas with a filename including the src→dst pair and view name. **Interactive zoom** on the Timeline view: click-drag to brush-select a time range and the view re-fits to that slice (the data is already client-side, so zoom doesn't refetch). Right-click on the canvas or the **Reset zoom** button returns to auto-fit. Switching to Interval histogram or Bytes drops the zoom since those views have their own X mappings.
- **PCAP Filter** — copies a ready-to-use `tcpdump` or Suricata filter string to the clipboard
- **Source Records** — scans the original Zeek logs (and `/data/archive`) for records matching the finding's (src, dst) pair, then opens a dialog with the full standard schema for the relevant log types. Columns are resizable; the table scrolls on both axes. A **Search range** dropdown (±6h default, up to All time) broadens the scan when needed. **Export CSV** flattens every loaded record into a single CSV with a leading `_log_type` column and canonical Zeek field ordering per type.
- **Suppress** — suppresses alerts for the source or destination IP for a configurable duration; suppressed findings are hidden from all tabs until the suppression expires or is manually removed
- **Analyst Recommendation** — auto-generated investigative guidance based on the finding type and score
- **Notes** — chronological thread of analyst annotations; new notes can be added inline

### Sensors Modal

Header **Sensors** button (admin + analyst). Three tables:

- **Enrolled Sensors** — read-only for analysts; admins also see Slot, Disenroll (red), and Purge data buttons. Slot and Last seen render in the watch-mode timezone with abbrev (e.g. `:30 hourly`, `2026-05-05 14:30:08 EDT`). **Health** column shows `✓ on time` (within 1h), `pending` (within 1.5h), `⚠ missed` (>1.5h since last checkin), or `never`. **Size** column shows the per-sensor `/logs/<name>/` byte total, populated from `/api/disk-usage` (5-minute server-side cache).
- **Pending Tokens** — outstanding enrollment tokens (24h TTL, single-use). Admins see the full token, override name, created/expires timestamps, and a Revoke button. Used tokens disappear from this list — they become rows in Enrolled Sensors. Live SSE updates: when a sensor finishes enrollment, the in-flight enrollment dialog flips to "✓ Enrolled as `<name>`" and the parent table refreshes automatically.
- **Unauthorized Attempts** — checkins from sensor names Archer doesn't know about. Auto-prunes after 30 days unless an admin pins a row. Admin actions: **Enroll this** (pre-fills override name in the token dialog) or **Dismiss**. Live SSE updates the list when a fresh unrecognized checkin arrives.

Admin-only "+ Enroll new sensor" dialog: optional override name, **Generate token**, then a 1200px-wide dialog showing the full curl one-liner with **Copy**, plus a status row that flips from "Waiting for sensor to run the install command…" (pulsing accent dot) to "✓ Enrolled as `<name>`" (green check) the moment the server records the enrollment. Closing the dialog refreshes the parent Sensors table.

### Settings Dialog (Admin only)

Opened with the gear button in the header. Contains:

- **Beaconing / DNS thresholds** — runtime-tunable detection parameters
- **Threat Intelligence** — VirusTotal, AbuseIPDB, OTX, CrowdSec, GreyNoise (optional), and Censys (`API ID` + `API Secret`, rendered as a single combined field where the secret half is masked). GreyNoise is the only entry that's optional — its Community API works unauthenticated; supplying a key lifts the rate limit.
- **Watch Mode** — opt-in **Always run full scan on every watch tick** checkbox. By default the watch loop runs the full pipeline only on the first UTC-day tick and a cheaper incremental TI/IOC pass on subsequent same-day ticks. Turning this on makes every tick a full pipeline run — closes the "wait until tomorrow" gap on statistical detectors at the cost of more CPU per tick. Useful during active hunts; off by default for resource-conscious background monitoring. The sidebar's schedule preview drops the "Next Full Scan:" follow-up line when this is on (every tick is full, so the line would be redundant).
- **Log Archive** — enable/disable automatic archive, retention days, and the opt-in **Also remove findings older than the archive cutoff** toggle; includes a **Run Archive Now** button that uses the saved settings, and a **Scan Archive for IOCs** button that retroactively re-scans `/data/archive` against the current IOC list and TI feeds (Feodo / URLhaus / Suspicious URL) without rerunning the heavy analysis phases. New IOC matches surface as findings via the same fingerprint-merge as a regular run.
  - **Retention is a detection-coverage decision, not just a disk-usage one.** Beacon detection only operates on whatever's currently in `/logs` — once a file is archived, the math can't see it. Minimum detectable beacon period ≈ `retention_days / BeaconMinConnections`. With the default 10-connection minimum: 5-day retention catches any beacon faster than ~12h (Cobalt Strike, hourly C2, etc.) but misses daily/weekly APT-cadence beacons; 30-day retention extends coverage down to every-3-day beacons; 60-day reaches every-6-day. Keep retention high enough for the slowest beacon period you care about catching. Findings detected on prior, larger-window runs persist across re-runs (fingerprint merge), but their scores are frozen at whatever the most recent successful detection computed — they don't accumulate as more data arrives. See `docs/DETECTION_METHODS.md` section 16 for the full tuning math.
- **Disk Usage** — auto-refreshing block (5-minute server-side cache via `/api/disk-usage`) showing per-sensor `/logs/<name>/` byte totals under a **Logs** section, the `/data/archive` total under an **Archive** section, and the free-space remaining on each volume. A red banner pins to the top of the page when any tracked volume drops below 10% free.
- **Danger Zone** — **Discard findings & re-analyze** button that clears every finding in the database and runs a fresh analysis. Useful for clean re-baselines after threshold changes. Destructive — analyst notes and statuses on existing findings are lost; confirmation required.

### Analysis Complete Alert

When an analysis run finishes, a centered dialog reports the total finding count and the number of new findings detected since the previous run.

---

## API Reference

All API endpoints require authentication. Role requirements are noted where applicable. The single exception is `/api/version`, which is unauthenticated diagnostic.

> Full reference (every endpoint, request/response shapes, query parameters, error codes, deprecation policy): **[docs/API.md](docs/API.md)**. The summary tables below in this README are kept brief; `docs/API.md` is the contract for what counts as a breaking change.

### Build Identifier

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/version` | None | `{"version":"v0.1.0","commit":"<short-sha>","build_time":"<iso-8601>"}`. Unauthenticated — same diagnostic tier as a future `/api/health`. The values come from `internal/version` and are populated at build time via `-ldflags` from the git checkout (see `start.sh`). The web UI reads this on init to populate the statusbar version pill and the About dialog. |

### Authentication

| Method | Path | Description |
|---|---|---|
| `POST` | `/login` | Authenticate with `{"email":"...","password":"..."}` |
| `POST` | `/register` | Create account with `{"name":"...","email":"...","password":"..."}` |
| `POST` | `/logout` | Invalidate current session |

### Users

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/me` | Any | Current user profile |
| `GET` | `/api/users` | Admin | List all users |
| `POST` | `/api/users` | Admin | Create user |
| `PATCH` | `/api/users/{id}` | Admin | Update user role |
| `DELETE` | `/api/users/{id}` | Admin | Delete user |

### Log Files

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/logs/tree` | Any | Sensor → date roll-up of `/logs` (file counts, sizes, newest mtime) |

### Analysis

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/api/analyze` | Analyst+ | Start analysis |
| `GET` | `/api/analyze/status` | Any | `{"running":bool,"paused":bool}` |
| `POST` | `/api/analyze/cancel` | Analyst+ | Stop running analysis |
| `POST` | `/api/analyze/pause` | Analyst+ | Pause running analysis |
| `POST` | `/api/analyze/resume` | Analyst+ | Resume paused analysis |
| `POST` | `/api/analyze/reset` | Admin | Clear all findings and launch a fresh analysis — used for baselining after threshold changes. Returns `{"status":"started","findings_cleared":N}` |

### Findings

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/findings` | Any | List findings (projected — `ts_data` / `intervals` / `notes` stripped). Query params: `search`, `type`, `severity`, `min_score`, `delta`, `src_ip` (IP or CIDR), `dst_ip` (IP or CIDR), `dst_port`, `sensor`, `from`, `to` (both accept `YYYY-MM-DD HH:MM:SS` UTC or RFC3339), `status` (`open` / `acknowledged` / `escalated`), `ioc_only` (`true`), `sort`, `dir`, `limit` (default 1000, max 50000), `offset` (default 0). Sets `X-Total-Count` and `X-Has-More` response headers (and `Access-Control-Expose-Headers` so JS can read them in CORS contexts). The per-tab page-nav buttons drive this. |
| `GET` | `/api/findings/counts` | Any | `{open, ack, esc, ioc, total}` aggregate counts honoring the active filter set (`status` / `ioc_only` are stripped — the counts span all status buckets). Drives the dashboard's info-line counters without forcing a full-set scan from the client. |
| `GET` | `/api/findings/facets` | Any | `{types, sensors}` — distinct values across the filter set. `status`, `ioc_only`, `delta`, `type`, `sensor`, `limit`, `offset` are stripped so the dropdowns reflect every available value regardless of what's currently selected. Powers the Type and Sensor filter dropdowns. |
| `GET` | `/api/findings/{id}` | Any | Single finding detail (full shape including `ts_data` / `intervals` / `notes`). |
| `GET` | `/api/findings/{id}/raw` | Any | Raw-log pivot. Returns source Zeek records matching the finding's (src, dst) pair. Query params: `limit` (default 500, max 5000), `window_hours` (default 6; `0` means no time filter — scan every matching file) |
| `PATCH` | `/api/findings/{id}` | Analyst+ | Update status: `{"status":"acknowledged"\|"escalated","analyst":"...","note":"..."}` |
| `POST` | `/api/findings/{id}/escalate` | Analyst+ | Escalate + run TI lookups: `{"note":"...","ips":["..."],"services":["vt","crowdsec","otx","abuseipdb","greynoise","censys"]}`. Each lookup's outcome is streamed as a `ti_result` SSE event; once all settle, a single consolidated TI Enrichment note is appended to the finding. |
| `POST` | `/api/findings/{id}/notes` | Analyst+ | Add note: `{"text":"..."}` |

### Exports

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/export/json` | Any | Download filtered findings as JSON. Accepts every query param supported by `GET /api/findings`. The per-finding chart data (`ts_data`, `intervals`) is stripped from the output — it's only used by the in-UI beacon chart and bloats the file ~10–20×. Pass `?include_lists=true` to bundle the current allowlist and IOC list in the output (needed only for `/api/import` round-trips). |
| `GET` | `/api/export/csv` | Any | Download filtered findings as CSV. Accepts every query param supported by `GET /api/findings` |

### Archive

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/archive` | Any | `{"enabled":bool,"after_days":N,"prune_findings_on_archive":bool,"last_run_at":"...","last_files_archived":N,"last_bytes_archived":N,"last_findings_pruned":N,"last_triggered_by":"..."}` — last_* fields are read-only telemetry omitted on a never-run instance |
| `POST` | `/api/archive` | Admin | Update archive config. Accepts `{"enabled":bool,"after_days":N,"prune_findings_on_archive":bool}` — last_* fields are ignored if sent |
| `POST` | `/api/archive/run` | Admin | Run the archive worker. Optional body `{"dry_run":true}` reports what would be moved/pruned without touching disk or the findings table; omit body or pass `{"dry_run":false}` to execute. Returns `{"files_archived":N,"bytes_archived":N,"findings_pruned":N,"skipped":N}` |
| `POST` | `/api/archive/scan` | Admin | Retroactive IOC + TI scan over `/data/archive`. Skips beacon/exfil/lateral/etc. — only the IOC list, Feodo Tracker, URLhaus, and Suspicious URL phases run. New matches surface as findings via the same fingerprint-merge as a regular run. Empty body. Returns `{"status":"started"}`; progress is emitted via the standard `progress` / `done` SSE events. |

### Disk Usage

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/disk-usage` | Any | `{"logs":{"total_bytes":N,"free_bytes":N,"sensors":[{"name":"...","bytes":N},...]},"archive":{"total_bytes":N,"free_bytes":N}}`. Server-side cached for 5 minutes — calling more often returns the cached snapshot. The Sensors modal Size column and Settings → Disk Usage block both poll this endpoint. |

### Configuration

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/config` | Any | Get all thresholds and API key presence |
| `PUT` | `/api/config` | Admin | Replace full config (JSON body matching config schema) |

### Lists

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/allowlist` | Any | `["ip-or-domain", ...]` |
| `PUT` | `/api/allowlist` | Analyst+ | Replace allowlist: `["ip-or-domain", ...]` |
| `GET` | `/api/ioc` | Any | `["ip-or-domain", ...]` |
| `PUT` | `/api/ioc` | Analyst+ | Replace IOC list: `["ip-or-domain", ...]` |

### Suppressions

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/suppressions` | Any | `[{"target":"1.2.3.4","expiry":1234567890,"detail":"..."},...]` |
| `POST` | `/api/suppressions` | Analyst+ | Add suppression: `{"target":"1.2.3.4","days":7,"detail":"..."}` |
| `DELETE` | `/api/suppressions/{target}` | Analyst+ | Remove suppression immediately |

### Notifications

The bell fires for new findings that are CRITICAL or of type `TI Hit (IP)` / `TI Hit (Domain)` / `TI Hit (Hash)` / `Suspicious URL`. `Host Risk Score` is intentionally excluded — it's a per-host roll-up, not a discrete event, and the underlying network detections that pushed the host's score over the line have already generated their own notifications.

Each notification has a **Jump** button. Clicking it lands the analyst on the page containing that finding, regardless of the active tab's filter, sort, pagination, or delta-mode state. The Jump action clears every filter input (search, src/dst/port, severity, type, sensor, score floor, time range → All time, delta off), switches to the tab matching the finding's status, queries `/api/findings/{id}/position` to find the absolute offset under the cleared filter, fetches the page that contains it, and scrolls the row into view. Filters that the analyst had set are intentionally lost — the Jump is a "show me this finding now" action; rebuilding the filter is the cost of guaranteed visibility.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/notifications` | Any | List alert notifications |
| `POST` | `/api/notifications` | Any | `{"action":"dismiss","id":N}` or `{"action":"dismiss_all"}` |

### Watch Mode

Watch ticks run in two tiers, automatic from the configured cadence:

- **First tick of each UTC calendar day → full analysis.** All phases (Beaconing, HTTP analysis, DNS, SSL, X.509, Files, Weird, Notices, TI, Host Risk Score). Statistical detectors need the long temporal window to spot patterns, so they get refreshed daily. Before the full pass launches, every enabled MISP / OpenCTI feed is refreshed in parallel under a two-minute global cap — this is the only path that fetches feeds (the auto-cadence worker is disabled, and there is no manual refresh endpoint).
- **Subsequent same-day ticks → incremental TI pass.** Only Phase 0 (feed prefetch — built-in Feodo Tracker / URLhaus only, no MISP/OpenCTI fetch) + Phase 3 (TI matching over the file subset modified since the last run). MISP / OpenCTI matching uses the indicator cache populated by the most recent full pass, so fresh hits from configured feeds surface within one tick interval without paying the upstream fetch cost. Stateless per-record, fast — typically seconds instead of the full-window minutes-to-hours.

The decision is automatic and persisted: `LastFullAnalysisUnix` (most recent full run) gates the full/incremental switch, `LastAnalysisUnix` (most recent run of either kind) is the mtime cutoff for the incremental file filter (with a 5-minute overlap so a log rotated at the boundary gets re-checked instead of missed). Manual "Discard findings & re-analyze" runs as a full pass and resets both timestamps, so the cycle restarts cleanly.

The `done` SSE event for incremental ticks includes `"incremental": true` so the UI can distinguish them from full-pass completions.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/watch` | Any | `{"time":"HH:MM","enabled":bool,"timezone":"America/New_York","timezone_abbr":"EDT","interval_hours":N,"next_run":"today 06:00","next_run_kind":"full|incremental","next_full_run":"tomorrow 00:00"}` — `interval_hours` is one of `24` (daily), `12`, `6`, `4`, or `1` (hourly). Sub-daily cadences anchor on the configured minute-of-hour. `timezone_abbr` is the resolved abbreviation (`EDT`, `PST`, `UTC`, …) — the long IANA name in `timezone` is the source of truth, this is the display form. `next_run` and `next_full_run` are pre-formatted relative-date strings (`today HH:MM`, `tomorrow HH:MM`, `Mon HH:MM` for same-week, `Jan 2 HH:MM` for further-out, year added only when it differs from the current calendar year) — no timezone is appended since the abbreviation is shown once on the cadence head. `next_run_kind` reflects the two-tier cadence: `"full"` when the upcoming tick is the daily full-pipeline pass (statistical detectors refresh), `"incremental"` when it's the hourly TI/IOC pass over mtime-filtered new files only. `next_full_run` always reports when the next full pipeline pass will fire — equals `next_run` for daily cadence and for sub-daily ticks where the next tick happens to be the full one. The sidebar's schedule preview surfaces all three so an analyst knows whether beacon detection will refresh at the next tick or wait until the daily slot. |
| `POST` | `/api/watch` | Admin | `{"time":"HH:MM","enabled":bool,"timezone":"America/New_York","interval_hours":N}` — empty `timezone` means UTC. Server validates the IANA name with `time.LoadLocation`; bad names return 400. `interval_hours` must be one of `1`, `4`, `6`, `12`, `24`; out-of-range values fall back to daily. |

### Threat Intelligence

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/ti/services` | Any | `{"vt":bool,"crowdsec":bool,"otx":bool,"abuseipdb":bool,"greynoise":bool,"censys":bool}` — true means API key is configured. `greynoise` is always `true` (Community API works unauthenticated; supplying a key only raises the rate limit). `censys` is true only when both API ID and Secret are configured. |

### Sensors (Admin UI)

Endpoints powering the Sensors modal. Read endpoints are open to admin + analyst; write endpoints are admin-only and enforce the role inside the handler.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/sensors` | Analyst+ | List every sensor row (any status), most recent enrollment first |
| `GET` | `/api/sensors/info` | Admin | `{"tls_fingerprint":"...","sensor_facing_host":"...","effective_host":"..."}` for rendering install one-liners |
| `PUT` | `/api/sensors/host` | Admin | `{"host":"192.0.2.10"}` (or `"host:port"`); set the sensor-facing override that install one-liners target |
| `GET` | `/api/sensors/tokens` | Admin | List enrollment tokens (used + unused) |
| `POST` | `/api/sensors/tokens` | Admin | `{"override_name":"..."}` mints a new single-use 24h token; returns `{token, override_name, created_at, expires_at, ...}` |
| `POST` | `/api/sensors/tokens/revoke` | Admin | `{"id":N}` deletes an outstanding token row |
| `POST` | `/api/sensors/disenroll` | Admin | `{"id":N}` flips the row to `disenrolling`, removes the authorized_keys line; the sensor self-cleans on its next checkin |
| `POST` | `/api/sensors/purge` | Admin | `{"id":N}` archives `/logs/<name>/`, retags findings, drops the sensor row (only allowed once status is `disenrolled`) |
| `POST` | `/api/sensors/schedule` | Admin | `{"id":N,"hour":0,"minute":N}` reassigns the push minute (hour is unused under hourly mode but accepted for backward compat) |
| `GET` | `/api/sensors/unauthorized` | Analyst+ | List recent unrecognized checkin attempts |
| `POST` | `/api/sensors/unauthorized/dismiss` | Admin | `{"id":N}` removes an unauthorized-attempt row |

### Quiver (sensor-facing, no session auth)

These endpoints are served on the TLS listener (`:8443`) and authenticated by single-use enrollment tokens (HTTPS) or per-sensor ed25519 keys (rsync sshd, host port `:2222`). They have no session cookies.

| Method | Path | Description |
|---|---|---|
| `GET` | `/quiver/install.sh` | Renders the install bash for the requesting host. Embeds the TLS fingerprint, host, ports, and base64-encoded daily + uninstall scripts so the install runs without a second network hop. |
| `POST` | `/api/quiver/enroll` | Body `{token, name, host, pubkey, protocol_version}`. Validates the token + protocol version, creates `/logs/<name>/`, writes the per-sensor `authorized_keys` line, persists the sensor row. Returns `{name, schedule_hour:0, schedule_minute:N, protocol_version}`. Unsupported protocol versions return HTTP 400 with `{error, sensor_version, server_version, supported_versions}`. |
| `POST` | `/api/quiver/checkin` | Body `{name, protocol_version}`. Returns `{"status":"enrolled","schedule":{"hour":0,"minute":N},"protocol_version":1}`, `{"status":"disenrolled","protocol_version":1}`, `{"status":"unknown","protocol_version":1}`, or `{"status":"protocol_unsupported","sensor_version":N,"server_version":1,"supported_versions":[1]}`. Unknown checkins create `unauthorized_attempts` rows and push an SSE event. Pre-versioning sensors that omit `protocol_version` are accepted as v1 for one compatibility cycle. |

See [docs/QUIVER.md](docs/QUIVER.md) for the full Quiver protocol description.

### Real-Time Events

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/events` | Any | SSE stream. Event types: `progress` `{"pct":N,"step":"..."}`, `status` `{"msg":"..."}`, `done` `{"count":N,"new_count":N,"cancelled":bool}`, `notification` (finding alert), `ti_result` `{"finding_id":N,"source":"...","detail":"...","hit":bool}`, `ti_done` `{"finding_id":N,"hits":N}`, `unauthorized_attempt` (full unauthorized-attempt row when an unknown sensor name checks in), `sensor_enrolled` (full sensor row when a fresh enrollment completes — drives the in-flight enrollment dialog's confirmation tick and the parent Sensors table refresh) |

---

## Versioning

Archer uses [Semantic Versioning](https://semver.org/) under the **0.x prefix**: `v0.MAJOR.MINOR`. Pre-1.0 minor versions may break any of four surfaces without a major bump:

1. **HTTP/SSE API contract** — renamed/removed `/api/*` fields, changed event shapes.
2. **DB schema** — table changes that require migration on upgrade.
3. **Quiver sensor protocol** — enrollment payload shape, rsync layout, ports, schedule contract.
4. **Detection semantics** — score formulas, thresholds, finding types, feed-matching logic.

These four surfaces become the stability contract once Archer reaches 1.0. Until then, releases call out breakage explicitly in `CHANGELOG.md` under `### Breaking` and (for detection-formula changes that may shift existing scores) `### Detection changes`.

**The current release** is identified by:

- `GET /api/version` — programmatic.
- The version pill at the bottom-right of the analyst UI status bar — clickable for build details (commit, build time).
- `docker inspect archer` — OCI image labels (`org.opencontainers.image.version`, `org.opencontainers.image.revision`).
- `git describe --tags` in the source checkout.

**To cut a release**, see [RELEASING.md](RELEASING.md) for the operator runbook.

**Release history** lives in [CHANGELOG.md](CHANGELOG.md), formatted per [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## Resetting to Factory State

Two paths, depending on scope.

**Soft reset — clear findings only.** From the Settings dialog, **Danger Zone → Discard findings & re-analyze** drops every finding in the database and relaunches analysis against the current log set. User accounts, allowlists, IOC lists, suppressions, threshold config, and API keys are preserved. Useful after threshold changes when you want a clean finding baseline without losing operator state.

**Hard reset — wipe the database volumes.** `reset.sh` stops Archer, removes the named Docker volumes (`archer-data`, `archer-sshd`, `archer-quiver` — i.e. SQLite DB, TLS material, sshd host keys, sensor `authorized_keys`), and starts a fresh instance. Log files in `./logs` are not affected. **Note:** wiping `archer-quiver` invalidates every enrolled sensor's pubkey — you'll need to re-enroll them. Wiping `archer-sshd` rotates the sshd host keys, so existing sensors' `known_hosts` will see a host-key mismatch on next push and need to re-pin (re-enrollment is the simplest path).

```bash
sudo ./reset.sh
```

The script prompts for confirmation before taking any action. After reset, navigate to `http://localhost:8080` and register a new admin account.

---

## Running Without Docker

```bash
# Install Go 1.21+
go build -o archer ./cmd/archer

# Run (requires a writable data directory and a logs directory)
./archer \
  --addr=:8080 \
  --web-dir=./web \
  --logs-dir=/path/to/zeek/logs \
  --data-dir=/path/to/data
```

The binary has no runtime dependencies beyond the operating system. SQLite is compiled in via a pure-Go driver — no `libsqlite3` required.

---

## License

MIT License

Copyright (c) 2026 BushidoCyb3r

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
