<p align="center">
  <img src="docs/archer-logo.png" alt="Archer — Silent Hunter" width="720">
</p>

# Archer — Network Threat Detection & Analyst Workbench

Archer is a self-hosted, open-source network threat detection platform that processes Zeek IDS log files to identify adversarial behaviors including C2 beaconing, data exfiltration, lateral movement, DNS tunneling, malicious TLS fingerprints, and more. It provides a browser-based analyst workbench for reviewing, annotating, and escalating findings — including live threat intelligence enrichment via VirusTotal, CrowdSec, AlienVault OTX, and AbuseIPDB.

---

## Table of Contents

- [Features](#features)
- [Detection Coverage](#detection-coverage)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installing Prerequisites](#installing-prerequisites)
- [Quick Start](#quick-start)
- [Log File Layout](#log-file-layout)
- [Configuration](#configuration)
- [Threat Intelligence](#threat-intelligence)
- [User Roles](#user-roles)
- [Web Interface](#web-interface)
- [API Reference](#api-reference)
- [Resetting to Factory State](#resetting-to-factory-state)
- [Running Without Docker](#running-without-docker)
- [License](#license)

---

## Features

- **Multi-log analysis** — ingests conn, DNS, HTTP, SSL, X.509, files, weird, and notice logs in TSV or JSON/NDJSON format, including gzip-compressed files
- **Bounded memory detection** — beacon analyzers use streaming aggregates and reservoir sampling so peak memory is a function of unique pair count, not total record count; Docker entrypoint auto-derives `GOMEMLIMIT` from the container's cgroup so the Go runtime applies back-pressure before OOM
- **Persistent findings** — findings survive restarts, rebuilds, and re-analyses; analyst annotations (status, notes, assignee) are carried over by fingerprint match; findings are preserved even when the logs that produced them are later archived, and are only removed when an admin explicitly prunes them
- **Delta detection** — new findings are flagged so analysts can focus on what changed since the last run
- **Raw-log pivot** — clicking a finding opens a Source Records dialog that scans the original Zeek logs (plus the archive) for matching records and renders the full standard schema with resizable, horizontally-scrollable columns
- **Advanced filtering** — in addition to search/severity/type/min-score, filters include Src IP/CIDR, Dst IP/CIDR, dataset, and a time range; all filters are server-side
- **Filtered exports** — CSV and JSON exports honor the current filter state so the downloaded file matches exactly what the analyst sees on screen
- **Log archive & retention** — admin-configurable: files older than N days automatically move from `/logs` to `/data/archive` after each watch analysis; findings are preserved by default (or optionally pruned past the same cutoff)
- **Dataset fingerprint skip** — watch-mode re-analyses short-circuit when the set of files + their sizes + mtimes is unchanged from the last successful run; nightly runs over a static dataset return in milliseconds
- **Preflight memory warning** — before each run Archer compares the total log size against `GOMEMLIMIT` and surfaces a status-bar warning when the run is projected to approach or exceed the budget
- **Live threat intelligence** — manual escalation queries VirusTotal, CrowdSec CTI, AlienVault OTX, and AbuseIPDB; results are saved as permanent notes on the finding and pushed to the browser in real time via Server-Sent Events
- **Automatic free TI feeds** — Feodo Tracker C2 IPs and URLhaus malware hosts are fetched and cross-referenced during every analysis run without requiring API keys
- **Role-based access control** — admin, analyst, and viewer roles with per-endpoint enforcement
- **Analyst workbench** — acknowledge, escalate, suppress, add notes, and copy tcpdump/Suricata filter strings directly from the UI
- **Watch mode** — admin-configurable daily schedule that automatically re-analyzes the logs directory at a set UTC time
- **Campaign & host views** — see which destinations are contacted by multiple internal hosts and view per-host composite risk scores
- **Resource-aware deployment** — `start.sh` automatically allocates 80% of host CPU and RAM to the container; the container entrypoint then wires the Go runtime memory limit to 90% of whatever budget it gets

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
| **Threat Intel Hit** | Source or destination IP/domain matched against Feodo Tracker C2 IPs or URLhaus malware hosts during analysis; or confirmed malicious by a TI service during analyst escalation | CRITICAL |
| **Suspicious URL** | HTTP destination matched against URLhaus malware distribution hosts | CRITICAL |

### Composite Scoring

| Detection Type | Description | Severity |
|---|---|---|
| **Host Risk Score** | Weighted composite score (0–100) aggregated across all findings for a given source IP. Weights: Cobalt Strike URI +40, Malicious JA3 +40, Domain Fronting +32, Threat Intel Hit +35, HTTP Beaconing +28, Beaconing +30, Data Exfiltration +25, Lateral Movement +20, Strobe +15, Long Connection +10 | CRITICAL / HIGH / MEDIUM / LOW |

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
│   │   ├── findings_filter.go  # Shared query-param filter used by list + exports
│   │   ├── findings_raw.go     # Raw-log pivot: finds source records for a finding
│   │   ├── archive.go          # Aged-log archive worker + finding prune
│   │   ├── watch.go            # Watch mode scheduler, dataset fingerprint skip, preflight check, launchAnalysis
│   │   ├── auth.go             # Session management, role middleware
│   │   ├── upload.go           # Log file ingestion
│   │   └── sse_broker.go       # Server-Sent Events fan-out
│   └── store/
│       ├── store.go            # Findings, allowlist, IOC list, suppressions, config — SQLite persistence
│       └── userstore.go        # User accounts, sessions — SQLite persistence
└── web/
    ├── templates/index.html    # Single-page application shell
    └── static/
        ├── css/archer.css
        └── js/
            ├── app.js          # Main application state machine
            ├── sse.js          # SSE connection manager with auto-reconnect
            ├── detail.js       # Finding detail pane renderer
            ├── table.js        # Findings table with sort/filter
            ├── chart.js        # Beacon inter-arrival time chart
            ├── campaigns.js    # Campaign aggregation view
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

Each subdirectory under `logs/` is treated as a distinct **dataset** or campaign and is labeled as such throughout the UI. Files can be uncompressed (`.log`) or gzip-compressed (`.log.gz`, `.gz`).

### 3. Start Archer

One command. No configuration required.

```bash
sudo ./start.sh up
```

`start.sh` measures the host, allocates 80% of available CPU and RAM to the container, builds the image, and starts Archer on port 8080. Drop the tool on a 16 GB laptop and it scales down; drop it on a 256 GB analysis box and it scales up. No env vars to set, no memory values to guess.

```
Host resources:   16 CPUs  |  32768 MB RAM
Archer limits:    12.8 CPUs  |  26214m RAM  (80%)

Archer is running at http://localhost:8080
```

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

### 5. Import and analyze

1. Click **Import** in the sidebar to scan the `logs/` directory
2. Click **Analyze** to run the full detection pipeline
3. Findings appear in real time as the pipeline progresses

---

## Log File Layout

Archer reads Zeek-format logs. Files may be uncompressed (`.log`) or gzip-compressed (`.log.gz`, `.gz`). Both TSV (tab-separated with `#fields` header) and JSON/NDJSON formats are supported.

The directory immediately under the configured logs root is used as the **dataset name** displayed throughout the UI. Deeper nesting is allowed but only the first level is used as the label:

```
/logs/<dataset-name>/[subdirs/]<file>.log
```

Supported log filenames: `conn`, `dns`, `http`, `ssl`, `x509`, `files`, `weird`, `notice` (with or without `.log` suffix, with or without `.gz`).

---

## Configuration

All thresholds are configurable at runtime through the **Settings** dialog (admin only). Changes are persisted in SQLite and survive restarts.

### Analysis Thresholds

| Parameter | Default | Description |
|---|---|---|
| `beacon_min_connections` | `10` | Minimum connection count before beacon scoring is applied |
| `beacon_max_jitter_cv` | `0.35` | Maximum coefficient of variation for inter-arrival times |
| `beacon_min_interval_sec` | `2` | Minimum seconds between connections to qualify as a beacon |
| `beacon_gap_multiplier` | `5.0` | Tolerance multiplier for gaps in the beacon timeline |
| `http_beacon_min_requests` | `8` | Minimum HTTP request count before HTTP beacon scoring is applied |
| `http_beacon_max_cv` | `0.40` | Maximum coefficient of variation for HTTP request timing |
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

### Paid / Registered Services (API Key Required)

Configure API keys in the **Settings** dialog. Only services with a configured key are available for escalation lookups.

| Service | Lookup Type | What is Checked |
|---|---|---|
| **VirusTotal** | IP addresses and domains | Malicious engine detection count from `last_analysis_stats` |
| **CrowdSec CTI** | IP addresses only | Overall reputation score from the smoke feed |
| **AlienVault OTX** | IP addresses and domains | Threat pulse count and reputation score |
| **AbuseIPDB** | IP addresses only | Abuse confidence score (0–100%) and total report count (last 90 days) |

### Escalation Workflow

When an analyst escalates a finding, Archer opens a dialog to:

1. Select which artifact to look up — **Dst IP**, **Src IP**, or both
2. Select which TI services to query (only services with configured API keys are shown)

Lookups run in the background. For each service queried:
- A permanent **note** is added to the finding with the full result
- A **toast notification** is pushed to the browser in real time
- A final summary toast indicates total hit count when all lookups complete

Results are classified as `[HIT]` (threat confirmed) or `[CLEAN]` (no threats found) and stored permanently regardless of outcome.

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
| Configure watch mode | ✓ | — | — |
| Create / delete users | ✓ | — | — |
| Promote / demote user roles | ✓ | — | — |

Sessions are stored in SQLite with a 24-hour expiry, httpOnly cookies, and `SameSite=Strict` enforcement.

---

## Web Interface

### Sidebar

| Section | Controls |
|---|---|
| **Zeek Logs** | Shows the current log directory; **Import** scans for new files; **Clear** removes the file list. The file list is grouped by dataset name with a file count. |
| **Analysis** | **Analyze** starts the detection pipeline. A progress bar and step indicator update in real time via SSE. **Pause** and **Stop** are available during a run. |
| **Threat Intel** | Displays a count of TI hits found in the last analysis. |
| **Watch Mode** | All users can see whether watch mode is enabled and when the next run is scheduled. Admins can set a daily UTC time and enable or disable automatic analysis. |
| **Allowlist** | Edit the list of IPs and domains to exclude from all findings. One entry per line. Findings matching an allowlisted IP are hidden across all tabs immediately after saving. |
| **IOC List** | Edit the list of known-bad IPs and domains. Findings with a src/dst IP matching this list are tagged and appear in the IOC Hits tab. |
| **Suppressions** | View all active suppressions with their target, context, and expiry time. Individual suppressions can be removed here; expired suppressions are pruned automatically. |

### Finding Tabs

| Tab | Contents |
|---|---|
| **Findings** | All open (unacknowledged, non-escalated) findings |
| **Acknowledged** | Findings marked as reviewed |
| **Escalated** | Findings sent to threat intelligence or escalated for response |
| **IOC Hits** | Findings where src or dst IP matches the IOC list, plus all Threat Intel Hit type findings |
| **Campaigns** | Destinations contacted by two or more distinct internal source IPs — potential shared C2 infrastructure |
| **Hosts** | Per-host composite risk scores aggregated across all finding types |

### Findings Table

Columns: **Score**, **Severity**, **Type**, **Src IP**, **Dst IP**, **Port**, **Timestamp**, **Dataset**, **Detail**, **Status**. All columns are sortable.

**Basic filters** (always visible): free-text search across IP addresses, domain names, types, and detail strings; severity level; detection type; minimum score.

**Advanced filters** (collapsible panel, state remembered): **Src IP/CIDR**, **Dst IP/CIDR**, **Dataset**, **From**, and **To** (time-range pickers). All filters are server-side and compose freely.

**Exports**: **⬇ CSV** and **⬇ JSON** buttons produce a file reflecting exactly what the current filter state returns. With no filters set, the full findings list is exported.

**Delta mode**: **New Only** / **Show All** toggle to focus on findings that appeared in the most recent analysis.

### Detail Pane

Selecting a finding opens the detail pane, which shows:

- Full finding metadata and description
- **Acknowledge** — marks the finding as reviewed
- **Escalate** — opens the TI escalation dialog
- **Beacon Chart** — visualises inter-arrival times and connection timestamps (beaconing findings only)
- **PCAP Filter** — copies a ready-to-use `tcpdump` or Suricata filter string to the clipboard
- **Source Records** — scans the original Zeek logs (and `/data/archive`) for records matching the finding's (src, dst) pair, then opens a dialog with the full standard schema for the relevant log types. Columns are resizable; the table scrolls on both axes. A **Search range** dropdown (±6h default, up to All time) broadens the scan when needed.
- **Suppress** — suppresses alerts for the source or destination IP for a configurable duration; suppressed findings are hidden from all tabs until the suppression expires or is manually removed
- **Analyst Recommendation** — auto-generated investigative guidance based on the finding type and score
- **Notes** — chronological thread of analyst annotations; new notes can be added inline

### Settings Dialog (Admin only)

Opened with the gear button in the header. Contains:

- **Beaconing / DNS thresholds** — runtime-tunable detection parameters
- **Threat Intelligence** — VirusTotal, AbuseIPDB, OTX, and CrowdSec API keys
- **Log Archive** — enable/disable automatic archive, retention days, and the opt-in **Also remove findings older than the archive cutoff** toggle; includes a **Run Archive Now** button that uses the saved settings
- **Danger Zone** — **Discard findings & re-analyze** button that clears every finding in the database and runs a fresh analysis. Useful for clean re-baselines after threshold changes. Destructive — analyst notes and statuses on existing findings are lost; confirmation required.

### Analysis Complete Alert

When an analysis run finishes, a centered dialog reports the total finding count and the number of new findings detected since the previous run.

---

## API Reference

All API endpoints require authentication. Role requirements are noted where applicable.

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
| `GET` | `/api/logs/scan` | Any | Get logs directory and current file count |
| `POST` | `/api/logs/scan` | Analyst+ | Scan logs directory for Zeek files |
| `GET` | `/api/files` | Any | List registered log files |
| `POST` | `/api/files/clear` | Analyst+ | Clear the file list |

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
| `GET` | `/api/findings` | Any | List findings. Query params: `search`, `type`, `severity`, `min_score`, `delta`, `src_ip` (IP or CIDR), `dst_ip` (IP or CIDR), `dataset`, `from`, `to` (both accept `YYYY-MM-DD HH:MM:SS` UTC or RFC3339), `sort`, `dir` |
| `GET` | `/api/findings/{id}` | Any | Single finding detail |
| `GET` | `/api/findings/{id}/raw` | Any | Raw-log pivot. Returns source Zeek records matching the finding's (src, dst) pair. Query params: `limit` (default 500, max 5000), `window_hours` (default 6; `0` means no time filter — scan every matching file) |
| `PATCH` | `/api/findings/{id}` | Analyst+ | Update status: `{"status":"acknowledged"\|"escalated","analyst":"...","note":"..."}` |
| `POST` | `/api/findings/{id}/escalate` | Analyst+ | Escalate + run TI lookups: `{"note":"...","ips":["..."],"services":["vt","crowdsec","otx","abuseipdb"]}` |
| `POST` | `/api/findings/{id}/notes` | Analyst+ | Add note: `{"text":"..."}` |

### Exports

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/export/json` | Any | Download filtered findings + allowlist + IOC list as JSON. Accepts every query param supported by `GET /api/findings` |
| `GET` | `/api/export/csv` | Any | Download filtered findings as CSV. Accepts every query param supported by `GET /api/findings` |

### Archive

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/archive` | Any | `{"enabled":bool,"after_days":N,"prune_findings_on_archive":bool}` |
| `POST` | `/api/archive` | Admin | Update archive config with the same shape |
| `POST` | `/api/archive/run` | Admin | Run the archive worker immediately against the saved config. Returns `{"files_archived":N,"bytes_archived":N,"findings_pruned":N,"skipped":N}` |

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

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/notifications` | Any | List alert notifications |
| `POST` | `/api/notifications` | Any | `{"action":"dismiss","id":N}` or `{"action":"dismiss_all"}` |

### Watch Mode

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/watch` | Any | `{"time":"HH:MM","enabled":bool,"next_run":"2026-04-25 02:00 UTC"}` |
| `POST` | `/api/watch` | Admin | `{"time":"HH:MM","enabled":bool}` |

### Threat Intelligence

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/ti/services` | Any | `{"vt":bool,"crowdsec":bool,"otx":bool,"abuseipdb":bool}` — true means API key is configured |

### Real-Time Events

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/events` | Any | SSE stream. Event types: `progress` `{"pct":N,"step":"..."}`, `status` `{"msg":"..."}`, `done` `{"count":N,"new_count":N,"cancelled":bool}`, `notification` (finding alert), `ti_result` `{"finding_id":N,"source":"...","detail":"...","hit":bool}`, `ti_done` `{"finding_id":N,"hits":N}` |

---

## Resetting to Factory State

Two paths, depending on scope.

**Soft reset — clear findings only.** From the Settings dialog, **Danger Zone → Discard findings & re-analyze** drops every finding in the database and relaunches analysis against the current log set. User accounts, allowlists, IOC lists, suppressions, threshold config, and API keys are preserved. Useful after threshold changes when you want a clean finding baseline without losing operator state.

**Hard reset — wipe the database volume.** `reset.sh` stops Archer, removes the entire SQLite volume (users, findings, suppressions, archive config — everything), and starts a fresh instance. Log files in `./logs` are not affected.

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
