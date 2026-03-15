# PhantomEye v2.0

```
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗███████╗██╗   ██╗███████╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔════╝╚██╗ ██╔╝██╔════╝
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║█████╗   ╚████╔╝ █████╗
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔══╝    ╚██╔╝  ██╔══╝
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ███████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝
```

**Hybrid Network & Web Vulnerability Assessment Framework**
`v2.0.0` &nbsp;|&nbsp; Author: `S1r1us` &nbsp;|&nbsp; Platform: `Linux / Kali`

---

## Overview

PhantomEye is a modular, extensible hybrid vulnerability assessment framework built entirely in Python. It combines the core capabilities of industry-standard tools — Nmap, Nikto, Nuclei, SQLMap, and OWASP ZAP — into a single unified CLI built for professional security assessments on Linux.

The framework covers the complete attack surface: network infrastructure, web applications, REST/GraphQL APIs, databases, SSL/TLS configuration, cloud environments (AWS/Azure/GCP), Docker and Kubernetes, compliance frameworks (PCI DSS, CIS, OWASP), OSINT collection, ICS/SCADA industrial protocols, and mobile device enumeration via ADB.

---

## Features

### Network
- TCP Connect, SYN Stealth, UDP, FIN, NULL, Xmas, ACK, Window, Maimon, Idle/Zombie port scans
- Host discovery — ICMP ping, TCP ping, ARP sweep, CIDR range sweep
- OS fingerprinting — TTL analysis, banner grab, TCP stack detection
- Service and version detection with CVE signature matching
- DNS enumeration — A/AAAA/MX/NS/TXT/SOA/SRV records, zone transfer (AXFR), subdomain brute-force
- SMB null session enumeration, share listing, EternalBlue (MS17-010) indicator check
- SNMP community string sweep, snmpwalk output capture
- SCTP INIT scan, IP protocol scan
- NSE-style script checks — FTP anonymous login, SSH weak algorithms, SMTP open relay, RDP exposure, Telnet check

### Web Application
- HTTP security header analysis (HSTS, CSP, X-Frame-Options, etc.)
- CMS detection — WordPress, Joomla, Drupal, Magento, Laravel, Django, Rails, Strapi, Ghost, Typo3
- Directory and file brute-force with system wordlist auto-detection and custom wordlist support
- Dangerous file detection — `.env`, `.git`, config files, database dumps, private keys
- SQL Injection — error-based, time-based blind
- Cross-Site Scripting — reflected XSS across all form parameters
- Local File Inclusion with file content signature verification
- Remote File Inclusion
- Open Redirect detection
- Server-Side Request Forgery (SSRF) with cloud metadata endpoint detection
- CSRF token validation on all POST forms
- CORS misconfiguration — wildcard, arbitrary origin reflection, ACAC bypass
- Path traversal — URL-based and parameter-based
- HTTP method enumeration and TRACE/XST check
- Server-specific checks — Apache server-status/info, Nginx alias traversal, IIS trace/elmah
- Directory listing detection
- Clickjacking protection check
- Technology stack fingerprinting
- WordPress and PHP version disclosure
- CGI script enumeration, Shellshock (CVE-2014-6271), PHP CGI RCE (CVE-2012-1823)
- Git/SVN/HG/Bazaar metadata exposure
- Environment and config file credential exposure
- JavaScript source map reconstruction exposure
- Error page stack trace and path leakage
- Backup and temporary file detection

### API Security
- REST and GraphQL endpoint discovery (50+ common paths)
- Spring Boot Actuator sensitive endpoint detection
- API documentation exposure — Swagger, OpenAPI, Redoc
- Authentication bypass — X-Original-URL, X-Forwarded-For, JWT alg:none
- IDOR via sequential object ID probing
- Rate limiting check on authentication endpoints
- GraphQL introspection enabled check

### SSL / TLS
- Certificate validity, expiry countdown, self-signed detection
- Subject Alternative Names enumeration
- Weak protocol detection — SSLv3, TLSv1.0, TLSv1.1
- Weak cipher suite detection — RC4, DES, 3DES, NULL, EXPORT, anon
- Heartbleed raw socket probe — CVE-2014-0160
- POODLE check — CVE-2014-3566
- Full TLS version support matrix (TLSv1.0 through TLSv1.3)

### Database Assessment
- Port detection for 12 database types
- MySQL — banner grab, EOL version detection, default credential brute-force
- PostgreSQL — SSL check, default credential brute-force
- MongoDB — unauthenticated access probe
- Redis — unauthenticated access, dangerous CONFIG write path detection
- Elasticsearch — open cluster access
- MSSQL — banner grab
- CouchDB, Cassandra, Neo4j, InfluxDB, Memcached port detection

### Cloud Security
- AWS IMDSv1 metadata endpoint exposure, IAM credential path enumeration
- AWS S3 bucket enumeration — public read, private existence, region detection
- Azure IMDS endpoint exposure
- Azure Blob Storage anonymous container enumeration
- GCP metadata endpoint exposure
- GCP Cloud Storage bucket enumeration
- Docker Remote API unauthenticated access
- Kubernetes API server unauthenticated access

### Container Security
- Docker Remote API exposure on ports 2375, 2376, 4243
- Container registry unauthenticated access on ports 5000/5001
- Privileged container detection via docker inspect
- Dangerous volume mount detection — /, /etc, /proc, /sys, /root, docker.sock
- Host network mode detection
- Docker socket permission audit
- Kubernetes API server, Kubelet API (10250/10255), etcd (2379/2380) exposure

### Host Audit
- OS information, kernel version, CVE correlation table
- Running services audit with insecure service flagging
- User enumeration — UID 0 check, login shell accounts, NOPASSWD sudo
- SUID/SGID binary audit with dangerous binary flagging
- World-writable file detection across /etc, /var, /tmp
- Cron job audit for network and shell execution commands
- SSH configuration hardening — PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, Protocol 1
- iptables and UFW firewall policy audit
- Pending package updates via apt and yum/dnf
- Kernel CVE correlation for known privilege escalation vulnerabilities
- Suspicious process detection matching known miner and malware patterns
- Known malware hash check across temp directories
- Rootkit kernel module indicator check
- Backdoor listening port detection
- Credentialed audit via SSH — shadow access, sudo permissions, sensitive file readability
- Unauthenticated service enumeration — Redis and MongoDB null auth

### Compliance
- PCI DSS requirements mapping — Req 1 (network), Req 2 (config), Req 4 (crypto), Req 6 (dev)
- OWASP Top 10 2021 mapping across all findings
- CIS Benchmark — filesystem (noexec, sticky bit), access control, logging, network hardening
- SCAP — OpenSCAP availability check and guidance
- AIDE file integrity check
- auditd daemon status check

### OSINT
- IP geolocation via ip-api.com
- WHOIS lookup with field extraction
- Shodan InternetDB — open ports, CVEs, hostnames, CPEs (no API key required)
- Certificate Transparency log subdomain discovery via crt.sh
- Passive email harvesting
- Historical DNS records via HackerTarget

### Fuzzer
- Parameter discovery via response differential analysis
- Input reflection detection for XSS/injection candidacy
- HTTP method enumeration
- Path traversal fuzzing with signature verification
- Command injection fuzzing — direct output and time-based blind
- HTTP header injection — CRLF via User-Agent, Referer, X-Forwarded-For
- Server-Side Template Injection — Jinja2, FreeMarker, Twig, Smarty, ERB payloads

### Other Modules
- Wireless — interface detection, network scan (encryption, auth), WPS detection
- ICS/SCADA — Modbus TCP probe, Siemens S7 ISO-TSAP probe, BACnet UDP/TCP probe
- Mobile — ADB device detection, debug mode check, root access check, storage encryption check
- Passive — DNS resolution and PTR, banner grab without active exploitation

---

## Installation

### Requirements

- Python 3.8 or higher
- Linux (Kali Linux recommended)
- `pip` package manager
- Root / sudo for SYN scans and raw socket operations

### Clone and Install

```bash
git clone https://github.com/S1r1us-xD/PhantomEye.git
cd PhantomEye
pip install -e . --break-system-packages
```

### Manual Launcher (if `pe` entry point fails)

```bash
cat > /usr/local/bin/pe << 'EOF'
#!/usr/bin/env python3
import sys, os
sys.path.insert(0, "/path/to/PhantomEye")
from phantomeye import main
main()
EOF

chmod +x /usr/local/bin/pe
```

Replace `/path/to/PhantomEye` with your actual installation path.

### Optional System Dependencies

These extend functionality when available:

```bash
sudo apt install -y \
  arp-scan smbclient enum4linux \
  snmp snmp-mibs-downloader \
  whois traceroute \
  aircrack-ng reaver \
  openscap-scanner aide auditd
```

---

## Usage

### Basic Syntax

```
pe -t <TARGET> [OPTIONS]
phantomeye -t <TARGET> [OPTIONS]
```

`TARGET` can be an IP address, hostname, URL, or CIDR range.

### Quick Examples

```bash
# Default scan against an IP
pe -t 192.168.1.1

# Web application scan with HTML report
pe -t http://example.com --profile web -o report.html --format html

# Full deep scan with all modules
sudo pe -t 192.168.1.1 --profile deep --scan-type syn --all-ports \
  --web --network --ssl --database --api --fuzz \
  --osint --cloud --container --compliance --advanced \
  --threads 150 --timeout 5 \
  -o ~/Desktop/full_report.html --format html -v

# Stealth scan (slow, low noise, minimal footprint)
sudo pe -t 192.168.1.1 --profile stealth --scan-type fin

# SYN stealth scan
sudo pe -t 192.168.1.1 --scan-type syn --all-ports

# Idle/zombie scan
sudo pe -t 192.168.1.1 --scan-type idle --zombie 192.168.1.5

# CIDR range network sweep
pe -t 10.0.0.0/24 --network --quick --threads 200

# OSINT collection only (no active probes)
pe -t example.com --profile osint

# PCI DSS compliance scan
pe -t 192.168.1.1 --profile pci -o pci_report.json

# API security assessment
pe -t https://api.example.com --api --ssl --fuzz -v

# Cloud infrastructure scan
pe -t example.com --cloud --container -v

# Database-focused scan
pe -t 192.168.1.1 --database --network -v

# Save XML report
pe -t 192.168.1.1 --full -o results.xml --format xml
```

---

## Scan Profiles

| Profile      | Description                                    | Threads | Port Range  |
|--------------|------------------------------------------------|---------|-------------|
| `quick`      | Fast top-1024 scan + basic web headers         | 150     | 1–1024      |
| `default`    | Balanced — ports, services, web, SSL           | 100     | Top ports   |
| `deep`       | All modules, all ports, extended payloads      | 100     | 1–65535     |
| `stealth`    | Low-noise — FIN/NULL scan, passive only        | 5       | Top ports   |
| `aggressive` | Max threads, all ports, all payloads           | 200     | 1–65535     |
| `web`        | Full web application assessment                | 50      | Web ports   |
| `network`    | Full network assessment                        | 200     | 1–65535     |
| `api`        | REST/GraphQL API security assessment           | 30      | Web ports   |
| `pci`        | PCI DSS compliance scan                        | 50      | Top ports   |
| `scap`       | SCAP / CIS benchmark audit                     | 10      | —           |
| `cloud`      | Cloud infrastructure scan                      | 50      | Cloud ports |
| `container`  | Docker / Kubernetes security scan              | 30      | Top ports   |
| `osint`      | Passive OSINT only — no active probes          | 10      | —           |
| `internal`   | Internal network credentialed scan             | 100     | 1–65535     |
| `external`   | External attack surface scan                   | 80      | Top ports   |

---

## Scan Types

| Type      | Description                              | Root Required |
|-----------|------------------------------------------|:-------------:|
| `tcp`     | TCP Connect scan (default)               | No            |
| `syn`     | SYN Stealth scan                         | Yes           |
| `udp`     | UDP scan                                 | No            |
| `fin`     | FIN scan                                 | Yes           |
| `null`    | NULL scan                                | Yes           |
| `xmas`    | Xmas scan — FIN + PSH + URG flags        | Yes           |
| `ack`     | ACK scan — firewall rule mapping         | Yes           |
| `window`  | Window scan                              | Yes           |
| `maimon`  | Maimon scan — FIN + ACK flags            | Yes           |
| `idle`    | Idle/Zombie scan — requires `--zombie`   | Yes           |

---

## Output Formats

| Format | Description                                        |
|--------|----------------------------------------------------|
| `json` | Structured JSON with metadata, summary, findings   |
| `html` | Dark-themed interactive HTML report (browser-ready)|
| `xml`  | Indented XML with summary and all finding fields   |

The HTML report includes a severity breakdown bar, color-coded findings table, target metadata, profile used, and full scan timestamp. Open it in any browser.

---

## All Flags & Options

```
Target:
  -t, --target TARGET       IP, hostname, URL, or CIDR range (required)

Scan Profile:
  --profile PROFILE         Scan profile (default: default)

Modules:
  --network                 Run network scan modules
  --web                     Run web application modules
  --host                    Run host audit modules
  --database                Run database scan modules
  --ssl                     Run SSL/TLS scan
  --cloud                   Run cloud security scan
  --container               Run container security scan
  --compliance              Run compliance checks (PCI/CIS/OWASP)
  --wireless                Run wireless scan
  --passive                 Run passive scan only
  --osint                   Run OSINT collection
  --fuzz                    Run HTTP fuzzer
  --api                     Run API security scan
  --mobile                  Run mobile/ADB checks
  --ics                     Run ICS/SCADA checks
  --full                    Enable all modules

Scan Options:
  --scan-type TYPE          tcp|syn|udp|fin|null|xmas|ack|window|maimon|idle
  --quick                   Top 1024 ports only
  --all-ports               Scan all 65535 ports
  --zombie HOST             Zombie host for idle scan
  --advanced                Advanced network checks (SMB, DNS, SNMP, SCTP)
  --threads N               Thread count (default: 100)
  --timeout SEC             Socket timeout in seconds (default: 5)
  --rate N                  Max requests/sec (default: 150)
  --wordlist FILE           Custom wordlist for directory brute-force
  --user USER               Username for credentialed scans
  --password PASS           Password for credentialed scans
  --cookies STR             Cookies for authenticated web scan

Output:
  -o, --output FILE         Save report to file
  --format FMT              json | html | xml (default: json)
  -v, --verbose             Verbose / debug output
  --no-color                Disable ANSI color output
  --log FILE                Write output to log file
  --version                 Show version and exit
```

---

## Severity Levels

| Level      | Meaning                                           |
|------------|---------------------------------------------------|
| `CRITICAL` | Direct exploitation possible — immediate action   |
| `HIGH`     | Significant risk — prompt remediation required    |
| `MEDIUM`   | Moderate risk — should be addressed               |
| `LOW`      | Minor risk or informational concern               |
| `INFO`     | Informational — no direct security risk           |

---

## Project Structure

```
PhantomEye/
├── phantomeye.py               Entry point
├── cli.py                      Argument parser
├── setup.py
├── requirements.txt
│
├── core/
│   ├── scanner.py              Main orchestrator — routes to all modules
│   ├── engine.py               Banner, footer, profile mapping
│   ├── context.py              Shared runtime state (thread-safe)
│   ├── dispatcher.py           Parallel and sequential task routing
│   ├── plugin_loader.py        Dynamic module registry
│   ├── exceptions.py           Custom exception classes
│   └── utils.py                Logger, Colors, Validator, OutputFormatter
│
├── config/
│   ├── settings.py             All constants, payloads, ports, CVE signatures
│   ├── profiles.py             Scan profile definitions
│   ├── wordlists.py            Wordlist loader with system path detection
│   └── signatures.py          CMS, service, tech, disclosure fingerprints
│
├── modules/
│   ├── network/                port_scan, host_discovery, service_detection,
│   │                           os_detect, dns_scan, smb_scan, snmp_scan,
│   │                           vuln_nse, advanced_net
│   ├── web/                    web_scanner, dir_scan, vuln_scan, api_scan,
│   │                           cgi_scan, info_disclosure, traversal_scan,
│   │                           methods_scan, outdated_scan, server_scan
│   ├── host/                   host_audit, patch_scan, config_audit,
│   │                           malware_scan, credentialed, uncredentialed
│   ├── database/               db_scan
│   ├── ssl/                    ssl_scan
│   ├── cloud/                  cloud_scan, aws_scan, azure_scan, gcp_scan
│   ├── container/              container_scan, docker_scan, kube_scan
│   ├── compliance/             compliance_scan, pci_scan, scap_scan, cis_scan
│   ├── wireless/               wireless_scan
│   ├── passive/                passive_scan
│   ├── mobile/                 mobile_scan
│   ├── ics/                    ics_scan
│   ├── osint/                  osint
│   └── fuzzer/                 fuzzer
│
├── reports/
│   ├── report_engine.py        Routes to correct format handler
│   ├── cli_report.py           Coloured terminal findings summary
│   ├── html_report.py          Dark-themed browser report
│   ├── json_report.py          JSON report
│   ├── xml_report.py           XML report
│   └── output/                 Default report output directory
│
├── data/
│   ├── wordlists/              Custom wordlist storage
│   ├── payloads/               Custom payload storage
│   └── fingerprints/           Custom fingerprint storage
│
└── tests/
    ├── test_engine.py          Context and engine unit tests
    ├── test_network.py         Validator, logger, formatter tests
    ├── test_web.py             Web scanner and vuln scan tests
    └── test_reports.py         JSON, XML, HTML, CLI report tests
```

---

## Running Tests

```bash
cd PhantomEye
python3 -m unittest discover tests/ -v
```

Expected output: **49 tests, 0 failures, 0 errors**

---

## Practice Targets (Legal)

The following are intentionally vulnerable systems built specifically for security testing practice:

| System              | Type            | Where to get it                                  |
|---------------------|-----------------|--------------------------------------------------|
| Metasploitable 2    | VM image        | sourceforge.net/projects/metasploitable          |
| DVWA                | Web app         | github.com/digininja/DVWA                        |
| OWASP WebGoat       | Web app         | github.com/WebGoat/WebGoat                       |
| VulnHub machines    | VM images       | vulnhub.com                                      |
| HackTheBox          | Online lab      | hackthebox.com (VPN required)                    |
| TryHackMe           | Online lab      | tryhackme.com (VPN required)                     |

**Recommended scan against Metasploitable 2:**

```bash
sudo pe -t <metasploitable_ip> \
  --profile deep \
  --scan-type syn \
  --all-ports \
  --web --network --ssl \
  --database --compliance \
  --advanced --fuzz \
  --threads 100 --timeout 5 \
  -o ~/Desktop/metasploitable_report.html \
  --format html -v
```

This will generate 50–100+ findings covering open services, default credentials, web vulnerabilities, misconfigurations, and compliance violations.

---

## Legal Disclaimer

PhantomEye is developed for **authorised security assessment and educational purposes only**.

- Only use this tool against systems you own or have **explicit written permission** to test
- Unauthorised scanning, probing, or exploitation is illegal under computer fraud laws in most jurisdictions
- The author (`S1r1us`) assumes **no liability** for any misuse, damage, or legal consequences arising from use of this 
- Always obtain written authorisation before conducting any security assessment on systems you do not own

---

## Author

**S1r1us**

> *"Know your attack surface before your adversary does."*
