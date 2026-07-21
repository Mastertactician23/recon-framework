# Automated Reconnaissance Framework

### A Python-based recon framework that automates the full intelligence-gathering phase of a penetration test — covering DNS, subdomain enumeration, port scanning, web technology detection, security header analysis, sensitive path discovery, and SSL/TLS analysis — producing a scored HTML target profile

**Author:** Kofi Asibey-Kitiabi
**GitHub:** [Mastertactician23](https://github.com/Mastertactician23/)
**LinkedIn:** [asibey-kitiabi](https://www.linkedin.com/in/asibey-kitiabi/)
**Date:** July 2026
**Status:** Completed
**Difficulty:** Intermediate–Advanced
**WARNING:** Only scan targets you have explicit written permission to test.

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Modules](#2-modules)
3. [Tools & Technologies](#3-tools--technologies)
4. [How to Run It](#4-how-to-run-it)
5. [Scan Results](#5-scan-results)
6. [Scoring Engine](#6-scoring-engine)
7. [HTML Report](#7-html-report)
8. [MITRE ATT&CK Mapping](#8-mitre-attck-mapping)
9. [Connection to Portfolio](#9-connection-to-portfolio)
10. [Skills Demonstrated](#10-skills-demonstrated)
11. [Legal & Ethical Use](#11-legal--ethical-use)
12. [Known Limitations](#12-known-limitations)
13. [What I Would Do Differently](#13-what-i-would-do-differently)
14. [Next Steps](#14-next-steps)

---

## 1. Project Overview

Reconnaissance is the first and most critical phase of any penetration test or bug bounty engagement. Before exploiting anything, an attacker (or ethical hacker) maps the target's attack surface — what domains exist, what ports are open, what software is running, what files are exposed, what headers are missing.

This framework automates that entire process in a single Python script with 7 parallel modules, a risk scoring engine, and a professional HTML report — the same output a junior pentester would produce at the start of an engagement.

**Why build this instead of just running Nmap:**
- Nmap scans ports. This framework does ports + DNS + subdomains + web tech + headers + path discovery + SSL in one run
- The risk scoring engine gives a quantified attack surface assessment — not just raw data
- The HTML report is presentation-ready — exactly what you would hand to a client or include in a bug bounty submission
- Results were validated against 5 real and local targets with meaningfully different findings per target

---

## 2. Modules

### Module 1 — DNS Resolution & IP Information
Resolves A records, performs reverse DNS lookups, and queries NS, MX, and TXT records using `dig`. Reveals hosting infrastructure, mail servers, and SPF/DKIM configuration. Correctly handles IP targets, domain targets, and `hostname:port` format.

### Module 2 — Subdomain Enumeration
Checks 97 common subdomain prefixes against the target domain using concurrent DNS resolution (50 threads). Discovers staging environments, admin panels, API endpoints, and internal tools. Automatically skips when the target is an IP address.

### Module 3 — Port Scanning
Scans 28 top ports using concurrent socket connections (100 threads). Fingerprints services and flags risky ports (Redis, MongoDB, Elasticsearch, RDP, VNC, database ports) with specific risk notes. Correctly resolves `hostname:port` targets by stripping the port suffix before DNS resolution.

### Module 4 — Web Technology Detection
Identifies server software, frameworks, CMS platforms, and runtime environments from HTTP response headers and body signatures. Detects WordPress, Drupal, Django, Laravel, React, Vue, Angular, Shopify, and 10+ others. Analyses session cookie security flags.

### Module 5 — HTTP Security Header Analysis
Checks for 7 recommended security headers and scores the result as a percentage. Flags information-leaking headers (Server, X-Powered-By, X-AspNet-Version) that reveal stack details to attackers.

### Module 6 — Interesting Path Discovery
Probes 34 paths for sensitive files and endpoints: `.git/HEAD`, `.env`, `phpinfo.php`, `/swagger`, `/admin`, `/api/v1`, backup files, config files, GraphQL endpoints, and legacy routes. Uses concurrent requests (20 threads).

### Module 7 — SSL/TLS Certificate Analysis
Checks certificate validity, subject/issuer details, and tests for deprecated protocol support (SSLv2, SSLv3, TLS 1.0, TLS 1.1) using OpenSSL. Only flags as vulnerable when the handshake genuinely succeeds — correctly rejects false positives from targets without port 443 open.

---

## 3. Tools & Technologies

| Tool | Purpose |
|------|---------|
| Python 3 | Main scripting language |
| socket | DNS resolution and port scanning |
| concurrent.futures | Thread pool for parallel scanning (50–100 threads) |
| subprocess | dig (DNS queries) and openssl (SSL testing) |
| requests | HTTP requests for web modules |
| colorama | Colour-coded terminal output |
| HTML/CSS | Self-contained report generation (no framework) |
| Docker | Lab environment for local targets |
| Kali Linux 2026.2 | Execution environment |

**No heavy dependencies.** Everything uses Python stdlib except `requests` and `colorama`.

---

## 4. How to Run It

**Install dependencies:**
```bash
pip install requests colorama --break-system-packages
```

**Run against a domain:**
```bash
python3 recon.py --target scanme.nmap.org
```

**Run against a Docker container (hostname:port format):**
```bash
python3 recon.py --target dvwa:80
python3 recon.py --target juiceshop:3000
```

**Run against an IP:**
```bash
python3 recon.py --target 172.18.0.2
```

**Output saved to:**
```
reports/recon_<target>_<timestamp>.json   — full structured data
reports/recon_<target>_<timestamp>.html   — HTML report (open in browser)
```

---

## 5. Scan Results

Five targets were scanned to validate the framework across different environments, tech stacks, and exposure levels.

---

### Target 1 — scanme.nmap.org (authorised public internet target)

```
Duration        : 25.2s
Open ports      : 3 (21/FTP, 22/SSH, 80/HTTP)
Risky ports     : 1 (FTP — check for anonymous login)
Missing headers : 7 (0% header score)
Sensitive paths : 1 (/.htaccess — 403)
Info leak       : Server: Apache/2.4.7 (Ubuntu)
Issues found    : 14
Security Score  : 0/100
Risk Rating     : CRITICAL
```

Key findings: Apache version and OS revealed in Server header. FTP open on a public-facing server. Zero security headers present. `.htaccess` file accessible (returns 403 — confirmed to exist). This is the Nmap project's authorised test server — explicitly provided for security testing.

---

### Target 2 — OWASP Juice Shop (juiceshop:3000) — fintech-style e-commerce app

```
Duration        : 1.2s
Open ports      : 0 (not in top 28 — runs on 3000)
Missing headers : 5 (missing HSTS, CSP, XSS-Protection, Referrer-Policy, Permissions-Policy)
Present headers : 2 (X-Frame-Options, X-Content-Type-Options)
Sensitive paths : 14
Issues found    : 23
Security Score  : 0/100
Risk Rating     : CRITICAL
```

Sensitive paths discovered:
- `/.git/HEAD` — source code repository exposed
- `/.env` — environment variables file accessible
- `/Dockerfile` and `/docker-compose.yml` — infrastructure configuration exposed
- `/backup.zip`, `/backup.sql`, `/dump.sql`, `/db.sql` — backup files accessible
- `/package.json` — dependency list exposed (reveals versions for CVE matching)
- `/web.config` — Windows web server configuration exposed
- `/.travis.yml` — CI/CD configuration exposed
- `/admin` and `/administrator` — admin panels discovered
- `/swagger`, `/swagger.json`, `/openapi.json` — API documentation exposed
- `/graphql` and `/graphiql` — GraphQL endpoints live

Juice Shop is the most realistic fintech-style target — it simulates an e-commerce platform with user accounts, payment flows, JWT authentication, and a full REST API. 14 sensitive path findings in 1.2 seconds.

---

### Target 3 — DVWA (dvwa:80) — Damn Vulnerable Web Application

```
Duration        : 1.0s
Open ports      : 1 (80/HTTP)
Missing headers : 7 (0% header score)
Sensitive paths : 2 (phpinfo.php, .htaccess)
Info leak       : Server: Apache/2.4.25 (Debian)
Issues found    : 10
Security Score  : 32/100
Risk Rating     : HIGH
```

Reverse DNS correctly resolved `dvwa` → `172.18.0.3` → `dvwa.soc-lab`. phpinfo.php returns a 302 redirect (confirmed to exist). Apache version and OS leaked in Server header. All 7 security headers missing.

---

### Target 4 — Custom Vulnerable API (localhost:8080)

```
Duration        : 0.5s
Sensitive paths : 1 (/swagger — 200)
Issues found    : 4 (SSL false positive test — no SSL on this target)
Security Score  : 60/100
Risk Rating     : MEDIUM
```

Swagger documentation endpoint discovered — exposes the full API structure to unauthenticated users. This target was built in Project 5 (API Security Scanner) and the recon framework correctly identifies it as the entry point before deeper API testing begins.

---

### Target 5 — testphp.vulnweb.com (Acunetix authorised test target)

```
Duration        : 54.6s
Open ports      : 1 (21/FTP — risky)
Issues found    : 1
Security Score  : 92/100
Risk Rating     : LOW
```

Minimal external exposure — the web server is not reachable from the scan host's IP range but FTP is exposed externally. Demonstrates the framework correctly handles partial connectivity and produces conservative, accurate findings rather than false positives.

---

### Results comparison table

| Target | Score | Risk | Key finding |
|--------|-------|------|-------------|
| scanme.nmap.org | 0/100 | CRITICAL | FTP open, 7 missing headers, server version leaked |
| Juice Shop | 0/100 | CRITICAL | 14 sensitive paths including .git, .env, backups |
| DVWA | 32/100 | HIGH | phpinfo.php, .htaccess, 7 missing headers |
| Vulnerable API | 60/100 | MEDIUM | Swagger endpoint exposed |
| testphp.vulnweb.com | 92/100 | LOW | FTP risky port |

Same tool, five targets, five meaningfully different result profiles — demonstrating the framework correctly distinguishes attack surface rather than generating uniform noise.

---

## 6. Scoring Engine

The scoring engine starts at 100 and deducts points based on confirmed findings:

| Finding | Deduction |
|---------|-----------|
| Each risky port open (Redis, MongoDB, RDP, FTP, etc.) | -8 points |
| Each missing security header | -5 points |
| Each information-leaking header | -3 points |
| Each sensitive path exposed (.git, .env, backups, etc.) | -15 points |
| Each weak SSL/TLS protocol confirmed accepted | -10 points |
| Invalid or expired SSL certificate | -10 points |

**Risk ratings:**

| Score | Rating |
|-------|--------|
| 70–100 | LOW |
| 50–69 | MEDIUM |
| 30–49 | HIGH |
| 0–29 | CRITICAL |

---

## 7. HTML Report

The scanner generates a self-contained HTML report that opens in any browser:

- Risk rating banner with colour-coded score gauge
- Summary stats: subdomains, open ports, risky ports, missing headers, sensitive paths
- Issues table with severity, detail, and context per finding
- Subdomains table with IP resolution
- Open ports table with service names and risk notes
- Web technology fingerprint
- Security headers: missing (red) and present (green)
- Interesting paths with status codes and response sizes

---

## 8. MITRE ATT&CK Mapping

| Module | Technique | ID |
|--------|-----------|-----|
| DNS Resolution | Gather Victim DNS Info | T1590.002 |
| Subdomain Enumeration | Active Scanning: Wordlist Scanning | T1595.003 |
| Port Scanning | Active Scanning: Scanning IP Blocks | T1595.001 |
| Web Tech Detection | Gather Victim Host Info: Software | T1592.002 |
| Path Discovery | Active Scanning: Vulnerability Scanning | T1595.002 |
| SSL Analysis | Gather Victim Network Info | T1590 |
| Header Analysis | Gather Victim Host Info | T1592 |

All techniques fall under the **Reconnaissance** tactic (TA0043).

---

## 9. Connection to Portfolio

| Project | How it connects |
|---------|----------------|
| [MiniSOC](https://github.com/Mastertactician23/minisoc-threat-detection-lab) | MiniSOC detected the Nmap scan in Kibana — this framework is the attacker-side tool that generates that scan |
| [CIS Auditor](https://github.com/Mastertactician23/linux-cis-hardening-auditor) | CIS Auditor checks OS hardening — this framework maps network and web exposure first |
| [API Scanner](https://github.com/Mastertactician23/api-security-scanner) | Recon maps the attack surface; the API Scanner goes deep on discovered endpoints |
| [Security Dashboard](https://github.com/Mastertactician23/minisoc-security-dashboard) | Recon JSON reports could feed the dashboard as a new data source |

**The complete red team kill chain across the portfolio:**
```
Recon (this project) → API Scanning → Exploit → Detect → Block → Audit → Visualise
```

---

## 10. Skills Demonstrated

- Python 3 (concurrent.futures, socket, subprocess, requests)
- Multi-threaded network scanning (50–100 thread pools)
- DNS querying and record analysis
- Subdomain enumeration methodology
- Service fingerprinting and banner grabbing
- Web technology detection via headers and body analysis
- Security header analysis and scoring
- Sensitive file and path discovery
- SSL/TLS protocol weakness testing with false positive mitigation
- Risk scoring algorithm design
- HTML report generation without frameworks
- Penetration testing methodology (recon phase)
- Target input normalisation (hostname, IP, hostname:port, URL)

---

## 11. Legal & Ethical Use

**Only scan targets you have explicit written permission to test.**

This framework performs active scanning — it sends network requests to the target. Scanning systems without permission is illegal under Kenya's Computer Misuse and Cybercrimes Act 2018 and equivalent legislation in most jurisdictions.

**Authorised targets used in this project:**
- Local Docker lab containers (`dvwa`, `juiceshop`, `localhost:8080`, `172.18.0.2`) — owned lab environment
- `scanme.nmap.org` — explicitly authorised by the Nmap project for security testing
- `testphp.vulnweb.com` — Acunetix's authorised test target

---

## 12. Known Limitations

**Port scanner on non-standard ports:** The top-28 port list does not include 3000 (Juice Shop), 8080 (custom API), or other application-specific ports. Juice Shop and the custom API showed 0 open ports in the scanner despite being reachable — the web and path modules still function correctly via direct URL construction. A future `--ports` argument would allow custom port ranges.

**Subdomain enumeration scope:** The 97-word wordlist covers common prefixes but will not find custom or randomly named subdomains. Real engagements use larger wordlists (SecLists) and passive enumeration via certificate transparency logs.

**SSL weak protocol detection:** The framework correctly identifies when OpenSSL rejects weak protocols (SSLv2, SSLv3, TLS 1.0/1.1) and avoids false positives on targets without port 443 open.

---

## 13. What I Would Do Differently

- Add `--ports` flag for custom port ranges to catch non-standard application ports
- Integrate certificate transparency log lookups for passive subdomain discovery
- Add WHOIS and Shodan integration for passive recon without touching the target
- Add CVE matching for identified software versions
- Add screenshot capture of discovered web paths using headless Chrome
- Export findings directly into a structured pentest report template

---

## 14. Next Steps

- [ ] Add custom port range support
- [ ] Add certificate transparency subdomain discovery
- [ ] Add CVE version matching for identified services
- [ ] Sit CompTIA Security+ SY0-701
- [ ] Begin applying for remote penetration testing and SOC Analyst roles

---

*Built on: Kali Linux 2026.2 inside Docker Desktop (WSL2)*
*Authorised test targets: local Docker lab, scanme.nmap.org, testphp.vulnweb.com*
*Purpose: Educational portfolio project — authorised targets only*
*Part of an active cybersecurity portfolio: [github.com/Mastertactician23](https://github.com/Mastertactician23)*
