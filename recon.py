#!/usr/bin/env python3
"""
Automated Reconnaissance Framework
Author: Kofi Asibey-Kitiabi
Description: Automates the full recon phase of a penetration test or bug bounty
             engagement. Covers subdomain enumeration, port scanning, service
             fingerprinting, web technology detection, and HTTP security header
             analysis. Produces a scored target profile in terminal and HTML format.
GitHub: https://github.com/Mastertactician23/recon-framework
WARNING: Only scan targets you have explicit permission to test.
"""

import subprocess
import requests
import socket
import json
import os
import sys
import argparse
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOUR = True
except ImportError:
    COLOUR = False

# ──────────────────────────────────────────────
# COLOUR HELPERS
# ──────────────────────────────────────────────

def red(t):     return Fore.RED + t + Style.RESET_ALL if COLOUR else t
def green(t):   return Fore.GREEN + t + Style.RESET_ALL if COLOUR else t
def yellow(t):  return Fore.YELLOW + t + Style.RESET_ALL if COLOUR else t
def cyan(t):    return Fore.CYAN + t + Style.RESET_ALL if COLOUR else t
def magenta(t): return Fore.MAGENTA + t + Style.RESET_ALL if COLOUR else t
def bold(t):    return Style.BRIGHT + t + Style.RESET_ALL if COLOUR else t


# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────

# Common subdomain wordlist
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "portal", "login", "secure", "vpn", "remote", "app", "mobile",
    "beta", "old", "new", "shop", "store", "blog", "wiki", "docs",
    "cdn", "static", "assets", "img", "images", "media", "upload",
    "download", "files", "backup", "db", "database", "mysql", "redis",
    "mongo", "elastic", "kibana", "grafana", "jenkins", "jira",
    "confluence", "git", "gitlab", "github", "svn", "deploy",
    "prod", "production", "preprod", "uat", "qa", "sandbox",
    "internal", "intranet", "extranet", "corp", "corporate",
    "ns1", "ns2", "mx", "smtp", "imap", "pop", "webmail",
    "m", "mobile", "wap", "w", "web", "www2", "www3",
    "support", "help", "helpdesk", "ticket", "crm", "erp",
    "payment", "pay", "checkout", "cart", "order", "billing",
    "account", "accounts", "auth", "sso", "oauth", "id",
    "monitor", "monitoring", "status", "health", "metrics",
]

# Top ports to scan
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 8888, 9200, 9300, 27017
]

# Interesting HTTP paths to probe
INTERESTING_PATHS = [
    "/robots.txt", "/.well-known/security.txt", "/sitemap.xml",
    "/admin", "/admin/", "/administrator", "/login", "/wp-login.php",
    "/.git/HEAD", "/.env", "/config.php", "/phpinfo.php",
    "/api", "/api/v1", "/api/v2", "/swagger", "/swagger.json",
    "/openapi.json", "/graphql", "/graphiql", "/.htaccess",
    "/backup.zip", "/backup.sql", "/dump.sql", "/db.sql",
    "/server-status", "/server-info", "/.travis.yml",
    "/Dockerfile", "/docker-compose.yml", "/package.json",
    "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
]

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS — prevents SSL stripping",
    "Content-Security-Policy": "Prevents XSS and injection attacks",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "X-XSS-Protection": "Legacy XSS filter",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Controls browser feature access",
}

# Information-leaking headers
LEAKY_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache",
    "X-WordPress-Cache", "X-Pingback", "X-Runtime",
    "X-Version", "X-Application-Context"
]


# ──────────────────────────────────────────────
# MODULE 1 — DNS RESOLUTION & IP INFO
# ──────────────────────────────────────────────

def module_dns(target):
    print(bold(cyan("\n[MODULE 1] DNS Resolution & IP Information")))
    results = {"module": "dns", "findings": [], "ips": [], "cname": []}

    # Strip protocol and port from target
    target = target.replace("http://", "").replace("https://", "").split("/")[0]
    if ":" in target:
        target = target.split(":")[0]

    # Resolve A record
    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        unique_ips = list(set(ip[4][0] for ip in ips))
        results["ips"] = unique_ips
        for ip in unique_ips:
            print(green(f"  [+] {target} resolves to {ip}"))
            results["findings"].append({"type": "A_RECORD", "value": ip})
    except socket.gaierror:
        print(red(f"  [!] Cannot resolve {target}"))
        results["findings"].append({"type": "DNS_FAIL", "value": target})
        return results

    # Reverse DNS
    for ip in unique_ips[:3]:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(yellow(f"  [i] Reverse DNS: {ip} → {hostname}"))
            results["findings"].append({"type": "REVERSE_DNS", "value": f"{ip} → {hostname}"})
        except Exception:
            pass

    # Try to get nameservers via dig/nslookup
    for record_type in ["NS", "MX", "TXT"]:
        try:
            result = subprocess.run(
                ["dig", "+short", record_type, target],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                records = result.stdout.strip().split("\n")
                for r in records[:3]:
                    if r.strip():
                        print(yellow(f"  [i] {record_type}: {r.strip()}"))
                        results["findings"].append({"type": record_type, "value": r.strip()})
        except Exception:
            pass

    return results


# ──────────────────────────────────────────────
# MODULE 2 — SUBDOMAIN ENUMERATION
# ──────────────────────────────────────────────

def check_subdomain(sub, domain):
    hostname = f"{sub}.{domain}"
    try:
        socket.setdefaulttimeout(2)
        ips = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ip = list(set(addr[4][0] for addr in ips))[0]
        return {"subdomain": hostname, "ip": ip, "status": "resolved"}
    except Exception:
        return None


def module_subdomains(target):
    print(bold(cyan("\n[MODULE 2] Subdomain Enumeration")))
    results = {"module": "subdomains", "found": [], "total_checked": 0}

    # Strip protocol and port if present
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    if ":" in domain:
        domain = domain.split(":")[0]
    # If it's an IP address, skip
    try:
        socket.inet_aton(domain)
        print(yellow("  [i] Target is an IP address — skipping subdomain enumeration"))
        return results
    except socket.error:
        pass

    print(f"  [*] Checking {len(SUBDOMAIN_WORDLIST)} subdomains for {domain}...")
    results["total_checked"] = len(SUBDOMAIN_WORDLIST)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(check_subdomain, sub, domain): sub
            for sub in SUBDOMAIN_WORDLIST
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results["found"].append(result)
                print(green(f"  [+] Found: {result['subdomain']} → {result['ip']}"))

    if not results["found"]:
        print(yellow(f"  [i] No subdomains resolved (checked {len(SUBDOMAIN_WORDLIST)})"))
    else:
        print(green(f"  [+] Total subdomains found: {len(results['found'])}"))

    return results


# ──────────────────────────────────────────────
# MODULE 3 — PORT SCANNING
# ──────────────────────────────────────────────

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def grab_banner(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()
        return banner[:200]
    except Exception:
        return ""


SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Dev", 9200: "Elasticsearch",
    9300: "Elasticsearch-Transport", 27017: "MongoDB"
}

RISKY_PORTS = {
    21: "FTP — check for anonymous login",
    23: "Telnet — plaintext protocol, highly insecure",
    3389: "RDP — common ransomware entry point",
    5900: "VNC — often has weak/no authentication",
    6379: "Redis — often exposed with no auth",
    9200: "Elasticsearch — often exposed with no auth",
    27017: "MongoDB — often exposed with no auth",
    1433: "MSSQL — database directly exposed",
    5432: "PostgreSQL — database directly exposed",
    3306: "MySQL — database directly exposed",
}


def module_ports(target):
    print(bold(cyan("\n[MODULE 3] Port Scanning")))
    results = {"module": "ports", "open_ports": [], "risky_ports": []}

    # Resolve to IP — strip protocol, path, and port suffix from hostname
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    # Handle hostname:port format — extract just the hostname
    if ":" in domain:
        domain = domain.split(":")[0]
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = domain
    print(f"  [*] Scanning {ip} ({len(TOP_PORTS)} ports)...")

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in TOP_PORTS}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)

    open_ports.sort()

    for port in open_ports:
        service = SERVICE_NAMES.get(port, "Unknown")
        risk_note = RISKY_PORTS.get(port, "")
        entry = {
            "port": port,
            "service": service,
            "risk_note": risk_note,
            "banner": ""
        }

        if risk_note:
            print(red(f"  [!] {port}/tcp OPEN  {service} — {risk_note}"))
            results["risky_ports"].append(entry)
        else:
            print(green(f"  [+] {port}/tcp OPEN  {service}"))

        results["open_ports"].append(entry)

    if not open_ports:
        print(yellow("  [i] No open ports found in top port list"))

    print(f"  [*] Open ports: {len(open_ports)} / {len(TOP_PORTS)} scanned")
    return results


# ──────────────────────────────────────────────
# MODULE 4 — WEB TECHNOLOGY DETECTION
# ──────────────────────────────────────────────

def module_web_tech(target):
    print(bold(cyan("\n[MODULE 4] Web Technology Detection")))
    results = {"module": "web_tech", "technologies": [], "server": "", "cms": ""}

    # Build correct URLs — handle hostname:port, plain hostname, and full URLs
    if target.startswith("http"):
        urls = [target]
    elif ":" in target and not target.startswith("http"):
        # hostname:port format
        host, port = target.split(":", 1)
        scheme = "https" if port == "443" else "http"
        urls = [f"{scheme}://{host}:{port}"]
    else:
        urls = [f"https://{target}", f"http://{target}"]

    resp = None
    for url in urls:
        try:
            resp = requests.get(url, timeout=8, verify=False,
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
            break
        except Exception:
            continue

    if not resp:
        print(yellow("  [i] Could not reach web server"))
        return results

    # Server header
    server = resp.headers.get("Server", "")
    if server:
        results["server"] = server
        print(yellow(f"  [i] Server: {server}"))
        results["technologies"].append({"name": "Server", "value": server})

    # Technology fingerprinting from headers
    tech_headers = {
        "X-Powered-By": "Runtime/Framework",
        "X-AspNet-Version": "ASP.NET",
        "X-Generator": "Generator",
        "X-Drupal-Cache": "Drupal CMS",
        "X-WordPress-Cache": "WordPress",
        "X-Shopify-Stage": "Shopify",
    }
    for header, tech in tech_headers.items():
        val = resp.headers.get(header, "")
        if val:
            print(yellow(f"  [i] {tech}: {val}"))
            results["technologies"].append({"name": tech, "value": val})

    # CMS detection from response body
    body = resp.text.lower()
    cms_signatures = {
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "Drupal": ["drupal.js", "drupal.min.js", "sites/default/files"],
        "Joomla": ["joomla", "/components/com_"],
        "Magento": ["mage/cookies.js", "varien/js.js", "magento"],
        "Shopify": ["shopify", "cdn.shopify.com"],
        "Django": ["csrfmiddlewaretoken", "__admin__"],
        "Laravel": ["laravel_session", "x-livewire"],
        "Ruby on Rails": ["authenticity_token", "rails-ujs"],
        "React": ["react-root", "__react", "next/router"],
        "Vue.js": ["__vue__", "vue-router"],
        "Angular": ["ng-version", "angular"],
    }
    for cms, signatures in cms_signatures.items():
        if any(sig in body for sig in signatures):
            print(green(f"  [+] Detected: {cms}"))
            results["technologies"].append({"name": "Framework/CMS", "value": cms})
            results["cms"] = cms

    # Cookie analysis
    for cookie in resp.cookies:
        if cookie.name.lower() in ["phpsessid", "jsessionid", "aspsessionid",
                                    "cfid", "cftoken", "laravel_session"]:
            print(yellow(f"  [i] Session cookie detected: {cookie.name}"))
            sec = "Secure" if cookie.secure else "NOT Secure"
            http_only = "HttpOnly" if cookie.has_nonstandard_attr("httponly") else "NOT HttpOnly"
            results["technologies"].append({
                "name": f"Cookie: {cookie.name}",
                "value": f"{sec}, {http_only}"
            })

    return results


# ──────────────────────────────────────────────
# MODULE 5 — HTTP SECURITY HEADERS
# ──────────────────────────────────────────────

def module_headers(target):
    print(bold(cyan("\n[MODULE 5] HTTP Security Header Analysis")))
    results = {
        "module": "headers",
        "missing": [],
        "present": [],
        "leaky": [],
        "score": 0
    }

    if target.startswith("http"):
        urls = [target]
    elif ":" in target and not target.startswith("http"):
        host, port = target.split(":", 1)
        scheme = "https" if port == "443" else "http"
        urls = [f"{scheme}://{host}:{port}"]
    else:
        urls = [f"https://{target}", f"http://{target}"]

    resp = None
    for url in urls:
        try:
            resp = requests.get(url, timeout=8, verify=False,
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0"})
            break
        except Exception:
            continue

    if not resp:
        print(yellow("  [i] Could not reach web server for header check"))
        return results

    # Security headers check
    present_count = 0
    for header, description in SECURITY_HEADERS.items():
        if header in resp.headers:
            val = resp.headers[header]
            print(green(f"  [+] {header}: {val[:60]}"))
            results["present"].append({"header": header, "value": val})
            present_count += 1
        else:
            print(red(f"  [!] MISSING: {header} — {description}"))
            results["missing"].append({"header": header, "description": description})

    results["score"] = int((present_count / len(SECURITY_HEADERS)) * 100)

    # Leaky headers
    for header in LEAKY_HEADERS:
        if header in resp.headers:
            val = resp.headers[header]
            print(yellow(f"  [i] Info leak — {header}: {val}"))
            results["leaky"].append({"header": header, "value": val})

    print(f"  [*] Header score: {results['score']}% ({present_count}/{len(SECURITY_HEADERS)} present)")
    return results


# ──────────────────────────────────────────────
# MODULE 6 — INTERESTING PATH DISCOVERY
# ──────────────────────────────────────────────

def check_path(base_url, path):
    try:
        url = base_url.rstrip("/") + path
        resp = requests.get(url, timeout=5, verify=False,
                            allow_redirects=False,
                            headers={"User-Agent": "Mozilla/5.0"})
        return {
            "path": path,
            "url": url,
            "status": resp.status_code,
            "size": len(resp.content),
            "content_type": resp.headers.get("Content-Type", "")
        }
    except Exception:
        return None


def module_paths(target):
    print(bold(cyan("\n[MODULE 6] Interesting Path Discovery")))
    results = {"module": "paths", "found": [], "sensitive": []}

    if target.startswith("http"):
        base_url = target
    elif ":" in target and not target.startswith("http"):
        host, port = target.split(":", 1)
        scheme = "https" if port == "443" else "http"
        base_url = f"{scheme}://{host}:{port}"
    else:
        base_url = f"http://{target}"

    print(f"  [*] Probing {len(INTERESTING_PATHS)} paths...")

    SENSITIVE_PATHS = [
        "/.git/HEAD", "/.env", "/config.php", "/phpinfo.php",
        "/backup.zip", "/backup.sql", "/dump.sql", "/db.sql",
        "/.htaccess", "/.travis.yml", "/Dockerfile",
        "/docker-compose.yml", "/package.json", "/web.config"
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(check_path, base_url, path): path
            for path in INTERESTING_PATHS
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result and result["status"] in [200, 301, 302, 403]:
                results["found"].append(result)
                is_sensitive = result["path"] in SENSITIVE_PATHS
                if is_sensitive:
                    results["sensitive"].append(result)
                    print(red(f"  [!] SENSITIVE {result['status']} {result['path']} ({result['size']} bytes)"))
                elif result["status"] == 200:
                    print(green(f"  [+] {result['status']} {result['path']} ({result['size']} bytes)"))
                else:
                    print(yellow(f"  [i] {result['status']} {result['path']}"))

    if not results["found"]:
        print(yellow("  [i] No interesting paths found"))
    return results


# ──────────────────────────────────────────────
# MODULE 7 — SSL/TLS ANALYSIS
# ──────────────────────────────────────────────

def module_ssl(target):
    print(bold(cyan("\n[MODULE 7] SSL/TLS Certificate Analysis")))
    results = {"module": "ssl", "findings": [], "cert_info": {}}

    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    if ":" in domain:
        domain = domain.split(":")[0]

    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{domain}:443",
             "-servername", domain],
            input=b"Q\n",
            capture_output=True, timeout=10
        )
        output = result.stderr.decode("utf-8", errors="replace") + \
                 result.stdout.decode("utf-8", errors="replace")

        # Extract cert details
        for line in output.split("\n"):
            if "subject=" in line or "issuer=" in line:
                print(green(f"  [+] {line.strip()}"))
                results["cert_info"][line.split("=")[0].strip()] = line.strip()
                results["findings"].append({"type": "CERT_INFO", "value": line.strip()})
            elif "Verify return code: 0" in line:
                print(green("  [+] Certificate: Valid"))
                results["findings"].append({"type": "CERT_VALID", "value": "Yes"})
            elif "Verify error:" in line:
                print(red(f"  [!] Certificate Error: {line.strip()}"))
                results["findings"].append({"type": "CERT_ERROR", "value": line.strip()})

        # Check for weak protocols
        for protocol in ["ssl2", "ssl3", "tls1", "tls1_1"]:
            try:
                weak_result = subprocess.run(
                    ["openssl", "s_client", f"-{protocol}",
                     "-connect", f"{domain}:443"],
                    input=b"Q\n",
                    capture_output=True, timeout=5
                )
                combined = (weak_result.stderr.decode("utf-8", errors="replace") +
                           weak_result.stdout.decode("utf-8", errors="replace")).lower()
                # Only flag as vulnerable if handshake actually succeeded
                # Modern OpenSSL rejects weak protocols with specific error strings
                rejected_indicators = [
                    "handshake failure",
                    "no protocols available",
                    "unsupported protocol",
                    "unknown option",
                    "ssl routines",
                    "wrong version number",
                    "alert protocol version",
                    "no cipher",
                    "option not supported"
                ]
                was_rejected = any(ind in combined for ind in rejected_indicators)
                was_connected = "cipher" in combined and "verify return code" in combined

                if was_connected and not was_rejected:
                    print(red(f"  [!] Weak protocol accepted: {protocol.upper()}"))
                    results["findings"].append({
                        "type": "WEAK_PROTOCOL",
                        "value": protocol.upper(),
                        "severity": "High"
                    })
                else:
                    print(green(f"  [+] Weak protocol rejected: {protocol.upper()}"))
            except Exception:
                pass

    except FileNotFoundError:
        print(yellow("  [i] openssl not found — install with: apt install openssl"))
    except subprocess.TimeoutExpired:
        print(yellow(f"  [i] SSL check timed out for {domain}:443"))
    except Exception as e:
        print(yellow(f"  [i] SSL check: {str(e)[:80]}"))

    return results


# ──────────────────────────────────────────────
# SCORING ENGINE
# ──────────────────────────────────────────────

def calculate_risk_score(all_results):
    score = 100
    issues = []

    for result in all_results:
        if result["module"] == "ports":
            risky = result.get("risky_ports", [])
            score -= len(risky) * 8
            for p in risky:
                issues.append({"severity": "High", "issue": f"Risky port open: {p['port']}/{p['service']}", "detail": p["risk_note"]})

        elif result["module"] == "subdomains":
            found = len(result.get("found", []))
            if found > 10:
                score -= 5
                issues.append({"severity": "Info", "issue": f"Large attack surface: {found} subdomains discovered"})

        elif result["module"] == "headers":
            missing = len(result.get("missing", []))
            score -= missing * 5
            leaky = result.get("leaky", [])
            score -= len(leaky) * 3
            for h in result.get("missing", []):
                issues.append({"severity": "Medium", "issue": f"Missing security header: {h['header']}", "detail": h["description"]})
            for h in leaky:
                issues.append({"severity": "Low", "issue": f"Information leaking header: {h['header']}", "detail": h["value"]})

        elif result["module"] == "paths":
            sensitive = result.get("sensitive", [])
            score -= len(sensitive) * 15
            for p in sensitive:
                issues.append({"severity": "Critical", "issue": f"Sensitive file exposed: {p['path']}", "detail": f"HTTP {p['status']}, {p['size']} bytes"})

        elif result["module"] == "ssl":
            weak = [f for f in result.get("findings", []) if f.get("type") == "WEAK_PROTOCOL"]
            score -= len(weak) * 10
            errors = [f for f in result.get("findings", []) if f.get("type") == "CERT_ERROR"]
            score -= len(errors) * 10
            for w in weak:
                issues.append({"severity": "High", "issue": f"Weak SSL/TLS protocol: {w['value']}"})

    score = max(0, min(100, score))
    risk = "CRITICAL" if score < 30 else "HIGH" if score < 50 else "MEDIUM" if score < 70 else "LOW"
    return score, risk, issues


# ──────────────────────────────────────────────
# HTML REPORT GENERATOR
# ──────────────────────────────────────────────

def generate_html_report(target, all_results, score, risk, issues, meta):
    risk_colors = {
        "CRITICAL": "#f85149", "HIGH": "#d29922",
        "MEDIUM": "#388bfd", "LOW": "#3fb950"
    }
    severity_colors = {
        "Critical": "#f85149", "High": "#d29922",
        "Medium": "#388bfd", "Low": "#3fb950", "Info": "#8b949e"
    }
    rc = risk_colors.get(risk, "#8b949e")
    subs_result = next((r for r in all_results if r["module"] == "subdomains"), {})
    ports_result = next((r for r in all_results if r["module"] == "ports"), {})
    headers_result = next((r for r in all_results if r["module"] == "headers"), {})
    paths_result = next((r for r in all_results if r["module"] == "paths"), {})
    tech_result = next((r for r in all_results if r["module"] == "web_tech"), {})

    subdomains_html = "".join(
        f"<tr><td>{s['subdomain']}</td><td>{s['ip']}</td></tr>"
        for s in subs_result.get("found", [])
    ) or "<tr><td colspan='2'>None found</td></tr>"

    ports_html = "".join(
        f"<tr><td>{p['port']}</td><td>{p['service']}</td>"
        f"<td style='color:{'#f85149' if p['risk_note'] else '#3fb950'}'>"
        f"{'⚠ ' + p['risk_note'] if p['risk_note'] else '✓ OK'}</td></tr>"
        for p in ports_result.get("open_ports", [])
    ) or "<tr><td colspan='3'>No open ports found</td></tr>"

    headers_missing_html = "".join(
        f"<tr><td style='color:#f85149'>✗ {h['header']}</td><td>{h['description']}</td></tr>"
        for h in headers_result.get("missing", [])
    )
    headers_present_html = "".join(
        f"<tr><td style='color:#3fb950'>✓ {h['header']}</td><td>{h['value'][:60]}</td></tr>"
        for h in headers_result.get("present", [])
    )

    paths_html = "".join(
        f"<tr><td style='color:{'#f85149' if p['path'] in ['/.git/HEAD','/.env'] else '#3fb950'}'>"
        f"HTTP {p['status']}</td><td>{p['path']}</td><td>{p['size']} bytes</td></tr>"
        for p in paths_result.get("found", [])
    ) or "<tr><td colspan='3'>No interesting paths found</td></tr>"

    tech_html = "".join(
        f"<tr><td>{t['name']}</td><td>{t['value']}</td></tr>"
        for t in tech_result.get("technologies", [])
    ) or "<tr><td colspan='2'>No technologies detected</td></tr>"

    issues_html = "".join(
        f"<tr><td style='color:{severity_colors.get(i['severity'],'#8b949e')}'>{i['severity']}</td>"
        f"<td>{i['issue']}</td>"
        f"<td>{i.get('detail','')}</td></tr>"
        for i in issues
    ) or "<tr><td colspan='3'>No issues found</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report — {target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px}}
header{{background:#161b22;border-bottom:1px solid #21262d;padding:20px 32px}}
h1{{font-size:20px;font-weight:600;color:#58a6ff;margin-bottom:4px}}
.sub{{font-size:12px;color:#8b949e}}
main{{max-width:1200px;margin:0 auto;padding:24px 32px}}
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}}
.stat{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px;text-align:center}}
.stat .val{{font-size:24px;font-weight:600;margin-bottom:2px}}
.stat .lbl{{font-size:11px;color:#8b949e;text-transform:uppercase}}
.risk-bar{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px 24px;margin-bottom:24px;display:flex;align-items:center;gap:20px}}
.risk-val{{font-size:36px;font-weight:700;color:{rc}}}
.bar-bg{{flex:1;background:#21262d;border-radius:4px;height:10px}}
.bar-fill{{height:10px;border-radius:4px;background:{rc};width:{score}%}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;margin-bottom:16px}}
.card h2{{font-size:14px;font-weight:600;color:#c9d1d9;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #21262d}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{text-align:left;padding:6px 10px;color:#8b949e;font-size:11px;text-transform:uppercase;border-bottom:1px solid #21262d}}
td{{padding:7px 10px;border-bottom:1px solid #0d1117;color:#c9d1d9;word-break:break-all}}
tr:hover td{{background:#1c2128}}
footer{{text-align:center;padding:20px;color:#8b949e;font-size:12px;border-top:1px solid #21262d;margin-top:24px}}
</style>
</head>
<body>
<header>
  <h1>Automated Reconnaissance Report</h1>
  <div class="sub">Target: {target} &nbsp;|&nbsp; Scan time: {meta['start']} → {meta['end']} ({meta['duration']}s) &nbsp;|&nbsp; by Kofi Asibey-Kitiabi</div>
</header>
<main>
  <div class="stats">
    <div class="stat"><div class="val" style="color:#58a6ff">{len(subs_result.get('found',[]))}</div><div class="lbl">Subdomains</div></div>
    <div class="stat"><div class="val" style="color:#3fb950">{len(ports_result.get('open_ports',[]))}</div><div class="lbl">Open Ports</div></div>
    <div class="stat"><div class="val" style="color:#f85149">{len(ports_result.get('risky_ports',[]))}</div><div class="lbl">Risky Ports</div></div>
    <div class="stat"><div class="val" style="color:#d29922">{len(headers_result.get('missing',[]))}</div><div class="lbl">Missing Headers</div></div>
    <div class="stat"><div class="val" style="color:#f85149">{len(paths_result.get('sensitive',[]))}</div><div class="lbl">Sensitive Paths</div></div>
  </div>
  <div class="risk-bar">
    <div><div style="font-size:12px;color:#8b949e;margin-bottom:4px">Risk Rating</div><div class="risk-val">{risk}</div></div>
    <div style="flex:1">
      <div style="display:flex;justify-content:space-between;font-size:11px;color:#8b949e;margin-bottom:4px"><span>Security Score</span><span>{score}/100</span></div>
      <div class="bar-bg"><div class="bar-fill"></div></div>
    </div>
  </div>
  <div class="card"><h2>Issues Found ({len(issues)})</h2>
    <table><thead><tr><th>Severity</th><th>Issue</th><th>Detail</th></tr></thead>
    <tbody>{issues_html}</tbody></table></div>
  <div class="card"><h2>Subdomains Discovered ({len(subs_result.get('found',[]))})</h2>
    <table><thead><tr><th>Subdomain</th><th>IP Address</th></tr></thead>
    <tbody>{subdomains_html}</tbody></table></div>
  <div class="card"><h2>Open Ports ({len(ports_result.get('open_ports',[]))})</h2>
    <table><thead><tr><th>Port</th><th>Service</th><th>Risk Note</th></tr></thead>
    <tbody>{ports_html}</tbody></table></div>
  <div class="card"><h2>Web Technologies</h2>
    <table><thead><tr><th>Type</th><th>Value</th></tr></thead>
    <tbody>{tech_html}</tbody></table></div>
  <div class="card"><h2>Security Headers</h2>
    <table><thead><tr><th>Header</th><th>Value / Description</th></tr></thead>
    <tbody>{headers_missing_html}{headers_present_html}</tbody></table></div>
  <div class="card"><h2>Interesting Paths ({len(paths_result.get('found',[]))})</h2>
    <table><thead><tr><th>Status</th><th>Path</th><th>Size</th></tr></thead>
    <tbody>{paths_html}</tbody></table></div>
</main>
<footer>Automated Reconnaissance Framework &nbsp;|&nbsp; github.com/Mastertactician23/recon-framework &nbsp;|&nbsp; For authorized testing only</footer>
</body></html>"""
    return html


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def run_recon(target, modules="all"):
    start_time = datetime.now()
    start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")

    print("")
    print(bold(cyan("  ╔══════════════════════════════════════════════╗")))
    print(bold(cyan("  ║   AUTOMATED RECONNAISSANCE FRAMEWORK         ║")))
    print(bold(cyan("  ║   by Kofi Asibey-Kitiabi                     ║")))
    print(bold(cyan("  ╚══════════════════════════════════════════════╝")))
    print(f"  Target  : {bold(target)}")
    print(f"  Started : {start_str}")
    print(f"  Modules : DNS · Subdomains · Ports · Web Tech · Headers · Paths · SSL")
    print(bold(red("  WARNING : Only scan targets you have explicit written permission to test")))
    print("")

    all_results = []

    all_results.append(module_dns(target))
    all_results.append(module_subdomains(target))
    all_results.append(module_ports(target))
    all_results.append(module_web_tech(target))
    all_results.append(module_headers(target))
    all_results.append(module_paths(target))
    all_results.append(module_ssl(target))

    # Score
    score, risk, issues = calculate_risk_score(all_results)
    end_time = datetime.now()
    end_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
    duration = round((end_time - start_time).total_seconds(), 1)

    print(bold(cyan("\n" + "─" * 50)))
    print(bold("  RECONNAISSANCE SUMMARY"))
    print(bold(cyan("─" * 50)))

    subs_result = next((r for r in all_results if r["module"] == "subdomains"), {})
    ports_result = next((r for r in all_results if r["module"] == "ports"), {})
    headers_result = next((r for r in all_results if r["module"] == "headers"), {})
    paths_result = next((r for r in all_results if r["module"] == "paths"), {})

    print(f"  Target            : {target}")
    print(f"  Duration          : {duration}s")
    print(f"  Subdomains found  : {len(subs_result.get('found', []))}")
    print(f"  Open ports        : {len(ports_result.get('open_ports', []))}")
    print(f"  Risky ports       : {len(ports_result.get('risky_ports', []))}")
    print(f"  Missing headers   : {len(headers_result.get('missing', []))}")
    print(f"  Sensitive paths   : {len(paths_result.get('sensitive', []))}")
    print(f"  Issues found      : {len(issues)}")
    print(f"  Security Score    : {bold(str(score) + '/100')}")
    risk_col = red if risk in ["CRITICAL", "HIGH"] else yellow if risk == "MEDIUM" else green
    print(f"  Risk Rating       : {risk_col(bold(risk))}")
    print("")

    # Save JSON
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    json_path = f"reports/recon_{safe_target}_{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump({
            "target": target, "start": start_str, "end": end_str,
            "duration": duration, "score": score, "risk": risk,
            "issues": issues, "modules": all_results
        }, f, indent=2)
    print(green(f"  [✓] JSON report: {json_path}"))

    # Save HTML
    html_path = f"reports/recon_{safe_target}_{timestamp}.html"
    meta = {"start": start_str, "end": end_str, "duration": duration}
    html = generate_html_report(target, all_results, score, risk, issues, meta)
    with open(html_path, "w") as f:
        f.write(html)
    print(green(f"  [✓] HTML report: {html_path}"))
    print(cyan(f"  [*] Open: file://{os.path.abspath(html_path)}"))
    print("")


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Automated Reconnaissance Framework — for authorized testing only"
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target domain or IP (e.g. example.com or 172.18.0.2)"
    )
    args = parser.parse_args()

    if not args.target:
        print(red("[ERROR] Target required. Use --target <domain_or_ip>"))
        sys.exit(1)

    run_recon(args.target)
