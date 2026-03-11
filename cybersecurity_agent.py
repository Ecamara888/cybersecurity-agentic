#!/usr/bin/env python3
"""
Cybersecurity Agent - Powered by Claude Opus 4.6

An agentic security assessment tool that plans, acts, and verifies to protect systems.
Features:
  - TCP port scanning
  - HTTP security header analysis
  - TLS/SSL certificate and cipher checks
  - DNS lookup and reverse DNS
  - Comprehensive report generation
  - Allowed-targets whitelist for safe-by-design operation
  - Full audit logging of every action

Usage:
    python cybersecurity_agent.py [target]

    target: hostname to assess (must be in ALLOWED_TARGETS)

Environment:
    ANTHROPIC_API_KEY: Your Anthropic API key
"""

import anthropic
import socket
import ssl
import json
import logging
import datetime
import urllib.request
import urllib.error
import os
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("security_agent.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowed targets whitelist
# ---------------------------------------------------------------------------
ALLOWED_TARGETS: list[str] = [
    "scanme.nmap.org",   # Intentionally available for scanning tests
    "example.com",
    "httpbin.org",
    "badssl.com",
    "expired.badssl.com",
    "wrong.host.badssl.com",
    "self-signed.badssl.com",
]

# Common ports to scan when no list is provided
COMMON_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 143, 443,
    993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 27017,
]

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _validate_target(target: str) -> bool:
    """Return True if the target's hostname is in the allowed whitelist."""
    host = target.split(":")[0].strip()
    return host in ALLOWED_TARGETS


def _service_for_port(port: int) -> str:
    """Return a service name for a well-known port, or 'unknown'."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def scan_ports(target: str, ports: list[int] | None = None, timeout: float = 1.0) -> dict:
    """Scan TCP ports on *target* and return open/closed details."""
    if not _validate_target(target):
        return {
            "error": (
                f"Target '{target}' is not in the allowed whitelist. "
                f"Allowed targets: {ALLOWED_TARGETS}"
            )
        }

    if ports is None:
        ports = COMMON_PORTS

    logger.info("Starting port scan on %s for %d ports (timeout=%.1fs)", target, len(ports), timeout)

    open_ports: list[int] = []
    port_details: dict[str, Any] = {}

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))

            if result == 0:
                open_ports.append(port)
                port_details[str(port)] = {
                    "status": "open",
                    "service": _service_for_port(port),
                }
            else:
                port_details[str(port)] = {"status": "closed"}

        except socket.gaierror as exc:
            return {"error": f"DNS resolution failed for '{target}': {exc}"}
        except socket.timeout:
            port_details[str(port)] = {"status": "filtered/timeout"}
        except Exception as exc:  # noqa: BLE001
            port_details[str(port)] = {"status": "error", "detail": str(exc)}

    logger.info("Port scan complete. Open ports on %s: %s", target, open_ports)
    return {
        "target": target,
        "open_ports": open_ports,
        "closed_count": len(ports) - len(open_ports),
        "port_details": port_details,
        "timestamp": datetime.datetime.now().isoformat(),
    }


def check_http_headers(target: str, use_https: bool = False) -> dict:
    """Check HTTP security headers for *target* and report missing/misconfigured ones."""
    if not _validate_target(target):
        return {"error": f"Target '{target}' is not in the allowed whitelist."}

    protocol = "https" if use_https else "http"
    url = f"{protocol}://{target}"
    logger.info("Checking HTTP headers: %s", url)

    security_headers_of_interest = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cache-Control",
    ]

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityAuditAgent/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            headers = dict(response.headers)
            status_code = response.status
            server = headers.get("Server", "not disclosed")

        present: dict[str, str] = {}
        missing: list[str] = []
        for h in security_headers_of_interest:
            val = headers.get(h)
            if val:
                present[h] = val
            else:
                missing.append(h)

        findings: list[dict] = []

        if "Server" in headers:
            findings.append({
                "severity": "low",
                "issue": f"Server header discloses software: {server}",
                "recommendation": "Remove or genericise the Server response header.",
            })

        if use_https and "Strict-Transport-Security" not in present:
            findings.append({
                "severity": "high",
                "issue": "HSTS header missing — susceptible to SSL-stripping attacks.",
                "recommendation": (
                    "Add: Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains; preload"
                ),
            })

        if "Content-Security-Policy" not in present:
            findings.append({
                "severity": "medium",
                "issue": "Content-Security-Policy missing — increases XSS risk.",
                "recommendation": "Define a strict Content-Security-Policy header.",
            })

        if "X-Frame-Options" not in present:
            findings.append({
                "severity": "medium",
                "issue": "X-Frame-Options missing — clickjacking risk.",
                "recommendation": "Add: X-Frame-Options: DENY",
            })

        if "X-Content-Type-Options" not in present:
            findings.append({
                "severity": "low",
                "issue": "X-Content-Type-Options missing — MIME-sniffing risk.",
                "recommendation": "Add: X-Content-Type-Options: nosniff",
            })

        logger.info("HTTP header check complete for %s (%d findings)", url, len(findings))
        return {
            "target": target,
            "url": url,
            "status_code": status_code,
            "server": server,
            "security_headers_present": present,
            "security_headers_missing": missing,
            "findings": findings,
            "timestamp": datetime.datetime.now().isoformat(),
        }

    except urllib.error.URLError as exc:
        return {"error": f"Connection failed to {url}: {exc.reason}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Unexpected error: {exc}"}


def check_tls_ssl(target: str, port: int = 443) -> dict:
    """Analyse TLS/SSL configuration, certificate validity, and cipher strength."""
    if not _validate_target(target):
        return {"error": f"Target '{target}' is not in the allowed whitelist."}

    logger.info("Checking TLS/SSL for %s:%d", target, port)

    findings: list[dict] = []

    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=10) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=target) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()          # (name, protocol, bits)
                tls_version = tls_sock.version()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        not_after = cert.get("notAfter", "")

        # Certificate expiry
        try:
            expire_ts = ssl.cert_time_to_seconds(not_after)
            days_remaining = (expire_ts - datetime.datetime.now().timestamp()) / 86400
        except Exception:
            days_remaining = float("inf")

        if days_remaining < 0:
            findings.append({
                "severity": "critical",
                "issue": f"Certificate EXPIRED {abs(int(days_remaining))} days ago.",
                "recommendation": "Renew the TLS certificate immediately.",
            })
        elif days_remaining < 30:
            findings.append({
                "severity": "high",
                "issue": f"Certificate expires in {int(days_remaining)} days.",
                "recommendation": "Renew the TLS certificate soon.",
            })

        # TLS protocol version
        if tls_version in ("TLSv1", "TLSv1.1"):
            findings.append({
                "severity": "high",
                "issue": f"Deprecated TLS version in use: {tls_version}",
                "recommendation": "Disable TLS 1.0/1.1; require TLS 1.2 or TLS 1.3.",
            })

        # Cipher strength
        cipher_name = cipher[0] if cipher else "unknown"
        cipher_bits = cipher[2] if cipher else 0
        if any(weak in cipher_name.upper() for weak in ("RC4", "DES", "NULL", "EXPORT")):
            findings.append({
                "severity": "critical",
                "issue": f"Weak cipher suite in use: {cipher_name}",
                "recommendation": "Remove weak ciphers; prefer AES-GCM or ChaCha20-Poly1305.",
            })

        logger.info("TLS check complete for %s:%d (%d findings)", target, port, len(findings))
        return {
            "target": target,
            "port": port,
            "tls_version": tls_version,
            "cipher": {
                "name": cipher_name,
                "protocol": cipher[1] if cipher else None,
                "bits": cipher_bits,
            },
            "certificate": {
                "subject": subject,
                "issuer": issuer,
                "valid_until": not_after,
                "days_remaining": int(days_remaining) if days_remaining != float("inf") else None,
                "san": cert.get("subjectAltName", []),
            },
            "findings": findings,
            "timestamp": datetime.datetime.now().isoformat(),
        }

    except ssl.SSLCertVerificationError as exc:
        return {
            "error": f"Certificate verification failed: {exc}",
            "findings": [{
                "severity": "critical",
                "issue": f"TLS certificate verification failed: {exc}",
                "recommendation": "Fix the certificate chain / hostname mismatch.",
            }],
        }
    except ssl.SSLError as exc:
        return {
            "error": f"SSL handshake error: {exc}",
            "findings": [{
                "severity": "critical",
                "issue": f"SSL handshake failed: {exc}",
                "recommendation": "Review the server's TLS configuration.",
            }],
        }
    except ConnectionRefusedError:
        return {"error": f"Connection refused on {target}:{port}"}
    except socket.timeout:
        return {"error": f"Connection timed out to {target}:{port}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Unexpected error: {exc}"}


def dns_lookup(target: str) -> dict:
    """Resolve DNS for *target* and perform reverse-DNS on the first few IPs."""
    if not _validate_target(target):
        return {"error": f"Target '{target}' is not in the allowed whitelist."}

    logger.info("DNS lookup for %s", target)

    try:
        addr_infos = socket.getaddrinfo(target, None)
        ipv4 = list(dict.fromkeys(
            a[4][0] for a in addr_infos if a[0] == socket.AF_INET
        ))
        ipv6 = list(dict.fromkeys(
            a[4][0] for a in addr_infos if a[0] == socket.AF_INET6
        ))

        reverse_dns: dict[str, str] = {}
        for ip in ipv4[:3]:
            try:
                reverse_dns[ip] = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                reverse_dns[ip] = "no PTR record"

        logger.info("DNS lookup complete for %s — IPv4: %s", target, ipv4)
        return {
            "target": target,
            "ipv4_addresses": ipv4,
            "ipv6_addresses": ipv6,
            "reverse_dns": reverse_dns,
            "timestamp": datetime.datetime.now().isoformat(),
        }

    except socket.gaierror as exc:
        return {"error": f"DNS resolution failed for '{target}': {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Unexpected error: {exc}"}


def generate_report(scan_results: dict, target: str, output_format: str = "text") -> dict:
    """Aggregate scan results into a prioritised security report."""
    logger.info("Generating security report for %s", target)

    all_findings: list[dict] = []
    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_counts: dict[str, int] = {s: 0 for s in severity_order}

    for scan_type, result in scan_results.items():
        if isinstance(result, dict):
            for finding in result.get("findings", []):
                enriched = dict(finding)
                enriched["source"] = scan_type
                all_findings.append(enriched)
                sev = finding.get("severity", "info").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1

    # Simple risk score (0–100)
    weights = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0}
    risk_score = min(100, sum(severity_counts[s] * weights[s] for s in severity_order))

    risk_level = (
        "CRITICAL" if risk_score >= 70 else
        "HIGH"     if risk_score >= 40 else
        "MEDIUM"   if risk_score >= 20 else
        "LOW"      if risk_score >   0 else
        "MINIMAL"
    )

    # Deduplicated, prioritised recommendations
    seen_recs: set[str] = set()
    recommendations: list[dict] = []
    for finding in sorted(all_findings, key=lambda f: severity_order.index(f.get("severity", "info").lower())):
        rec = finding.get("recommendation", "")
        if rec and rec not in seen_recs:
            seen_recs.add(rec)
            recommendations.append({
                "priority": finding.get("severity", "info"),
                "recommendation": rec,
                "related_issue": finding.get("issue", ""),
            })

    report = {
        "report_title": f"Security Assessment — {target}",
        "target": target,
        "generated_at": datetime.datetime.now().isoformat(),
        "executive_summary": {
            "risk_level": risk_level,
            "risk_score": f"{risk_score}/100",
            "total_findings": len(all_findings),
            "severity_breakdown": severity_counts,
        },
        "findings": sorted(
            all_findings,
            key=lambda f: severity_order.index(f.get("severity", "info").lower()),
        ),
        "recommendations": recommendations,
        "raw_scan_results": scan_results,
    }

    logger.info("Report ready. Risk level: %s, score: %d/100", risk_level, risk_score)
    return report


# ---------------------------------------------------------------------------
# Claude tool definitions
# ---------------------------------------------------------------------------
TOOLS: list[dict] = [
    {
        "name": "scan_ports",
        "description": (
            "Scan TCP ports on a target host to discover open services. "
            "Only works with targets on the allowed whitelist."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Hostname or IP to scan (must be in the allowed list).",
                },
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Ports to scan. Omit to use a built-in list of common ports.",
                },
                "timeout": {
                    "type": "number",
                    "description": "Per-port TCP connection timeout in seconds (default 1.0).",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "check_http_headers",
        "description": (
            "Fetch HTTP/HTTPS headers from a target and report missing or "
            "misconfigured security headers."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Hostname to check.",
                },
                "use_https": {
                    "type": "boolean",
                    "description": "Use HTTPS instead of HTTP (default false).",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "check_tls_ssl",
        "description": (
            "Analyse TLS/SSL configuration: certificate validity, expiry, "
            "protocol version, and cipher strength."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Hostname to check.",
                },
                "port": {
                    "type": "integer",
                    "description": "TLS port (default 443).",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "dns_lookup",
        "description": (
            "Resolve DNS records for a target: A/AAAA addresses and reverse-DNS."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Hostname to look up.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "generate_report",
        "description": (
            "Aggregate all scan results into a risk-scored security report "
            "with prioritised recommendations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "scan_results": {
                    "type": "object",
                    "description": "Dictionary of results from previous scans.",
                },
                "target": {
                    "type": "string",
                    "description": "The assessed target hostname.",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["text", "json"],
                    "description": "Report format (default: text).",
                },
            },
            "required": ["scan_results", "target"],
        },
    },
]

TOOL_FUNCTIONS = {
    "scan_ports": scan_ports,
    "check_http_headers": check_http_headers,
    "check_tls_ssl": check_tls_ssl,
    "dns_lookup": dns_lookup,
    "generate_report": generate_report,
}


def _execute_tool(name: str, tool_input: dict) -> str:
    """Dispatch a tool call and return its result as a JSON string."""
    logger.info("Tool call → %s(%s)", name, json.dumps(tool_input)[:120])
    fn = TOOL_FUNCTIONS.get(name)
    if fn is None:
        return json.dumps({"error": f"Unknown tool: {name}"})
    try:
        result = fn(**tool_input)
        return json.dumps(result, indent=2, default=str)
    except Exception as exc:  # noqa: BLE001
        logger.error("Tool '%s' raised an exception: %s", name, exc)
        return json.dumps({"error": f"Tool execution failed: {exc}"})


# ---------------------------------------------------------------------------
# Agent entry point
# ---------------------------------------------------------------------------

def run_security_agent(target: str, task: str | None = None) -> None:
    """
    Run the agentic security assessment loop against *target*.

    Args:
        target: Hostname to assess (must be in ALLOWED_TARGETS).
        task:   Optional natural-language task description.
                Defaults to a full comprehensive assessment.
    """
    if not _validate_target(target):
        print(
            f"\nERROR: '{target}' is not in the allowed whitelist.\n"
            f"Allowed targets: {ALLOWED_TARGETS}\n"
        )
        return

    logger.info("=== Security assessment started for %s ===", target)
    print(f"\n{'='*60}")
    print("  CYBERSECURITY AGENT  —  powered by Claude Opus 4.6")
    print(f"  Target  : {target}")
    print(f"  Started : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    client = anthropic.Anthropic()

    system_prompt = f"""You are an expert cybersecurity agent. Your mission is to perform \
thorough, responsible security assessments of network targets.

ALLOWED TARGETS (whitelist): {ALLOWED_TARGETS}
You MUST refuse any request to scan a target not in this list.

Assessment workflow:
1. dns_lookup      — map the infrastructure
2. scan_ports      — discover open services
3. check_http_headers (HTTP)  — baseline header review
4. check_http_headers (HTTPS) — HTTPS header review if port 443 is open
5. check_tls_ssl   — TLS/SSL posture if HTTPS is reachable
6. generate_report — compile findings into a risk-scored report

For every finding report:
  • Severity: CRITICAL / HIGH / MEDIUM / LOW
  • Why it matters
  • Concrete, actionable remediation

Be methodical, complete, and present results clearly."""

    user_message = task or (
        f"Perform a comprehensive security assessment of {target}. "
        "Run all available checks (DNS, ports, HTTP/HTTPS headers, TLS/SSL) "
        "and produce a full security report."
    )

    messages = [{"role": "user", "content": user_message}]

    # -----------------------------------------------------------------------
    # Agentic loop — keep running until Claude stops calling tools
    # -----------------------------------------------------------------------
    while True:
        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=8096,
            thinking={"type": "adaptive"},
            system=system_prompt,
            tools=TOOLS,
            messages=messages,
        )

        logger.info("Response received — stop_reason: %s", response.stop_reason)

        # Print any text blocks the model produced
        for block in response.content:
            if block.type == "text":
                print(f"\nAgent:\n{block.text}\n")

        if response.stop_reason == "end_turn":
            break

        if response.stop_reason == "tool_use":
            tool_results = []

            for block in response.content:
                if block.type == "tool_use":
                    print(f"[Tool] {block.name}  input={json.dumps(block.input)[:120]}")
                    raw = _execute_tool(block.name, block.input)
                    data = json.loads(raw)

                    if "error" in data:
                        print(f"       ✗ {data['error']}")
                    else:
                        keys = ", ".join(str(k) for k in data.keys())
                        print(f"       ✓ returned keys: {keys}")

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": raw,
                    })

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        else:
            # pause_turn or unexpected — append and break
            messages.append({"role": "assistant", "content": response.content})
            break

    logger.info("=== Security assessment complete for %s ===", target)
    print(f"\n{'='*60}")
    print("  Assessment complete.")
    print("  Full audit log → security_agent.log")
    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    target_host = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    run_security_agent(target_host)
