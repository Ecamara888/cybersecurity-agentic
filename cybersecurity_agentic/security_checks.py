"""Security check helpers for the cybersecurity agent.

The functions here are intentionally small and testable so the agent can
plan (determine what to check), act (collect data) and verify (report
issues) without needing network access in the tests.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from socket import AF_INET, SOCK_STREAM, socket
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


@dataclass
class DestinationPolicy:
    """Allowlist policy for target hosts.

    Attributes
    ----------
    allowed_hosts:
        Iterable of hostnames or IP addresses that the assistant is
        permitted to contact.
    """

    allowed_hosts: Sequence[str] = field(default_factory=list)

    def is_allowed(self, host: str) -> bool:
        """Return ``True`` if the host is included in the allowlist.

        Comparison is case-insensitive to keep the check predictable.
        """

        if not self.allowed_hosts:
            return True
        host_lower = host.lower()
        return any(candidate.lower() == host_lower for candidate in self.allowed_hosts)


def allowed_destinations(policy: DestinationPolicy, targets: Iterable[str]) -> List[str]:
    """Filter ``targets`` against the supplied :class:`DestinationPolicy`.

    Parameters
    ----------
    policy:
        Allowlist policy describing which hosts are permitted.
    targets:
        Iterable of target host strings.

    Returns
    -------
    list[str]
        Targets that are permitted by the allowlist.
    """

    return [target for target in targets if policy.is_allowed(target)]


def scan_open_ports(host: str, ports: Iterable[int], timeout: float = 0.5) -> List[int]:
    """Return a list of open ``ports`` for ``host`` using TCP connect probes.

    The function avoids raising on common socket errors and keeps the
    probing time bounded via a timeout. It is intentionally simple so it
    can be used in teaching and testing scenarios without requiring
    external dependencies.
    """

    open_ports: List[int] = []
    for port in ports:
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
            except OSError:
                # Treat connection errors as closed ports to keep the
                # helper resilient in constrained environments.
                continue
    return open_ports


def analyze_headers(headers: Mapping[str, str]) -> Dict[str, List[str]]:
    """Evaluate basic HTTP response headers for common security controls.

    Parameters
    ----------
    headers:
        Mapping of header names to values. Header name matching is
        case-insensitive, mirroring HTTP semantics.

    Returns
    -------
    dict[str, list[str]]
        A dictionary with two keys: ``"present"`` and ``"missing"``
        listing which recommended headers exist.
    """

    recommended = {
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
    }
    normalized = {key.lower(): value for key, value in headers.items()}

    present: List[str] = []
    missing: List[str] = []
    for header in sorted(recommended):
        if header in normalized and normalized[header].strip():
            present.append(header)
        else:
            missing.append(header)

    return {"present": present, "missing": missing}


def analyze_tls_profile(
    tls_profile: Mapping[str, Optional[str] | Optional[int] | Optional[bool]]
) -> Dict[str, object]:
    """Assess a TLS profile dictionary for obvious weaknesses.

    The function intentionally accepts a generic mapping so that tests
    can provide mocked TLS information without performing real network
    handshakes.

    Expected keys
    -------------
    protocol: str | None
        TLS version such as ``"TLSv1.2"`` or ``"TLSv1.3"``.
    cipher_bits: int | None
        Bit-length of the negotiated cipher; values below 128 are flagged
        as weak.
    certificate_valid: bool | None
        Whether the certificate is valid according to the caller.
    hostname_matches: bool | None
        Whether the certificate matches the expected hostname.
    """

    issues: List[str] = []

    protocol = tls_profile.get("protocol")
    if protocol is None:
        issues.append("Unknown TLS version")
    elif str(protocol).upper() in {"SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"}:
        issues.append("Legacy TLS version in use")

    cipher_bits = tls_profile.get("cipher_bits")
    if isinstance(cipher_bits, int) and cipher_bits < 128:
        issues.append("Weak cipher (<128 bits)")
    elif cipher_bits is None:
        issues.append("Cipher strength not provided")

    cert_valid = tls_profile.get("certificate_valid")
    if cert_valid is False:
        issues.append("Certificate validation failed")
    elif cert_valid is None:
        issues.append("Certificate status unknown")

    hostname_match = tls_profile.get("hostname_matches")
    if hostname_match is False:
        issues.append("Certificate hostname mismatch")
    elif hostname_match is None:
        issues.append("Hostname match unknown")

    grade = "good"
    if issues:
        grade = "warning" if len(issues) <= 2 else "critical"

    return {"grade": grade, "issues": issues}
