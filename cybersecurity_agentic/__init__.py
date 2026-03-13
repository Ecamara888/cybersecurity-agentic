"""Lightweight security assistant utilities."""

from .security_checks import (
    DestinationPolicy,
    analyze_headers,
    analyze_tls_profile,
    allowed_destinations,
    scan_open_ports,
)
from .reporting import build_security_report

__all__ = [
    "DestinationPolicy",
    "analyze_headers",
    "analyze_tls_profile",
    "allowed_destinations",
    "scan_open_ports",
    "build_security_report",
]
