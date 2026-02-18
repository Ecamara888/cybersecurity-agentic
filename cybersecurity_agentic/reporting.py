"""Report construction helpers."""
from __future__ import annotations

from typing import Dict, Iterable, List, Mapping


def build_security_report(
    host: str,
    open_ports: Iterable[int],
    header_findings: Mapping[str, List[str]],
    tls_assessment: Mapping[str, object],
) -> Dict[str, object]:
    """Assemble a structured report summarizing security observations."""

    return {
        "host": host,
        "open_ports": sorted(open_ports),
        "headers": {
            "present": sorted(header_findings.get("present", [])),
            "missing": sorted(header_findings.get("missing", [])),
        },
        "tls": {
            "grade": tls_assessment.get("grade", "unknown"),
            "issues": list(tls_assessment.get("issues", [])),
        },
    }
