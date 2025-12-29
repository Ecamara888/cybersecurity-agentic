import contextlib
import socket
import socketserver
import threading

import pytest

from cybersecurity_agentic import (
    DestinationPolicy,
    analyze_headers,
    analyze_tls_profile,
    allowed_destinations,
    build_security_report,
    scan_open_ports,
)


class _EphemeralTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        self.request.sendall(data)


@contextlib.contextmanager
def _running_server():
    with _EphemeralTCPServer(("127.0.0.1", 0), _EchoHandler) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join()


def test_allowed_destinations_filters_hosts():
    policy = DestinationPolicy(["Example.com", "intranet.local"])
    permitted = allowed_destinations(policy, ["example.com", "internet.com"])
    assert permitted == ["example.com"]


def test_scan_open_ports_detects_listening_socket():
    with _running_server() as port:
        open_ports = scan_open_ports("127.0.0.1", [port, port + 1])
        assert port in open_ports
        assert port + 1 not in open_ports


def test_analyze_headers_reports_missing_defaults():
    findings = analyze_headers({
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
    })
    assert "content-security-policy" in findings["present"]
    assert "x-frame-options" in findings["present"]
    # Ensure missing headers are tracked even if not provided
    assert "strict-transport-security" in findings["missing"]
    assert "x-content-type-options" in findings["missing"]


def test_analyze_tls_profile_grades_issues():
    assessment = analyze_tls_profile(
        {
            "protocol": "TLSv1.0",
            "cipher_bits": 64,
            "certificate_valid": False,
            "hostname_matches": True,
        }
    )
    assert assessment["grade"] == "critical"
    assert "Legacy TLS version in use" in assessment["issues"]
    assert "Weak cipher (<128 bits)" in assessment["issues"]
    assert "Certificate validation failed" in assessment["issues"]


def test_build_security_report_compiles_sections():
    report = build_security_report(
        host="example.com",
        open_ports=[443, 80],
        header_findings={"present": ["x-frame-options"], "missing": ["referrer-policy"]},
        tls_assessment={"grade": "warning", "issues": ["Certificate status unknown"]},
    )

    assert report["host"] == "example.com"
    assert report["open_ports"] == [80, 443]
    assert report["headers"]["present"] == ["x-frame-options"]
    assert report["headers"]["missing"] == ["referrer-policy"]
    assert report["tls"]["grade"] == "warning"
    assert "Certificate status unknown" in report["tls"]["issues"]
