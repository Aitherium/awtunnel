"""Test scheme conflict detection.

The trap: same (hostname, port) with different schemes. One fails at runtime
while both validate individually.
"""

import pytest

from awtunnel import validate_rules


def test_no_conflict_different_hosts():
    """Different hostnames never conflict, even with same port."""
    rules = [
        {"hostname": "localhost", "path": "^/v1", "origin": "http://localhost:8080"},
        {"hostname": "127.0.0.1", "path": "^/v1", "origin": "https://127.0.0.1:8080"},
    ]
    result = validate_rules(rules)
    assert result.ok, f"Should be valid: {result.findings}"


def test_no_conflict_different_ports():
    """Same hostname but different ports never conflict."""
    rules = [
        {"hostname": "localhost", "path": "^/v1", "origin": "http://localhost:8080"},
        {"hostname": "localhost", "path": "^/v2", "origin": "http://localhost:8081"},
    ]
    result = validate_rules(rules)
    assert result.ok, f"Should be valid: {result.findings}"


def test_conflict_same_host_port_different_schemes():
    """Same host:port with different schemes — one will fail at runtime."""
    rules = [
        {"hostname": "localhost", "path": "^/auth", "origin": "http://localhost:8115"},
        {"hostname": "localhost", "path": "^/", "origin": "https://localhost:8115"},
    ]
    result = validate_rules(rules)
    assert not result.ok, "Should detect scheme conflict"
    assert len(result.findings) == 1
    assert result.findings[0].category == "SCHEME_CONFLICT"
    assert "8115" in result.findings[0].message
    assert "http" in result.findings[0].message
    assert "https" in result.findings[0].message


def test_conflict_implicit_ports():
    """Scheme conflict with implicit (default) ports."""
    # http defaults to port 80, https defaults to port 443.
    rules = [
        {"hostname": "localhost", "path": "^/v1", "origin": "http://localhost"},
        {"hostname": "localhost", "path": "^/v2", "origin": "https://localhost"},
    ]
    result = validate_rules(rules)
    # These should NOT conflict because default ports are different (80 vs 443).
    assert result.ok, f"Different default ports, should be valid: {result.findings}"


def test_conflict_same_explicit_ports():
    """Scheme conflict when explicitly set to same port."""
    rules = [
        {"hostname": "localhost", "path": "^/", "origin": "http://localhost:8115"},
        {"hostname": "localhost", "path": "^/extra", "origin": "https://localhost:8115"},
    ]
    result = validate_rules(rules)
    assert not result.ok
    assert result.findings[0].category == "SCHEME_CONFLICT"


def test_conflict_multiple_pairs():
    """Multiple scheme conflicts detected."""
    rules = [
        {"hostname": "localhost", "path": "^/v1", "origin": "http://localhost:8080"},
        {"hostname": "localhost", "path": "^/v2", "origin": "https://localhost:8080"},
        {"hostname": "127.0.0.1", "path": "^/", "origin": "http://127.0.0.1:9000"},
        {"hostname": "127.0.0.1", "path": "^/extra", "origin": "https://127.0.0.1:9000"},
    ]
    result = validate_rules(rules)
    assert not result.ok
    assert len(result.findings) >= 2
    assert sum(1 for f in result.findings if f.category == "SCHEME_CONFLICT") == 2
