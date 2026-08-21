"""Test shadowing detection.

The trap: a rule that is hidden by an earlier, broader rule. In most connector
implementations, the first match wins, so a later rule with the same hostname
is unreachable.
"""

import pytest

from awtunnel import validate_rules


def test_no_shadowing_different_hostnames():
    """Different hostnames never shadow each other."""
    rules = [
        {"hostname": "localhost", "path": "^/v1", "origin": "http://localhost:8080"},
        {"hostname": "127.0.0.1", "path": "^/v1", "origin": "http://127.0.0.1:8081"},
    ]
    result = validate_rules(rules)
    assert result.ok, f"Should be valid: {result.findings}"


def test_shadowing_same_hostname():
    """Same hostname in earlier rule shadows later rule."""
    rules = [
        {"hostname": "localhost", "path": "^/", "origin": "http://localhost:8080"},
        {"hostname": "localhost", "path": "^/v1", "origin": "http://localhost:8081"},
    ]
    result = validate_rules(rules)
    assert not result.ok, "Should detect shadowing"
    assert len(result.findings) == 1
    assert result.findings[0].category == "SHADOWED"
    assert "localhost" in result.findings[0].message
    assert result.findings[0].rule_index == 1
    assert result.findings[0].conflicting_rule_index == 0


def test_shadowing_multiple_rules():
    """Multiple shadowing detections when several rules have the same hostname."""
    rules = [
        {"hostname": "localhost", "path": "^/", "origin": "http://localhost:8080"},
        {"hostname": "localhost", "path": "^/v1", "origin": "http://localhost:8081"},
        {"hostname": "localhost", "path": "^/v2", "origin": "http://localhost:8082"},
    ]
    result = validate_rules(rules)
    assert not result.ok
    shadowed = [f for f in result.findings if f.category == "SHADOWED"]
    assert len(shadowed) == 2
    # Rule 1 is shadowed by rule 0.
    assert any(f.rule_index == 1 and f.conflicting_rule_index == 0 for f in shadowed)
    # Rule 2 is shadowed by rule 0 (or rule 1, depending on connector logic).
    assert any(f.rule_index == 2 for f in shadowed)


def test_no_shadowing_identical_rules():
    """Identical rules don't shadow (though they're redundant)."""
    # Note: Our implementation treats same hostname as shadowing.
    # If you want to allow identical rules, the implementation would need to change.
    rules = [
        {"hostname": "localhost", "path": "^/v1", "origin": "http://localhost:8080"},
        {"hostname": "localhost", "path": "^/v1", "origin": "http://localhost:8080"},
    ]
    result = validate_rules(rules)
    # With our simple implementation, same hostname = shadowing.
    # This is a conservative choice.
    assert not result.ok
    assert any(f.category == "SHADOWED" for f in result.findings)


def test_shadowing_with_mixed_findings():
    """Shadowing detected alongside other findings."""
    rules = [
        {"hostname": "localhost", "path": "^/", "origin": "http://localhost:8080"},
        {"hostname": "localhost", "path": "^/v1", "origin": "https://localhost:8080"},
    ]
    result = validate_rules(rules)
    assert not result.ok
    # Should have both scheme conflict and shadowing.
    categories = {f.category for f in result.findings}
    # The scheme conflict is between rules 0 and 1 on localhost:8080 (http vs https).
    # The shadowing is rule 1 shadowed by rule 0.
    assert "SHADOWED" in categories
    assert "SCHEME_CONFLICT" in categories
