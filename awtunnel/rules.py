"""Core rule validation logic."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Any, NamedTuple


class Rule(NamedTuple):
    """An ingress rule: hostname/path → origin."""

    hostname: str
    """The hostname to match (e.g., 'api.aitherium.com'). Patterns are literal
    strings at this layer; the connector interprets glob/regex."""

    path: str
    """The path pattern to match (e.g., '^/v1' or '^/auth'). Regex or glob
    depending on the connector."""

    origin: str
    """The origin URL to route to (e.g., 'https://gateway:8080'). Must include
    scheme and port."""

    def scheme_and_port(self) -> tuple[str, str]:
        """Extract scheme and port from origin.

        Returns a (scheme, port) tuple. If origin is 'https://host:8115',
        returns ('https', '8115'). If origin is 'http://host', returns
        ('http', '80').
        """
        # Parse the origin to extract scheme and port.
        origin = self.origin
        if "://" not in origin:
            raise ValueError(f"origin missing scheme: {origin!r}")

        scheme, rest = origin.split("://", 1)
        if "/" in rest:
            hostport, _ = rest.split("/", 1)
        else:
            hostport = rest

        if ":" in hostport:
            host, port = hostport.rsplit(":", 1)
            return (scheme, port)
        else:
            # No explicit port; use default for scheme.
            defaults = {"http": "80", "https": "443"}
            port = defaults.get(scheme, "80")
            return (scheme, port)

    def hostname_and_port(self) -> tuple[str, str]:
        """Extract hostname and port from origin.

        Returns a (hostname, port) tuple. If origin is 'https://host:8115',
        returns ('host', '8115'). If origin is 'http://host', returns
        ('host', '80').
        """
        origin = self.origin
        if "://" not in origin:
            raise ValueError(f"origin missing scheme: {origin!r}")

        _, rest = origin.split("://", 1)
        if "/" in rest:
            hostport, _ = rest.split("/", 1)
        else:
            hostport = rest

        if ":" in hostport:
            host, port = hostport.rsplit(":", 1)
            return (host, port)
        else:
            scheme = origin.split("://", 1)[0]
            defaults = {"http": "80", "https": "443"}
            port = defaults.get(scheme, "80")
            return (hostport, port)


@dataclass
class ValidationResult:
    """Result of validating a rule set."""

    ok: bool
    """Whether all validations passed."""

    findings: list[Finding] = field(default_factory=list)
    """List of findings (errors or warnings)."""


@dataclass
class Finding:
    """A single validation finding."""

    category: str
    """The finding category (e.g., 'SCHEME_CONFLICT', 'SHADOWED')."""

    message: str
    """Human-readable description of the finding."""

    rule_index: int | None = None
    """Index of the rule in the original list (0-based), if applicable."""

    conflicting_rule_index: int | None = None
    """Index of the conflicting rule, if applicable."""

    def __str__(self) -> str:
        """Format the finding for display."""
        if self.rule_index is not None:
            if self.conflicting_rule_index is not None:
                return f"{self.category} (rules {self.rule_index}, " \
                       f"{self.conflicting_rule_index}): {self.message}"
            else:
                return f"{self.category} (rule {self.rule_index}): {self.message}"
        return f"{self.category}: {self.message}"


def validate_rules(rules_data: list[dict[str, Any]]) -> ValidationResult:
    """Validate a set of ingress rules.

    Checks for:
    - Scheme conflicts: same (hostname, port) with different schemes
    - Unresolvable hostnames: hostnames that cannot be resolved
    - Shadowing: a rule that is hidden by an earlier, broader rule

    Args:
        rules_data: List of rule dicts with keys 'hostname', 'path', 'origin'.

    Returns:
        ValidationResult with ok=True if all validations pass, False otherwise.
    """
    findings: list[Finding] = []
    rules: list[Rule] = []

    # Parse rules and check for format errors.
    for idx, rule_dict in enumerate(rules_data):
        if not isinstance(rule_dict, dict):
            findings.append(Finding(
                category="INVALID_FORMAT",
                message=f"rule is not a dict: {type(rule_dict).__name__}",
                rule_index=idx,
            ))
            continue

        try:
            rule = Rule(
                hostname=rule_dict["hostname"],
                path=rule_dict["path"],
                origin=rule_dict["origin"],
            )
            rules.append(rule)
        except KeyError as e:
            findings.append(Finding(
                category="MISSING_FIELD",
                message=f"rule missing field: {e}",
                rule_index=idx,
            ))
            continue
        except (ValueError, TypeError) as e:
            findings.append(Finding(
                category="INVALID_FIELD",
                message=str(e),
                rule_index=idx,
            ))
            continue

    # Check for scheme conflicts: same (hostname, port) with different schemes.
    scheme_port_pairs: dict[tuple[str, str, str], int] = {}
    for idx, rule in enumerate(rules):
        try:
            hostname, port = rule.hostname_and_port()
            scheme, _ = rule.scheme_and_port()
        except ValueError as e:
            findings.append(Finding(
                category="PARSE_ERROR",
                message=str(e),
                rule_index=idx,
            ))
            continue

        key = (hostname, port, scheme)
        if (hostname, port) in {(h, p) for h, p, s in scheme_port_pairs.keys()}:
            # Find the conflicting rule.
            for (h, p, s), prev_idx in scheme_port_pairs.items():
                if h == hostname and p == port and s != scheme:
                    findings.append(Finding(
                        category="SCHEME_CONFLICT",
                        message=f"same host:port ({hostname}:{port}) with "
                                f"different schemes: rule {prev_idx} uses {s}, "
                                f"rule {idx} uses {scheme}",
                        rule_index=idx,
                        conflicting_rule_index=prev_idx,
                    ))

        scheme_port_pairs[key] = idx

    # Check for unresolvable hostnames.
    for idx, rule in enumerate(rules):
        hostname, _ = rule.hostname_and_port()
        # An IP LITERAL never needs the resolver: '::1' through getaddrinfo
        # fails on any host with no IPv6 stack (GitHub-hosted runners, plenty
        # of real machines), which reported a syntactically-valid address as a
        # typo. Resolution is a check for NAMES; literals are validated by form.
        try:
            ipaddress.ip_address(hostname.strip("[]"))
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False  # a NAME -- the resolver below is the check
        if is_ip_literal:
            continue
        # Try to resolve. We check both IPv4 and IPv6, and accept either.
        # A port in the hostname is already stripped by hostname_and_port().
        try:
            socket.getaddrinfo(hostname, None)
        except (socket.gaierror, socket.error):
            # Hostname does not resolve. Report it.
            findings.append(Finding(
                category="UNRESOLVABLE_HOST",
                message=f"hostname '{hostname}' cannot be resolved",
                rule_index=idx,
            ))

    # Check for shadowing: a rule that is hidden by an earlier, broader rule.
    for idx, rule in enumerate(rules):
        # A rule is shadowed if any earlier rule has the same hostname AND
        # a path pattern that would match this rule's paths.
        # Simple heuristic: if paths are identical, or if earlier path is "^/"
        # (which matches everything), then shadowing occurs.
        for prev_idx in range(idx):
            prev_rule = rules[prev_idx]
            if prev_rule.hostname == rule.hostname:
                # Check if paths would cause shadowing
                is_shadowed = False
                if prev_rule.path == rule.path:
                    # Identical paths: definitely shadowing
                    is_shadowed = True
                elif prev_rule.path == "^/":
                    # Root pattern matches everything: shadowing
                    is_shadowed = True

                if is_shadowed:
                    findings.append(Finding(
                        category="SHADOWED",
                        message=f"rule {idx} with path {rule.path!r} is shadowed by "
                                f"rule {prev_idx} with path {prev_rule.path!r} "
                                f"(same hostname '{rule.hostname}')",
                        rule_index=idx,
                        conflicting_rule_index=prev_idx,
                    ))

    return ValidationResult(ok=len(findings) == 0, findings=findings)
