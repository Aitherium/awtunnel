"""Core rule validation logic."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Any, NamedTuple

_LITERAL_PREFIX_RE = re.compile(r"\^/[A-Za-z0-9_./-]*")


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


def validate_rules(rules_data: list[dict[str, Any]], *, resolve: bool = True) -> ValidationResult:
    """Validate a set of ingress rules.

    Checks for:
    - Scheme conflicts: same (hostname, port) with different schemes
    - Unresolvable hostnames: hostnames that cannot be resolved
    - Shadowing: a rule that is hidden by an earlier, broader rule

    Args:
        rules_data: List of rule dicts with keys 'hostname', 'path', 'origin'.
        resolve: ask the resolver about every origin NAME. False makes this a
            purely static check -- what CI wants, where fleet names like
            ``web-origin`` resolve nowhere and would fail every rule.

    Returns:
        ValidationResult with ok=True if all validations pass, False otherwise.
    """
    findings: list[Finding] = []
    parsed_rules: list[tuple[int, Rule]] = []

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
            hostname = rule_dict["hostname"]
            path = rule_dict["path"]
            origin = rule_dict["origin"]
        except KeyError as e:
            findings.append(Finding(
                category="MISSING_FIELD",
                message=f"rule missing field: {e}",
                rule_index=idx,
            ))
            continue

        invalid_fields: list[str] = []
        for field_name, field_val in (("hostname", hostname), ("path", path), ("origin", origin)):
            if not isinstance(field_val, str) or (
                field_name in ("hostname", "path") and not field_val.strip()
            ):
                invalid_fields.append(f"{field_name} must be a non-empty string")
        if invalid_fields:
            findings.append(Finding(
                category="INVALID_FIELD",
                message="; ".join(invalid_fields),
                rule_index=idx,
            ))
            continue

        parsed_rules.append((idx, Rule(hostname=hostname, path=path, origin=origin)))

    # Check for scheme conflicts: same (hostname, port) with different schemes.
    # Rules failing PARSE_ERROR are excluded from downstream resolution & shadowing.
    valid_rules: list[tuple[int, Rule]] = []
    scheme_port_pairs: dict[tuple[str, str, str], int] = {}
    for idx, rule in parsed_rules:
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

        valid_rules.append((idx, rule))
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
    for idx, rule in valid_rules:
        if not resolve:
            break
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
    for pos, (idx, rule) in enumerate(valid_rules):
        for prev_idx, prev_rule in valid_rules[:pos]:
            if _hostname_shadows(prev_rule.hostname, rule.hostname) and _pattern_shadows(prev_rule.path, rule.path):
                if (
                    _normalize_host(prev_rule.hostname) == _normalize_host(rule.hostname)
                    and not prev_rule.hostname.strip().startswith("*.")
                ):
                    msg = (
                        f"rule {idx} with path {rule.path!r} is shadowed by "
                        f"rule {prev_idx} with path {prev_rule.path!r} "
                        f"(same hostname '{rule.hostname}')"
                    )
                else:
                    msg = (
                        f"rule {idx} ({rule.hostname} {rule.path!r}) is shadowed by "
                        f"wildcard rule {prev_idx} ({prev_rule.hostname} {prev_rule.path!r})"
                    )
                findings.append(Finding(
                    category="SHADOWED",
                    message=msg,
                    rule_index=idx,
                    conflicting_rule_index=prev_idx,
                ))

    return ValidationResult(ok=len(findings) == 0, findings=findings)


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _hostname_shadows(prev_host: str, curr_host: str) -> bool:
    """Return True if ``prev_host`` covers ``curr_host`` (exact or single-label ``*.domain``)."""
    prev = _normalize_host(prev_host)
    curr = _normalize_host(curr_host)
    if not prev or not curr:
        return False
    if prev == curr:
        return True
    if prev.startswith("*.") and curr != prev:
        suffix = prev[1:]
        if curr.endswith(suffix):
            label = curr[: -len(suffix)]
            return bool(label) and "." not in label
    return False


def _has_top_level_alternation(pattern: str) -> bool:
    """Return True if ``pattern`` has an unescaped ``|`` at parenthesis depth 0."""
    depth = 0
    in_char_class = False
    escaped = False
    for ch in pattern:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if in_char_class:
            if ch == "]":
                in_char_class = False
            continue
        if ch == "[":
            in_char_class = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "|" and depth == 0:
            return True
    return False


def _pattern_shadows(prev_path: str, curr_path: str) -> bool:
    """Return True if ``prev_path`` matches everything ``curr_path`` matches.

    Literal prefix shadowing is intentionally segment-bounded (for example,
    ``^/r`` shadows ``^/r/sub``, ``^/r$``, and ``^/r(...)`` but does not
    shadow sibling path segments like ``^/root``), and skips literal-prefix
    inference when ``curr_path`` uses top-level ``|`` alternation or makes a
    trailing boundary slash optional (e.g. ``^/r/?$`` under ``^/r/``).
    """
    if prev_path == curr_path:
        return True
    if prev_path in ("^/", "^/.*", ".*", "/"):
        return True
    if _has_top_level_alternation(curr_path):
        return False
    if _LITERAL_PREFIX_RE.fullmatch(prev_path) and curr_path.startswith("^/"):
        p_lit = prev_path[1:]
        c_lit = curr_path[1:]
        if p_lit.endswith("/"):
            if not c_lit.startswith(p_lit):
                return False
            rest = c_lit[len(p_lit) :]
            if rest[:1] in ("?", "*") or rest.startswith("{0,"):
                return False
            return True
        return (
            c_lit == p_lit
            or c_lit.startswith(p_lit + "/")
            or c_lit.startswith(p_lit + "$")
            or c_lit.startswith(p_lit + "(")
        )
    return False


def match_route(
    rules_data: list[dict[str, Any]],
    hostname: str,
    path: str,
) -> tuple[int, dict[str, Any]] | None:
    """Resolve the first matching rule for ``(hostname, path)`` (first-match-wins).

    When ``path`` starts with ``"^"``, matches exact pattern equality against
    each rule's ``path`` (preserving pattern-lookup mode). Otherwise treats
    ``path`` as a concrete request path (e.g. ``/r/devbox-1``) and matches
    ``^/`` or ``re.search(rule_path, path)``.
    """
    if not isinstance(hostname, str) or not isinstance(path, str):
        return None
    target_host = _normalize_host(hostname)
    pattern_mode = path.startswith("^")
    for idx, rule_dict in enumerate(rules_data):
        if not isinstance(rule_dict, dict):
            continue
        raw_host = rule_dict.get("hostname")
        if not isinstance(raw_host, str):
            continue
        rule_host = _normalize_host(raw_host)
        if not rule_host or not _hostname_shadows(rule_host, target_host):
            continue
        raw_path = rule_dict.get("path")
        rule_path = raw_path if isinstance(raw_path, str) and raw_path else "^/"
        if pattern_mode:
            if rule_path == path:
                return (idx, rule_dict)
            continue
        if rule_path == "^/":
            return (idx, rule_dict)
        try:
            if re.search(rule_path, path) is not None:
                return (idx, rule_dict)
        except re.error:
            if rule_path == path or path.startswith(rule_path):
                return (idx, rule_dict)
    return None
