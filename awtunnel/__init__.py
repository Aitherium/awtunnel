"""awtunnel — tunnel ingress rule validation.

Rule validation that catches scheme mismatches, unresolvable hostnames, and
shadowing where a broader pattern hides a more specific rule.
"""

from __future__ import annotations

from .connector import AitherTunnel, TunnelConfig, TunnelStatus
from .rules import Finding, Rule, match_route, validate_rules

__all__ = [
    "Rule",
    "Finding",
    "validate_rules",
    "match_route",
    "AitherTunnel",
    "TunnelConfig",
    "TunnelStatus",
]
__version__ = "0.2.1"
