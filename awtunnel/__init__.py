"""awtunnel — tunnel ingress rule validation.

Rule validation that catches scheme mismatches, unresolvable hostnames, and
shadowing where a broader pattern hides a more specific rule.
"""

from __future__ import annotations

from .rules import Finding, Rule, validate_rules

__all__ = ["Rule", "Finding", "validate_rules"]
__version__ = "0.1.0"
