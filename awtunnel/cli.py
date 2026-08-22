"""awtunnel CLI — validate ingress rules.

Exit codes: 0 valid, 1 validation failed, 2 could not judge (bad file/format).

A rule set that passes validation may still fail at runtime if origins are down
or misconfigured. Validation checks the rule set alone, not the actual services.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .rules import validate_rules


def load_rules(path: str) -> list[dict]:
    """Load rules from a YAML or JSON file.

    Supports .yaml, .yml, and .json extensions. For JSON, rules are expected to
    be a top-level array or an object with a 'rules' key.
    """
    try:
        content = Path(path).read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"DEAD: cannot read rules file {path}: {exc}", file=sys.stderr)
        return []

    # Determine format by extension.
    if path.endswith(".json"):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and "rules" in data:
                return data["rules"]
            else:
                print("DEAD: JSON file must have 'rules' key or be an array",
                      file=sys.stderr)
                return []
        except json.JSONDecodeError as exc:
            print(f"DEAD: invalid JSON in {path}: {exc}", file=sys.stderr)
            return []
    elif path.endswith((".yaml", ".yml")):
        # For now, expect YAML to be simple enough to parse as Python dict.
        # A full YAML parser is a dependency we want to avoid.
        print("NOTE: YAML parsing requires PyYAML (not installed). "
              "Use JSON for now.", file=sys.stderr)
        return []
    else:
        print("DEAD: unsupported file extension (use .json, .yaml, or .yml)",
              file=sys.stderr)
        return []


def main(argv: list[str] | None = None) -> int:
    """Entry point for the awtunnel CLI."""
    # GENERATED doctor intercept (gen_aw_doctor.py) -- do not edit
    _dv = locals().get("argv")
    if (_dv if _dv is not None else __import__("sys").argv[1:])[:1] == ["doctor"]:
        from ._doctor import report
        return report()
    ap = argparse.ArgumentParser(
        prog="awtunnel",
        description=__doc__,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # validate subcommand
    v = sub.add_parser("validate", help="validate a rule set")
    v.add_argument("rules", help="path to rules file (.json or .yaml)")
    v.add_argument("--json", action="store_true", help="output results as JSON")

    # check subcommand
    c = sub.add_parser("check", help="check if a route exists")
    c.add_argument("rules", help="path to rules file")
    c.add_argument("hostname", help="hostname to match")
    c.add_argument("path", help="path pattern to match")

    args = ap.parse_args(argv)

    if args.cmd == "validate":
        if not Path(args.rules).is_file():
            print(f"DEAD: no such rules file: {args.rules}", file=sys.stderr)
            return 2

        rules = load_rules(args.rules)
        if not rules:
            # load_rules already printed an error.
            return 2

        result = validate_rules(rules)
        if args.json:
            print(json.dumps({
                "ok": result.ok,
                "findings_count": len(result.findings),
                "findings": [
                    {
                        "category": f.category,
                        "message": f.message,
                        "rule_index": f.rule_index,
                        "conflicting_rule_index": f.conflicting_rule_index,
                    }
                    for f in result.findings
                ],
            }, indent=2))
        else:
            print(f"{len(rules)} rule(s), {len(result.findings)} finding(s)")
            for f in result.findings:
                print("  ! " + str(f))
            print("VERDICT:", "ok" if result.ok else "FAILED")

        return 0 if result.ok else 1

    if args.cmd == "check":
        if not Path(args.rules).is_file():
            print(f"DEAD: no such rules file: {args.rules}", file=sys.stderr)
            return 2

        rules = load_rules(args.rules)
        if not rules:
            return 2

        # Find matching rules.
        matches = []
        for idx, rule_dict in enumerate(rules):
            if rule_dict.get("hostname") == args.hostname and \
               rule_dict.get("path") == args.path:
                matches.append((idx, rule_dict))

        if not matches:
            print(f"not found: no rule for {args.hostname} {args.path}")
            return 1

        for idx, rule in matches:
            print(f"rule {idx}: {rule.get('origin', 'no origin')}")

        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
