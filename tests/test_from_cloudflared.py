"""--from-cloudflared: real route files validate, and the validator can still FAIL on them."""

from __future__ import annotations

import json

from awtunnel.cli import from_cloudflared, load_rules, main
from awtunnel.rules import validate_rules

ROUTES = """\
# a slice of tunnel-routes.yaml, with the carve-out ABOVE its bare hostname
routes:
  - hostname: mcp.aitherium.com
    path: ^/api/v1/chat/hosted
    service: https://api-origin:8001
    noTLSVerify: true
  - hostname: mcp.aitherium.com
    service: http://mcp-origin:8182
    description: "the gateway"   # trailing comment after a quoted scalar
  - hostname: gobbonet.aitherium.com
    service: http_status:404
  - hostname: '*.aitherium.com'
    service: http://web-origin:3000
catchall:
  service: http_status:404
"""


def test_normalises_service_path_and_drops_builtins():
    rules = from_cloudflared({"routes": [
        {"hostname": "a.example", "service": "http://x:1"},
        {"hostname": "a.example", "path": "^/api", "service": "http://y:2"},
        {"hostname": "dead.example", "service": "http_status:404"},
        {"service": "http_status:404"},                      # catch-all, no hostname
    ]})
    assert rules == [
        {"hostname": "a.example", "path": "^/", "origin": "http://x:1"},
        {"hostname": "a.example", "path": "^/api", "origin": "http://y:2"},
    ]


def test_real_shape_validates_clean_without_a_resolver(tmp_path):
    f = tmp_path / "tunnel-routes.yaml"
    f.write_text(ROUTES, encoding="utf-8")
    rules = load_rules(str(f), cloudflared=True)
    assert [r["hostname"] for r in rules] == [
        "mcp.aitherium.com", "mcp.aitherium.com", "*.aitherium.com"]
    assert validate_rules(rules, resolve=False).ok
    assert main(["validate", str(f), "--from-cloudflared", "--no-resolve"]) == 0


def test_bare_hostname_above_its_carve_out_is_SHADOWED(tmp_path):
    # the order cloudflared would silently get wrong: first match wins, so the
    # hosted-chat floor would never be reached
    swapped = ROUTES.replace(
        "  - hostname: mcp.aitherium.com\n    path: ^/api/v1/chat/hosted\n"
        "    service: https://api-origin:8001\n    noTLSVerify: true\n", "")
    swapped = swapped.replace(
        "  - hostname: gobbonet.aitherium.com\n",
        "  - hostname: mcp.aitherium.com\n    path: ^/api/v1/chat/hosted\n"
        "    service: https://api-origin:8001\n  - hostname: gobbonet.aitherium.com\n")
    f = tmp_path / "swapped.yaml"
    f.write_text(swapped, encoding="utf-8")
    rules = load_rules(str(f), cloudflared=True)
    result = validate_rules(rules, resolve=False)
    assert not result.ok
    assert [x.category for x in result.findings] == ["SHADOWED"]
    assert main(["validate", str(f), "--from-cloudflared", "--no-resolve"]) == 1


def test_same_host_port_two_schemes_is_a_conflict(tmp_path):
    f = tmp_path / "conflict.yaml"
    f.write_text(
        "ingress:\n"
        "- hostname: a.example\n  service: http://idp-origin:8115\n"
        "- hostname: b.example\n  service: https://idp-origin:8115\n"
        "- service: http_status:404\n", encoding="utf-8")
    rules = load_rules(str(f), cloudflared=True)
    result = validate_rules(rules, resolve=False)
    assert [x.category for x in result.findings] == ["SCHEME_CONFLICT"]


def test_resolver_is_the_only_thing_no_resolve_turns_off():
    rules = [{"hostname": "a.example", "path": "^/", "origin": "http://no-such-host-awtunnel.invalid:1"}]
    assert validate_rules(rules, resolve=False).ok
    res = validate_rules(rules, resolve=True)
    assert [x.category for x in res.findings] == ["UNRESOLVABLE_HOST"]


def test_plain_yaml_without_the_flag_needs_a_rules_key(tmp_path, capsys):
    f = tmp_path / "tunnel-routes.yaml"
    f.write_text(ROUTES, encoding="utf-8")
    assert main(["validate", str(f)]) == 2
    assert "--from-cloudflared" in capsys.readouterr().err


def test_json_output_still_works_with_the_flag(tmp_path, capsys):
    f = tmp_path / "r.yaml"
    f.write_text(ROUTES, encoding="utf-8")
    assert main(["validate", str(f), "--from-cloudflared", "--no-resolve", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True and out["findings_count"] == 0
