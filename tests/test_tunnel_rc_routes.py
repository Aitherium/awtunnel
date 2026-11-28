"""Offline validation & route-resolution tests for tunnel.aitherium.com Remote Control."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from awtunnel import match_route, validate_rules
from awtunnel.cli import load_rules, main

VALID_BARE_ROUTES = """\
routes:
  - hostname: tunnel.aitherium.com
    service: https://rc-origin:8310
    noTLSVerify: true
  - hostname: '*.aitherium.com'
    service: http://web-origin:3000
catchall:
  service: http://web-origin:3000
"""

VALID_CARVEOUT_ROUTES = """\
routes:
  - hostname: tunnel.aitherium.com
    path: ^/r/
    service: https://rc-origin:8310
  - hostname: tunnel.aitherium.com
    path: ^/tunnel/
    service: https://rc-origin:8310
  - hostname: tunnel.aitherium.com
    path: ^/nodes/
    service: https://rc-origin:8310
  - hostname: tunnel.aitherium.com
    service: https://rc-origin:8310
  - hostname: '*.aitherium.com'
    service: http://web-origin:3000
catchall:
  service: http_status:404
"""


def test_valid_tunnel_rc_bare_rule_above_wildcard(tmp_path):
    f = tmp_path / "routes.yaml"
    f.write_text(VALID_BARE_ROUTES, encoding="utf-8")
    assert main(["validate", str(f), "--from-cloudflared", "--no-resolve"]) == 0


def test_valid_tunnel_rc_explicit_carveouts_above_bare_rule(tmp_path):
    f = tmp_path / "routes.yaml"
    f.write_text(VALID_CARVEOUT_ROUTES, encoding="utf-8")
    assert main(["validate", str(f), "--from-cloudflared", "--no-resolve"]) == 0


def test_shadowed_bare_rule_above_carveouts(tmp_path):
    bad = """\
routes:
  - hostname: tunnel.aitherium.com
    service: https://rc-origin:8310
  - hostname: tunnel.aitherium.com
    path: ^/r/
    service: https://rc-origin:8310
  - hostname: tunnel.aitherium.com
    path: ^/tunnel/
    service: https://rc-origin:8310
  - hostname: tunnel.aitherium.com
    path: ^/nodes/
    service: https://rc-origin:8310
"""
    f = tmp_path / "bad.yaml"
    f.write_text(bad, encoding="utf-8")
    rules = load_rules(str(f), cloudflared=True)
    res = validate_rules(rules, resolve=False)
    assert not res.ok
    shadowed = [x for x in res.findings if x.category == "SHADOWED"]
    assert len(shadowed) == 3
    assert main(["validate", str(f), "--from-cloudflared", "--no-resolve"]) == 1


def test_shadowed_wildcard_above_tunnel_subdomain(tmp_path):
    bad = """\
routes:
  - hostname: '*.aitherium.com'
    service: http://web-origin:3000
  - hostname: tunnel.aitherium.com
    service: https://rc-origin:8310
"""
    f = tmp_path / "wildcard_first.yaml"
    f.write_text(bad, encoding="utf-8")
    rules = load_rules(str(f), cloudflared=True)
    res = validate_rules(rules, resolve=False)
    assert not res.ok
    assert [x.category for x in res.findings] == ["SHADOWED"]
    assert main(["validate", str(f), "--from-cloudflared", "--no-resolve"]) == 1


def test_shadowed_prefix_rule_above_subpath():
    rules = [
        {"hostname": "tunnel.aitherium.com", "path": "^/r", "origin": "https://rc-origin:8310"},
        {"hostname": "tunnel.aitherium.com", "path": "^/r/sub", "origin": "https://rc-origin:8310"},
    ]
    res = validate_rules(rules, resolve=False)
    assert not res.ok
    assert [x.category for x in res.findings] == ["SHADOWED"]

    rules_slash = [
        {"hostname": "tunnel.aitherium.com", "path": "^/r/", "origin": "https://rc-origin:8310"},
        {"hostname": "tunnel.aitherium.com", "path": "^/r/sub", "origin": "https://rc-origin:8310"},
    ]
    res_slash = validate_rules(rules_slash, resolve=False)
    assert not res_slash.ok
    assert [x.category for x in res_slash.findings] == ["SHADOWED"]


def test_scheme_conflict_on_rc_origin():
    rules = [
        {"hostname": "tunnel.aitherium.com", "path": "^/r/", "origin": "http://rc-origin:8310"},
        {"hostname": "tunnel.aitherium.com", "path": "^/tunnel/", "origin": "https://rc-origin:8310"},
    ]
    res = validate_rules(rules, resolve=False)
    assert not res.ok
    assert [x.category for x in res.findings] == ["SCHEME_CONFLICT"]


@pytest.mark.parametrize(
    "req_path",
    [
        "/",
        "/r/devbox-swift-falcon",
        "/tunnel/rc/instances",
        "/tunnel/nodes/n1/attach",
        "/nodes/n1/harness/sessions/unified",
    ],
)
def test_check_from_cloudflared_resolves_concrete_rc_paths(tmp_path, capsys, req_path):
    f = tmp_path / "routes.yaml"
    f.write_text(VALID_BARE_ROUTES, encoding="utf-8")

    rc = main(["check", str(f), "--from-cloudflared", "tunnel.aitherium.com", req_path])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out == "rule 0: https://rc-origin:8310"

    rc_json = main([
        "check", str(f), "--from-cloudflared", "--json", "tunnel.aitherium.com", req_path,
    ])
    assert rc_json == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["matched"] is True
    assert payload["rule_index"] == 0
    assert payload["origin"] == "https://rc-origin:8310"


def test_check_from_cloudflared_first_match_wins_and_single_label_wildcard(tmp_path, capsys):
    doc = """\
routes:
  - hostname: tunnel.aitherium.com
    path: ^/r/
    service: https://rc-edge:8310
  - hostname: tunnel.aitherium.com
    service: https://portal-origin:8310
  - hostname: '*.aitherium.com'
    service: http://web-origin:3000
"""
    f = tmp_path / "routes.yaml"
    f.write_text(doc, encoding="utf-8")

    assert main(["check", str(f), "--from-cloudflared", "tunnel.aitherium.com", "/r/box-1"]) == 0
    assert "https://rc-edge:8310" in capsys.readouterr().out

    assert main(["check", str(f), "--from-cloudflared", "tunnel.aitherium.com", "/health"]) == 0
    assert "https://portal-origin:8310" in capsys.readouterr().out

    assert main(["check", str(f), "--from-cloudflared", "tenant.aitherium.com", "/"]) == 0
    assert "http://web-origin:3000" in capsys.readouterr().out

    # Cloudflared single-label wildcard does not match multi-label subdomains or foreign domains.
    assert main(["check", str(f), "--from-cloudflared", "deep.tenant.aitherium.com", "/"]) == 1
    assert main(["check", str(f), "--from-cloudflared", "unknown.example.org", "/"]) == 1


def test_monorepo_tunnel_routes_when_present():
    repo_routes = Path(__file__).resolve().parents[3] / "config" / "tunnel-routes.yaml"
    if not repo_routes.is_file():
        pytest.skip("monorepo route config not present")

    rules = load_rules(str(repo_routes), cloudflared=True)
    res = validate_rules(rules, resolve=False)
    assert res.ok, f"Unexpected findings: {res.findings}"

    for host in ("a30.link", "tunnel.aitherium.com"):
        for path in ("/", "/r/devbox-swift-falcon", "/tunnel/rc/instances", "/nodes/node-1/attach"):
            hit = match_route(rules, host, path)
            assert hit is not None, f"Missing route for {host}{path}"
            _idx, rule = hit
            assert rule["hostname"] == host
            assert rule["origin"].startswith("https://")
            assert ":8310" in rule["origin"]

    # Cookie-isolated *.a30.run bot/awrun wildcard is declared fail-closed (http_status:404).
    raw_text = repo_routes.read_text(encoding="utf-8")
    assert '"*.a30.run"' in raw_text or "'*.a30.run'" in raw_text


def test_pattern_shadows_avoids_false_positives_on_alternation_and_optional_slash():
    # Top-level alternation can match /other which ^/r does not cover.
    res_alt = validate_rules([
        {"hostname": "tunnel.aitherium.com", "path": "^/r", "origin": "https://rc-origin:8310"},
        {"hostname": "tunnel.aitherium.com", "path": "^/r/sub|^/other", "origin": "https://rc-origin:8310"},
    ], resolve=False)
    assert res_alt.ok, f"Unexpected findings: {res_alt.findings}"

    # Optional trailing slash ^/r/?$ matches /r which ^/r/ does not cover.
    res_opt = validate_rules([
        {"hostname": "tunnel.aitherium.com", "path": "^/r/", "origin": "https://rc-origin:8310"},
        {"hostname": "tunnel.aitherium.com", "path": "^/r/?$", "origin": "https://rc-origin:8310"},
    ], resolve=False)
    assert res_opt.ok, f"Unexpected findings: {res_opt.findings}"

    # Segment-bounded: ^/r does not shadow ^/root, while ^/r/ still shadows ^/r/(?:a|b).
    res_seg = validate_rules([
        {"hostname": "tunnel.aitherium.com", "path": "^/r", "origin": "https://rc-origin:8310"},
        {"hostname": "tunnel.aitherium.com", "path": "^/root", "origin": "https://rc-origin:8310"},
    ], resolve=False)
    assert res_seg.ok

    res_group = validate_rules([
        {"hostname": "tunnel.aitherium.com", "path": "^/r/", "origin": "https://rc-origin:8310"},
        {"hostname": "tunnel.aitherium.com", "path": "^/r/(?:a|b)", "origin": "https://rc-origin:8310"},
    ], resolve=False)
    assert [x.category for x in res_group.findings] == ["SHADOWED"]


def test_validate_rules_handles_bad_origin_none_fields_and_case_hostname_message():
    res_bad_origin = validate_rules([
        {"hostname": "a.example", "path": "^/", "origin": "bad-origin"},
    ], resolve=True)
    assert not res_bad_origin.ok
    assert [x.category for x in res_bad_origin.findings] == ["PARSE_ERROR"]

    res_none = validate_rules([
        {"hostname": None, "path": "^/", "origin": None},
    ], resolve=True)
    assert not res_none.ok
    assert [x.category for x in res_none.findings] == ["INVALID_FIELD"]

    res_case = validate_rules([
        {"hostname": "Tunnel.Aitherium.com", "path": "^/", "origin": "https://rc-origin:8310"},
        {"hostname": "tunnel.aitherium.com", "path": "^/r/", "origin": "https://rc-origin:8310"},
    ], resolve=False)
    assert not res_case.ok
    assert [x.category for x in res_case.findings] == ["SHADOWED"]
    msg = res_case.findings[0].message
    assert "same hostname" in msg
    assert "wildcard rule" not in msg
