"""Tests for fail-closed awseal verification in awtunnel validate/check."""

from __future__ import annotations

import contextlib
import importlib
import json
import sys
from pathlib import Path
from typing import Any, Iterator

import pytest
from awtunnel.cli import main

_SAMPLE_RULES = """\
routes:
  - hostname: tunnel.aitherium.com
    service: https://rc-origin:8310
    noTLSVerify: true
"""

_AWSEAL_DIR = Path(__file__).resolve().parents[2] / "awseal"


@contextlib.contextmanager
def _scoped_repo_awseal(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """Load in-repo ``awseal`` (0.1.2) without leaking ``sys.path`` or ``sys.modules``."""
    saved = {
        name: mod
        for name, mod in list(sys.modules.items())
        if name == "awseal" or name.startswith("awseal.")
    }
    for name in list(saved):
        sys.modules.pop(name, None)
    monkeypatch.syspath_prepend(str(_AWSEAL_DIR))
    try:
        yield importlib.import_module("awseal")
    finally:
        for name in [
            k for k in list(sys.modules) if k == "awseal" or k.startswith("awseal.")
        ]:
            sys.modules.pop(name, None)
        sys.modules.update(saved)


def test_unsealed_rules_pass_without_awseal_dependency(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "awseal", None)
    monkeypatch.delenv("AWTUNNEL_EXPECT_KEY", raising=False)
    rules = tmp_path / "routes.yaml"
    rules.write_text(_SAMPLE_RULES, encoding="utf-8")

    assert main(["validate", str(rules), "--from-cloudflared", "--no-resolve"]) == 0
    assert (
        main(
            [
                "check",
                str(rules),
                "--from-cloudflared",
                "tunnel.aitherium.com",
                "/r/demo",
            ]
        )
        == 0
    )


def test_sealed_rules_verify_and_reject_tamper_or_wrong_key(tmp_path, monkeypatch, capsys):
    keys = pytest.importorskip("awseal.keys")
    seal = pytest.importorskip("awseal.seal")

    key_a = tmp_path / "a.key"
    key_b = tmp_path / "b.key"
    keys.generate(key_a)
    keys.generate(key_b)
    pub_a = keys.public_key_hex(keys.load_private_key(key_a))
    pub_b = keys.public_key_hex(keys.load_private_key(key_b))

    rules = tmp_path / "routes.yaml"
    rules.write_text(_SAMPLE_RULES, encoding="utf-8")
    signed = seal.sign(tmp_path, key_path=key_a, subject="routes:test")
    seal.write(signed, tmp_path)

    # Matching key -> pass
    assert (
        main(
            [
                "validate",
                str(rules),
                "--from-cloudflared",
                "--no-resolve",
                "--expect-key",
                pub_a,
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "check",
                str(rules),
                "--from-cloudflared",
                "--expect-key",
                pub_a,
                "tunnel.aitherium.com",
                "/r/demo",
            ]
        )
        == 0
    )
    capsys.readouterr()

    # Wrong key -> exit 1
    assert (
        main(
            [
                "validate",
                str(rules),
                "--from-cloudflared",
                "--no-resolve",
                "--expect-key",
                pub_b,
                "--json",
            ]
        )
        == 1
    )
    err_payload = json.loads(capsys.readouterr().out)
    assert err_payload["ok"] is False
    assert err_payload["seal_ok"] is False

    # Tamper 1 byte -> exit 1
    rules.write_text(_SAMPLE_RULES + "# tampered\n", encoding="utf-8")
    assert (
        main(
            [
                "validate",
                str(rules),
                "--from-cloudflared",
                "--no-resolve",
                "--expect-key",
                pub_a,
            ]
        )
        == 1
    )
    assert (
        main(
            [
                "check",
                str(rules),
                "--from-cloudflared",
                "--expect-key",
                pub_a,
                "tunnel.aitherium.com",
                "/r/demo",
            ]
        )
        == 1
    )


def test_sealed_or_expect_key_without_awseal_exits_2(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "awseal", None)
    rules = tmp_path / "routes.yaml"
    rules.write_text(_SAMPLE_RULES, encoding="utf-8")

    # --expect-key without awseal -> exit 2
    assert (
        main(
            [
                "validate",
                str(rules),
                "--from-cloudflared",
                "--no-resolve",
                "--expect-key",
                "00" * 32,
            ]
        )
        == 2
    )

    # Adjacent awseal.json without awseal -> exit 2
    (tmp_path / "awseal.json").write_text("{}", encoding="utf-8")
    assert main(["validate", str(rules), "--from-cloudflared", "--no-resolve"]) == 2


def test_sealed_rules_awseal_011_compat_and_fail_closed(tmp_path, monkeypatch):
    """verify_rules_seal works and fails closed when awseal lacks verify_files (0.1.1)."""
    awseal_mod = pytest.importorskip("awseal")
    keys = pytest.importorskip("awseal.keys")
    seal = pytest.importorskip("awseal.seal")
    monkeypatch.delattr(awseal_mod, "verify_files", raising=False)

    key_a = tmp_path / "a.key"
    key_b = tmp_path / "b.key"
    keys.generate(key_a)
    keys.generate(key_b)
    pub_a = keys.public_key_hex(keys.load_private_key(key_a))
    pub_b = keys.public_key_hex(keys.load_private_key(key_b))

    rules = tmp_path / "routes.yaml"
    rules.write_text(_SAMPLE_RULES, encoding="utf-8")
    signed = seal.sign(tmp_path, key_path=key_a, subject="routes:011")
    seal.write(signed, tmp_path)

    assert (
        main(
            [
                "validate",
                str(rules),
                "--from-cloudflared",
                "--no-resolve",
                "--expect-key",
                pub_a,
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "validate",
                str(rules),
                "--from-cloudflared",
                "--no-resolve",
                "--expect-key",
                pub_b,
            ]
        )
        == 1
    )

    # Corrupted signature -> exit 1
    seal_path = tmp_path / "awseal.json"
    orig_seal = seal_path.read_text(encoding="utf-8")
    doc = json.loads(orig_seal)
    doc["signature"] = "ff" * 64 if not doc["signature"].startswith("ff") else "00" * 64
    seal_path.write_text(json.dumps(doc), encoding="utf-8")
    assert (
        main(
            [
                "validate",
                str(rules),
                "--from-cloudflared",
                "--no-resolve",
                "--expect-key",
                pub_a,
            ]
        )
        == 1
    )
    seal_path.write_text(orig_seal, encoding="utf-8")

    # Tamper 1 byte -> exit 1
    rules.write_text(_SAMPLE_RULES + "# tampered\n", encoding="utf-8")
    assert (
        main(
            [
                "validate",
                str(rules),
                "--from-cloudflared",
                "--no-resolve",
                "--expect-key",
                pub_a,
            ]
        )
        == 1
    )


def test_sealed_rules_repo_awseal_012_isolated(tmp_path, monkeypatch):
    """In-repo awseal 0.1.2 verifies and fails closed without leaking sys.modules."""
    with _scoped_repo_awseal(monkeypatch) as awseal_012:
        assert callable(getattr(awseal_012, "verify_files", None))
        from awseal import keys, seal

        key_a = tmp_path / "k12.key"
        keys.generate(key_a)
        pub_a = keys.public_key_hex(keys.load_private_key(key_a))

        rules = tmp_path / "routes.yaml"
        rules.write_text(_SAMPLE_RULES, encoding="utf-8")
        signed = seal.sign(tmp_path, key_path=key_a, subject="routes:012")
        seal.write(signed, tmp_path)

        assert (
            main(
                [
                    "validate",
                    str(rules),
                    "--from-cloudflared",
                    "--no-resolve",
                    "--expect-key",
                    pub_a,
                ]
            )
            == 0
        )
        rules.write_text(_SAMPLE_RULES + "# tamper\n", encoding="utf-8")
        assert (
            main(
                [
                    "validate",
                    str(rules),
                    "--from-cloudflared",
                    "--no-resolve",
                    "--expect-key",
                    pub_a,
                ]
            )
            == 1
        )
