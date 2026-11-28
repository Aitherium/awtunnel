"""Tests for stdlib-only Remote Control discovery and `awtunnel rc` / `status` bridge."""

from __future__ import annotations

import http.server
import json
import os
import socket
import threading
from types import SimpleNamespace

import pytest

from awtunnel import cli, rc_bridge


class _StatusHandler(http.server.BaseHTTPRequestHandler):
    payload: dict = {"active": False}
    status_code: int = 200
    expected_token: str | None = None

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/rc/status":
            self.send_response(404)
            self.end_headers()
            return
        if self.expected_token is not None:
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {self.expected_token}":
                body = json.dumps({"detail": "missing or invalid bearer token"}).encode("utf-8")
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        body = json.dumps(self.payload).encode("utf-8")
        self.send_response(self.status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return


@pytest.fixture()
def rc_daemon():
    class _Server(http.server.ThreadingHTTPServer):
        allow_reuse_address = True

    class _Handler(_StatusHandler):
        pass

    server = _Server(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    url = f"http://{host}:{port}"
    try:
        yield url, _Handler
    finally:
        server.shutdown()
        server.server_close()


def test_discover_rc_from_daemon(rc_daemon, tmp_path):
    url, handler = rc_daemon
    handler.payload = {
        "active": True,
        "instance_id": "devbox-swift",
        "node_id": "node-42",
        "reach": "mesh",
    }
    info = rc_bridge.discover_rc(
        rc_state_file=tmp_path / "missing.json",
        harness_url=url,
        probe_daemon=True,
    )
    assert info["active"] is True
    assert info["source"] == "daemon"
    assert info["instance_id"] == "devbox-swift"
    assert info["node_id"] == "node-42"
    assert info["rc_url"] == "https://a30.link/r/devbox-swift"
    assert info["app_url"] == "https://app.aitherium.com/code/node-42"
    assert info["reach"] == "mesh"


def test_discover_rc_falls_back_to_state_file_live_pid(tmp_path):
    state_file = tmp_path / "rc-state.json"
    state_file.write_text(json.dumps({
        "instance_id": "laptop-1",
        "node_id": "n-1",
        "pid": os.getpid(),
        "rc_mode": "cli",
    }), encoding="utf-8")

    info = rc_bridge.discover_rc(
        rc_state_file=state_file,
        probe_daemon=False,
        pid_alive=lambda pid: pid == os.getpid(),
    )
    assert info["active"] is True
    assert info["source"] == "state_file"
    assert info["rc_url"] == "https://a30.link/r/laptop-1"
    assert info["app_url"] == "https://app.aitherium.com/code/n-1"
    assert info["reach"] == "cli"


def test_discover_rc_ignores_dead_pid_state_file(tmp_path):
    state_file = tmp_path / "rc-state.json"
    state_file.write_text(json.dumps({
        "instance_id": "stale-box",
        "node_id": "n-old",
        "pid": 999999,
        "rc_mode": "cli",
    }), encoding="utf-8")

    info = rc_bridge.discover_rc(
        rc_state_file=state_file,
        probe_daemon=False,
        pid_alive=lambda _pid: False,
    )
    assert info["active"] is False
    assert info["source"] == "none"
    assert info["rc_url"] is None
    assert info["app_url"] is None


def test_awtunnel_rc_status_json_active_and_inactive(rc_daemon, tmp_path, monkeypatch, capsys):
    url, handler = rc_daemon
    monkeypatch.setenv("AITHER_HARNESS_URL", url)
    monkeypatch.setenv("AITHER_RC_STATE", str(tmp_path / "missing.json"))

    handler.payload = {
        "active": True,
        "instance_id": "demo-slug",
        "node_id": "node-9",
        "reach": "tunnel",
    }
    rc = cli.main(["rc", "status", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["active"] is True
    assert out["rc_url"] == "https://a30.link/r/demo-slug"
    assert out["app_url"] == "https://app.aitherium.com/code/node-9"

    handler.payload = {"active": False}
    rc = cli.main(["rc", "status", "--json"])
    assert rc == 1
    out2 = json.loads(capsys.readouterr().out)
    assert out2["active"] is False


def test_awtunnel_rc_help_returns_zero(capsys):
    assert cli.main(["rc", "--help"]) == 0
    out = capsys.readouterr().out
    assert "adk rc" in out
    assert "tunnel.aitherium.com/r/" in out

    assert cli.main(["rc", "-h"]) == 0
    assert "usage: awtunnel rc" in capsys.readouterr().out


def test_awtunnel_rc_delegates_to_adk_when_present(monkeypatch):
    seen = []

    def fake_run(cmd, check=False):
        seen.append((cmd, check))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(rc_bridge, "find_adk_cmd", lambda: ["/mock/bin/adk"])
    monkeypatch.setattr(rc_bridge.subprocess, "run", fake_run)

    rc = cli.main(["rc", "--name", "devbox-1"])
    assert rc == 0
    assert seen == [(["/mock/bin/adk", "rc", "--name", "devbox-1"], False)]

    monkeypatch.setattr(
        rc_bridge.subprocess,
        "run",
        lambda cmd, check=False: SimpleNamespace(returncode=3),
    )
    assert cli.main(["rc", "off"]) == 3


def test_awtunnel_rc_missing_adk_prints_guidance(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rc_bridge, "find_adk_cmd", lambda: None)
    monkeypatch.setenv("AITHER_RC_STATE", str(tmp_path / "missing.json"))
    monkeypatch.setenv("AITHER_HARNESS_URL", "http://127.0.0.1:9")

    rc = cli.main(["rc", "--name", "devbox-1"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "adk rc" in out
    assert "https://tunnel.aitherium.com/r/<instance_id>" in out
    assert "awtunnel up" in out


def test_awtunnel_status_without_state_file_checks_rc(rc_daemon, tmp_path, monkeypatch, capsys):
    url, handler = rc_daemon
    monkeypatch.setattr(cli, "STATE_FILE", tmp_path / "no-state.json")
    monkeypatch.setenv("AITHER_RC_STATE", str(tmp_path / "no-rc-state.json"))
    monkeypatch.setenv("AITHER_HARNESS_URL", url)

    handler.payload = {"active": False}
    assert cli.main(["status"]) == 1
    assert capsys.readouterr().out.strip() == "no tunnel recorded"

    handler.payload = {
        "active": True,
        "instance_id": "rc-box",
        "node_id": "node-rc",
        "reach": "mesh",
    }
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "https://a30.link/r/rc-box" in out

    assert cli.main(["status", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["alive"] is True
    assert data["active"] is True
    assert data["rc_url"] == "https://a30.link/r/rc-box"
    assert data["remote_control"]["rc_url"] == "https://a30.link/r/rc-box"


def test_awtunnel_status_with_state_file_preserves_shape(rc_daemon, tmp_path, monkeypatch, capsys):
    url, handler = rc_daemon
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({
        "pid": os.getpid(),
        "url": "https://demo.trycloudflare.com",
        "port": 8080,
    }), encoding="utf-8")

    monkeypatch.setattr(cli, "STATE_FILE", state_file)
    monkeypatch.setenv("AITHER_RC_STATE", str(tmp_path / "no-rc-state.json"))
    monkeypatch.setenv("AITHER_HARNESS_URL", url)

    handler.payload = {"active": False}
    assert cli.main(["status"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["alive"] is True
    assert data["url"] == "https://demo.trycloudflare.com"
    assert "remote_control" not in data

    handler.payload = {"active": True, "instance_id": "box-2", "node_id": "n-2"}
    assert cli.main(["status"]) == 0
    data2 = json.loads(capsys.readouterr().out)
    assert data2["alive"] is True
    assert data2["remote_control"]["rc_url"] == "https://a30.link/r/box-2"


def test_discover_rc_bearer_auth_env_and_token_file(rc_daemon, tmp_path, monkeypatch):
    url, handler = rc_daemon
    handler.expected_token = "secret-harness-tok"
    handler.payload = {
        "active": True,
        "instance_id": "auth-box",
        "node_id": "node-auth",
        "reach": "tunnel",
    }

    aither_home = tmp_path / "aither_home"
    aither_home.mkdir()
    monkeypatch.delenv("AITHER_HARNESS_TOKEN", raising=False)
    monkeypatch.setenv("AITHER_HOME", str(aither_home))
    missing_state = tmp_path / "missing-rc.json"

    # Missing token -> 401 -> inactive
    res_unauth = rc_bridge.discover_rc(
        rc_state_file=missing_state,
        harness_url=url,
        probe_daemon=True,
    )
    assert res_unauth["active"] is False
    assert res_unauth["source"] == "none"

    # AITHER_HOME/harness_token -> 200 -> active
    (aither_home / "harness_token").write_text("secret-harness-tok\n", encoding="utf-8")
    res_file = rc_bridge.discover_rc(
        rc_state_file=missing_state,
        harness_url=url,
        probe_daemon=True,
    )
    assert res_file["active"] is True
    assert res_file["source"] == "daemon"
    assert res_file["rc_url"] == "https://a30.link/r/auth-box"

    # AITHER_HARNESS_TOKEN overrides file
    (aither_home / "harness_token").write_text("wrong-tok", encoding="utf-8")
    monkeypatch.setenv("AITHER_HARNESS_TOKEN", "secret-harness-tok")
    res_env = rc_bridge.discover_rc(
        rc_state_file=missing_state,
        harness_url=url,
        probe_daemon=True,
    )
    assert res_env["active"] is True
    assert res_env["instance_id"] == "auth-box"


def test_discover_rc_honors_aither_rc_state_file_and_aither_home(tmp_path, monkeypatch):
    monkeypatch.delenv("AITHER_RC_STATE", raising=False)
    monkeypatch.delenv("AITHER_RC_STATE_FILE", raising=False)
    monkeypatch.delenv("AITHER_HOME", raising=False)

    custom_state = tmp_path / "custom-rc.json"
    custom_state.write_text(json.dumps({
        "instance_id": "env-file-box",
        "node_id": "n-env",
        "pid": os.getpid(),
        "rc_mode": "cli",
    }), encoding="utf-8")
    monkeypatch.setenv("AITHER_RC_STATE_FILE", str(custom_state))

    info_file = rc_bridge.discover_rc(probe_daemon=False, pid_alive=lambda _pid: True)
    assert info_file["active"] is True
    assert info_file["instance_id"] == "env-file-box"
    assert info_file["rc_url"] == "https://a30.link/r/env-file-box"

    monkeypatch.delenv("AITHER_RC_STATE_FILE", raising=False)
    aither_home = tmp_path / "home_dir"
    aither_home.mkdir()
    (aither_home / "rc-state.json").write_text(json.dumps({
        "instance_id": "home-box",
        "node_id": "n-home",
        "pid": os.getpid(),
        "rc_mode": "daemon",
    }), encoding="utf-8")
    monkeypatch.setenv("AITHER_HOME", str(aither_home))

    info_home = rc_bridge.discover_rc(probe_daemon=False, pid_alive=lambda _pid: True)
    assert info_home["active"] is True
    assert info_home["instance_id"] == "home-box"
    assert info_home["app_url"] == "https://app.aitherium.com/code/n-home"


def test_discover_rc_ignores_stale_state_urls_when_daemon_active(rc_daemon, tmp_path):
    url, handler = rc_daemon
    stale_state = tmp_path / "rc-state.json"
    stale_state.write_text(json.dumps({
        "instance_id": "old-box",
        "node_id": "old-node",
        "rc_url": "https://tunnel.aitherium.com/r/old-box",
        "app_url": "https://app.aitherium.com/code/old-node",
        "pid": 99999999,
    }), encoding="utf-8")

    handler.payload = {
        "active": True,
        "instance_id": "fresh-box",
        "node_id": "fresh-node",
        "reach": "tunnel",
    }
    info = rc_bridge.discover_rc(
        rc_state_file=stale_state,
        harness_url=url,
        probe_daemon=True,
        pid_alive=lambda _pid: False,
    )
    assert info["active"] is True
    assert info["source"] == "daemon"
    assert info["instance_id"] == "fresh-box"
    assert info["node_id"] == "fresh-node"
    assert info["rc_url"] == "https://a30.link/r/fresh-box"
    assert info["app_url"] == "https://app.aitherium.com/code/fresh-node"

    # Even when daemon omits node_id, stale dead-PID state must not supply old-node.
    handler.payload = {"active": True, "instance_id": "fresh-only", "reach": "tunnel"}
    info2 = rc_bridge.discover_rc(
        rc_state_file=stale_state,
        harness_url=url,
        probe_daemon=True,
        pid_alive=lambda _pid: False,
    )
    assert info2["instance_id"] == "fresh-only"
    assert info2["node_id"] is None
    assert info2["rc_url"] == "https://a30.link/r/fresh-only"
    assert info2["app_url"] is None


def test_discover_rc_handles_non_http_daemon_garbage(tmp_path):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _serve_garbage() -> None:
        try:
            conn, _ = srv.accept()
            with conn:
                conn.recv(1024)
                conn.sendall(b"NOT_HTTP_GARBAGE\r\n\r\n")
        except OSError:
            pass

    t = threading.Thread(target=_serve_garbage, daemon=True)
    t.start()
    try:
        info = rc_bridge.discover_rc(
            rc_state_file=tmp_path / "missing.json",
            harness_url=f"http://127.0.0.1:{port}",
            probe_daemon=True,
            timeout=1.0,
        )
    finally:
        srv.close()
        t.join(timeout=1.0)

    assert info["active"] is False
    assert info["source"] == "none"


def test_awtunnel_rc_status_help_exits_zero_without_probing(monkeypatch, capsys):
    def _must_not_probe(*_args, **_kwargs):
        raise AssertionError("discover_rc must not be called for --help")

    monkeypatch.setattr(rc_bridge, "discover_rc", _must_not_probe)
    assert cli.main(["rc", "status", "--help"]) == 0
    out = capsys.readouterr().out
    assert "usage: awtunnel rc" in out

    assert cli.main(["rc", "status", "-h"]) == 0
    assert "usage: awtunnel rc" in capsys.readouterr().out


def test_awtunnel_status_and_down_handle_malformed_state_files(tmp_path, monkeypatch, capsys):
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(cli, "STATE_FILE", state_file)
    monkeypatch.setenv("AITHER_RC_STATE", str(tmp_path / "no-rc.json"))
    monkeypatch.setenv("AITHER_HARNESS_URL", "http://127.0.0.1:9")

    # Truthy non-dict JSON ("[1]") must not raise AttributeError.
    state_file.write_text("[1]", encoding="utf-8")
    assert cli.main(["status"]) == 1
    assert capsys.readouterr().out.strip() == "no tunnel recorded"
    assert cli.main(["down"]) == 1
    assert capsys.readouterr().out.strip() == "no tunnel recorded"

    # Non-integer pid ("abc") must not raise ValueError.
    state_file.write_text(json.dumps({
        "pid": "abc",
        "url": "https://demo.trycloudflare.com",
    }), encoding="utf-8")
    assert cli.main(["status"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["alive"] is False

    assert cli.main(["down"]) == 1
    assert "nothing was running; state cleared" in capsys.readouterr().out
    assert not state_file.exists()
