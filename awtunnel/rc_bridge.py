"""Remote-control status discovery and optional delegation to `adk rc`."""

from __future__ import annotations

import http.client
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

RC_BASE_URL = "https://a30.link/r"
RC_COMPAT_BASE_URL = "https://tunnel.aitherium.com/r"
APP_CODE_BASE_URL = "https://app.aitherium.com/code"


def _default_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not h:
            return False
        ctypes.windll.kernel32.CloseHandle(h)
        return True
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def find_adk_cmd() -> list[str] | None:
    """Locate the `adk` CLI executable or module if installed."""
    adk_bin = shutil.which("adk")
    if adk_bin:
        return [adk_bin]
    if importlib.util.find_spec("adk") is not None:
        return [sys.executable, "-m", "adk"]
    return None


def _default_rc_state_file() -> Path:
    for var in ("AITHER_RC_STATE", "AITHER_RC_STATE_FILE"):
        env_path = (os.environ.get(var) or "").strip()
        if env_path:
            return Path(env_path).expanduser()
    home = (os.environ.get("AITHER_HOME") or "").strip()
    if home:
        return Path(home).expanduser() / "rc-state.json"
    return Path.home() / ".aither" / "rc-state.json"


def _default_harness_url() -> str:
    env_url = (os.environ.get("AITHER_HARNESS_URL") or "").strip()
    if env_url:
        return env_url.rstrip("/")
    port = (os.environ.get("AITHER_HARNESS_PORT") or "").strip() or "8362"
    return f"http://127.0.0.1:{port}"


def _default_harness_token() -> str:
    env_token = (os.environ.get("AITHER_HARNESS_TOKEN") or "").strip()
    if env_token:
        return env_token
    home = (os.environ.get("AITHER_HOME") or "").strip()
    tok_path = (
        Path(home).expanduser() / "harness_token"
        if home
        else Path.home() / ".aither" / "harness_token"
    )
    try:
        return tok_path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _read_rc_state(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _probe_rc_daemon(
    harness_url: str,
    timeout: float,
    harness_token: str | None = None,
) -> dict[str, Any] | None:
    url = f"{harness_url.rstrip('/')}/rc/status"
    token = (harness_token if harness_token is not None else _default_harness_token()).strip()
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            raw = resp.read().decode("utf-8")
    except (
        urllib.error.URLError,
        http.client.HTTPException,
        TimeoutError,
        OSError,
        UnicodeDecodeError,
        ValueError,
    ):
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _clean_str(val: Any) -> str | None:
    if not isinstance(val, str):
        return None
    cleaned = val.strip()
    return cleaned or None


def discover_rc(
    rc_state_file: str | Path | None = None,
    harness_url: str | None = None,
    probe_daemon: bool = True,
    timeout: float = 0.8,
    pid_alive: Callable[[int], bool] | None = None,
    harness_token: str | None = None,
) -> dict[str, Any]:
    """Discover active authenticated Remote Control session state.

    Probes the local harness daemon (``GET /rc/status``) when ``probe_daemon``
    is True and falls back to ``~/.aither/rc-state.json`` (checking PID
    liveness). Returns canonical URLs when an instance or node ID is known.
    """
    state_path = Path(rc_state_file) if rc_state_file is not None else _default_rc_state_file()
    base_url = (harness_url or _default_harness_url()).rstrip("/")
    alive_fn = pid_alive or _default_pid_alive
    adk_installed = find_adk_cmd() is not None

    daemon_data = (
        _probe_rc_daemon(base_url, timeout, harness_token=harness_token)
        if probe_daemon
        else None
    )
    state_data = _read_rc_state(state_path)

    state_pid_alive = False
    if state_data is not None:
        raw_pid = state_data.get("pid")
        if not isinstance(raw_pid, bool):
            try:
                pid_val = int(raw_pid) if raw_pid is not None else 0
            except (TypeError, ValueError):
                pid_val = 0
            state_pid_alive = pid_val > 0 and bool(alive_fn(pid_val))

    if daemon_data is not None and bool(daemon_data.get("active")):
        active = True
        source = "daemon"
        d_instance = _clean_str(daemon_data.get("instance_id"))
        d_node = _clean_str(daemon_data.get("node_id"))
        d_rc_url = _clean_str(daemon_data.get("rc_url"))
        d_app_url = _clean_str(daemon_data.get("app_url"))

        s_instance = _clean_str(state_data.get("instance_id")) if state_data else None
        s_node = _clean_str(state_data.get("node_id")) if state_data else None
        state_usable = (
            state_data is not None
            and state_pid_alive
            and (s_instance is None or d_instance is None or s_instance == d_instance)
            and (s_node is None or d_node is None or s_node == d_node)
        )

        instance_id = d_instance or (s_instance if state_usable else None)
        node_id = d_node or (s_node if state_usable else None)
        rc_url = d_rc_url or (
            _clean_str(state_data.get("rc_url"))
            if (
                state_usable
                and state_data is not None
                and (s_instance is None or s_instance == instance_id)
            )
            else None
        )
        app_url = d_app_url or (
            _clean_str(state_data.get("app_url"))
            if state_usable and state_data is not None and (s_node is None or s_node == node_id)
            else None
        )
        reach = str(daemon_data.get("reach") or "daemon")
    elif state_data is not None and state_pid_alive:
        active = True
        source = "state_file"
        instance_id = _clean_str(state_data.get("instance_id"))
        node_id = _clean_str(state_data.get("node_id"))
        rc_url = _clean_str(state_data.get("rc_url"))
        app_url = _clean_str(state_data.get("app_url"))
        reach = str(state_data.get("rc_mode") or "state_file")
    else:
        active = False
        source = "none"
        instance_id = None
        node_id = None
        rc_url = None
        app_url = None
        reach = "offline"

    if instance_id and not rc_url:
        rc_url = f"{RC_BASE_URL}/{instance_id}"
    if node_id and not app_url:
        app_url = f"{APP_CODE_BASE_URL}/{node_id}"

    return {
        "active": active,
        "instance_id": instance_id,
        "node_id": node_id,
        "rc_url": rc_url,
        "app_url": app_url,
        "reach": reach,
        "source": source,
        "adk_installed": adk_installed,
    }


def _print_rc_usage() -> None:
    print(
        "usage: awtunnel rc [status [--json] | off | --name <slug> | ...]\n"
        "\n"
        "Authenticated Remote Control bridges local sessions to:\n"
        "  https://a30.link/r/<instance_id> (alias: https://tunnel.aitherium.com/r/<instance_id>)\n"
        "  https://app.aitherium.com/code/<node_id>\n"
        "\n"
        "Subcommands:\n"
        "  status [--json]   Inspect active Remote Control state (/rc/status or rc-state.json)\n"
        "  off               Stop active Remote Control link (delegates to `adk rc off`)\n"
        "  --name <slug>     Start with a friendly instance slug (delegates to `adk rc`)"
    )


def _print_rc_status(info: dict[str, Any]) -> None:
    state_label = "active" if info["active"] else "inactive"
    print(f"Remote control: {state_label} (source={info['source']}, reach={info['reach']})")
    if info["instance_id"]:
        print(f"Instance: {info['instance_id']}")
    if info["node_id"]:
        print(f"Node: {info['node_id']}")
    if info["rc_url"]:
        print(f"RC URL: {info['rc_url']}")
    if info["app_url"]:
        print(f"App URL: {info['app_url']}")
    if not info["active"] and not info["adk_installed"]:
        print("Install awdk and run `adk rc` for authenticated remote control.")


def cmd_rc(rc_args: list[str]) -> int:
    """Handle `awtunnel rc` subcommand."""
    if any(arg in ("-h", "--help") for arg in rc_args):
        _print_rc_usage()
        return 0

    if rc_args and rc_args[0] == "status":
        as_json = "--json" in rc_args[1:]
        info = discover_rc()
        if as_json:
            print(json.dumps(info, indent=2))
        else:
            _print_rc_status(info)
        return 0 if info["active"] else 1

    adk_cmd = find_adk_cmd()
    if adk_cmd is not None:
        proc = subprocess.run([*adk_cmd, "rc", *rc_args], check=False)
        return proc.returncode

    info = discover_rc()
    print(
        "adk is not installed; authenticated Remote Control requires `adk rc`.\n"
        "Install awdk, run `adk login`, then run `adk rc` to get:\n"
        "  https://a30.link/r/<instance_id> (alias: https://tunnel.aitherium.com/r/<instance_id>)\n"
        "  https://app.aitherium.com/code/<node_id>\n"
        "(Note: `awtunnel up --port <port>` creates an unauthenticated quick tunnel for one port.)"
    )
    if info["active"]:
        _print_rc_status(info)
    return 1
