"""awtunnel CLI — validate ingress rules, and give one local port a public address.

    awtunnel validate RULES [--from-cloudflared] [--no-resolve] [--json]
    awtunnel check RULES HOSTNAME PATH
    awtunnel up --port 8150 [--host localhost] [--protocol http] [--name N --hostname H]
    awtunnel expose ...            (alias of up)
    awtunnel status
    awtunnel down

Exit codes: 0 ok, 1 validation failed / nothing to act on, 2 could not judge
(bad file, no cloudflared, tunnel never came up).

A rule set that passes validation may still fail at runtime if origins are down
or misconfigured. Validation checks the rule set alone, not the actual services.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

from . import _yaml
from .rules import validate_rules

#: cloudflared's own built-in services -- rules that route to the CONNECTOR, not
#: to an origin, so they carry no scheme/port to validate.
_CF_BUILTIN = ("http_status:", "hello_world", "bastion", "socks-proxy")

#: where `up` records the running tunnel so `status`/`down` can find it
STATE_FILE = Path(os.environ.get("AWTUNNEL_STATE", str(Path.home() / ".awtunnel" / "state.json")))


def from_cloudflared(doc: dict) -> list[dict]:
    """Normalise a cloudflared-shaped document into validator rules.

    Real route files say ``service:`` where the Rule wants ``origin:``; carry
    ``routes:`` (tunnel-routes.yaml) or ``ingress:`` (cloudflared config); and
    hold rules with NO path, which in cloudflared means "everything on this
    hostname". That last one maps to ``^/`` so the shadowing check asks the real
    question: a bare-hostname rule placed ABOVE its carve-out hides the carve-out.
    The catch-all (no hostname) and connector built-ins (``http_status:404``)
    are not origins and are dropped.
    """
    items = doc.get("routes")
    if items is None:
        items = doc.get("ingress")
    if not isinstance(items, list):
        raise ValueError("no `routes:` or `ingress:` list in the document")
    out: list[dict] = []
    for r in items:
        if not isinstance(r, dict):
            continue
        host = r.get("hostname")
        svc = r.get("service") or r.get("origin")
        if not host or not isinstance(svc, str):
            continue
        if svc.startswith(_CF_BUILTIN):
            continue
        out.append({"hostname": str(host), "path": str(r.get("path") or "^/"), "origin": svc})
    return out


def load_rules(path: str, *, cloudflared: bool = False) -> list[dict]:
    """Load rules from a YAML or JSON file.

    JSON: a top-level array or an object with a 'rules' key. YAML: the same,
    or -- with ``cloudflared=True`` -- a tunnel-routes.yaml / cloudflared config
    document, normalised by :func:`from_cloudflared`. YAML needs no PyYAML:
    :mod:`awtunnel._yaml` reads the route-file grammar with the stdlib.
    """
    try:
        content = Path(path).read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"DEAD: cannot read rules file {path}: {exc}", file=sys.stderr)
        return []

    if path.endswith(".json"):
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            print(f"DEAD: invalid JSON in {path}: {exc}", file=sys.stderr)
            return []
    elif path.endswith((".yaml", ".yml")):
        try:
            data = _yaml.load(content)
        except _yaml.YamlShapeError as exc:
            print(f"DEAD: {path} is outside the route-file grammar: {exc}", file=sys.stderr)
            return []
    else:
        print("DEAD: unsupported file extension (use .json, .yaml, or .yml)",
              file=sys.stderr)
        return []

    if cloudflared:
        try:
            return from_cloudflared(data if isinstance(data, dict) else {})
        except ValueError as exc:
            print(f"DEAD: {exc}", file=sys.stderr)
            return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "rules" in data:
        return data["rules"]
    print("DEAD: file must have a 'rules' key or be an array "
          "(pass --from-cloudflared for a route file)", file=sys.stderr)
    return []


# ── the verbs the registry promised ─────────────────────────────────────────
def _read_state() -> dict | None:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _clear_state() -> None:
    try:
        STATE_FILE.unlink()
    except FileNotFoundError:
        return                                  # already gone is the goal
    except OSError as exc:
        print(f"state file not removed ({STATE_FILE}): {exc}", file=sys.stderr)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # SYNCHRONIZE
        if not h:
            return False
        ctypes.windll.kernel32.CloseHandle(h)
        return True
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def cmd_up(args) -> int:
    """Expose one local port. Foreground: prints the URL, runs until Ctrl-C."""
    import asyncio

    from .connector import AitherTunnel

    try:
        tunnel = AitherTunnel(
            local_port=args.port, local_host=args.host, protocol=args.protocol,
            tunnel_name=args.name, hostname=args.hostname,
        )
    except FileNotFoundError as exc:
        print(f"DEAD: {exc}", file=sys.stderr)
        return 2

    async def run() -> int:
        try:
            url = await tunnel.start()
        except Exception as exc:  # the connector raises on timeout / exit
            print(f"DEAD: tunnel did not come up: {exc}", file=sys.stderr)
            return 2
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps({
            "pid": os.getpid(),
            "cloudflared_pid": tunnel._process.pid if tunnel._process else None,
            "url": url, "port": args.port, "host": args.host,
            "started": time.time(),
        }), encoding="utf-8")
        print(url, flush=True)
        if args.once:
            await tunnel.stop()
            return 0
        try:
            while tunnel.is_connected:
                await asyncio.sleep(1)
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("stopping", file=sys.stderr)
        finally:
            await tunnel.stop()
            _clear_state()
        return 0

    try:
        return asyncio.run(run())
    except KeyboardInterrupt:
        return 0


def cmd_status(_args) -> int:
    st = _read_state()
    if not st:
        print("no tunnel recorded")
        return 1
    alive = _pid_alive(int(st.get("pid") or 0))
    print(json.dumps({**st, "alive": alive}, indent=2))
    return 0 if alive else 1


def cmd_down(_args) -> int:
    st = _read_state()
    if not st:
        print("no tunnel recorded")
        return 1
    stopped = False
    for key in ("cloudflared_pid", "pid"):
        pid = int(st.get(key) or 0)
        if pid and pid != os.getpid() and _pid_alive(pid):
            try:
                if sys.platform == "win32":
                    import subprocess

                    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                                   capture_output=True, check=False)
                else:
                    os.kill(pid, signal.SIGTERM)
                stopped = True
            except OSError as exc:
                print(f"could not stop pid {pid}: {exc}", file=sys.stderr)
    _clear_state()
    print("stopped" if stopped else "nothing was running; state cleared")
    return 0 if stopped else 1


def main(argv: list[str] | None = None) -> int:
    """Entry point for the awtunnel CLI."""
    # GENERATED doctor intercept (gen_aw_doctor.py) -- do not edit
    _dv = locals().get("argv")
    if (_dv if _dv is not None else __import__("sys").argv[1:])[:1] == ["doctor"]:
        from ._doctor import report
        return report()
    # GENERATED repo-state intercept (gen_aw_doctor.py) -- do not edit
    try:
        from awgit import state as _aw_state
    except Exception:
        _aw_state = None
    if _aw_state is not None:
        _sv = locals().get("argv")
        if _aw_state.cli_banner(_sv if _sv is not None else __import__("sys").argv[1:]):
            return 0
    ap = argparse.ArgumentParser(
        prog="awtunnel",
        description=__doc__,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # validate subcommand
    v = sub.add_parser("validate", help="validate a rule set")
    v.add_argument("rules", help="path to rules file (.json or .yaml)")
    v.add_argument("--json", action="store_true", help="output results as JSON")
    v.add_argument("--from-cloudflared", action="store_true",
                   help="the file is a tunnel-routes.yaml / cloudflared config "
                        "(service: -> origin:, no path -> ^/, built-ins dropped)")
    v.add_argument("--no-resolve", action="store_true",
                   help="static only: do not ask the resolver about origin names")

    for verb in ("up", "expose"):
        u = sub.add_parser(verb, help="give one local port a public address")
        u.add_argument("--port", type=int, required=True)
        u.add_argument("--host", default="localhost")
        u.add_argument("--protocol", default="http", choices=["http", "https"])
        u.add_argument("--name", default=None, help="named tunnel (needs cloudflared login)")
        u.add_argument("--hostname", default=None, help="custom hostname for a named tunnel")
        u.add_argument("--once", action="store_true",
                       help="print the URL and take the tunnel down again (a smoke test)")
    sub.add_parser("status", help="is the tunnel `up` recorded still alive")
    sub.add_parser("down", help="take the recorded tunnel away again")

    # check subcommand
    c = sub.add_parser("check", help="check if a route exists")
    c.add_argument("rules", help="path to rules file")
    c.add_argument("hostname", help="hostname to match")
    c.add_argument("path", help="path pattern to match")

    args = ap.parse_args(argv)

    if args.cmd in ("up", "expose"):
        return cmd_up(args)
    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "down":
        return cmd_down(args)

    if args.cmd == "validate":
        if not Path(args.rules).is_file():
            print(f"DEAD: no such rules file: {args.rules}", file=sys.stderr)
            return 2

        rules = load_rules(args.rules, cloudflared=args.from_cloudflared)
        if not rules:
            # load_rules already printed an error.
            return 2

        result = validate_rules(rules, resolve=not args.no_resolve)
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
