"""A stdlib reader for the ONE YAML shape route files use.

Not PyYAML on purpose: ``dependencies = []`` is a decision ("a validator you
cannot run without installing something is one nobody runs during an
incident"). If PyYAML happens to be importable it is used, because it is
correct for everything; otherwise this reader handles exactly the grammar
that ``tunnel-routes.yaml``, ``tunnel-ingress.yaml`` and
``cloudflared-config.yml`` are written in:

* top-level ``key:`` mappings and ``key: value`` scalars
* block lists of mappings (``- hostname: x`` with indented continuation keys)
* one level of nested mapping inside a list item (``originRequest:``)
* ``#`` comments, blank lines, single/double-quoted scalars, ``true``/``false``
  /``null``/ints, and ``>-`` / ``|`` folded block scalars (kept as text)

Anything outside that grammar raises :class:`YamlShapeError` naming the line,
never guesses -- a wrong parse of a routing plane is worse than no parse.
"""

from __future__ import annotations

import re
from typing import Any


class YamlShapeError(ValueError):
    """The text is outside the route-file grammar this reader accepts."""


_KV = re.compile(r"^(?P<key>[A-Za-z0-9_.*-]+|'[^']*'|\"[^\"]*\")\s*:(?:\s+(?P<val>.*))?$")


def _scalar(raw: str) -> Any:
    v = raw.strip()
    # a trailing comment on an UNQUOTED scalar goes first, or `false  # why`
    # reads as the string "false" -- measured against tunnel-routes.yaml.
    if v[:1] in ('"', "'"):
        q = v[0]
        end = v.find(q, 1)
        if end > 0:                      # quoted: everything after the close is comment
            return v[1:end]
    elif " #" in v:
        v = v.split(" #", 1)[0].rstrip()
    if v == "" or v in ("null", "~"):
        return None
    if v in ("true", "True"):
        return True
    if v in ("false", "False"):
        return False
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    if v in ("[]",):
        return []
    if v in ("{}",):
        return {}
    return v


def _strip(line: str) -> str:
    """Drop a full-line comment; keep indentation of real lines."""
    s = line.rstrip("\r\n")
    if s.strip().startswith("#"):
        return ""
    return s


def load(text: str) -> dict[str, Any]:
    """Parse ``text`` into a dict. Prefers PyYAML when importable."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return _load_stdlib(text)          # the whole point of this module
    data = yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise YamlShapeError("top level is not a mapping")
    return data


def _load_stdlib(text: str) -> dict[str, Any]:
    lines = [_strip(x) for x in text.splitlines()]
    root: dict[str, Any] = {}
    i = 0
    n = len(lines)

    def indent(s: str) -> int:
        return len(s) - len(s.lstrip(" "))

    def read_block_scalar(start: int, base_indent: int, style: str) -> tuple[str, int]:
        """`|` keeps newlines, `>` folds them; a trailing `-` clips the final newline."""
        buf: list[str] = []
        j = start
        inner = None
        while j < n:
            s = lines[j]
            if s.strip() == "":
                buf.append("")
                j += 1
                continue
            if indent(s) <= base_indent:
                break
            if inner is None:
                inner = indent(s)
            buf.append(s[inner:])
            j += 1
        while buf and buf[-1] == "":
            buf.pop()
        if style.startswith("|"):
            text = "\n".join(buf)
        else:
            text = ""
            for x in buf:
                if x == "":
                    text += "\n"
                elif text and not text.endswith("\n"):
                    text += " " + x
                else:
                    text += x
        if not style.endswith("-"):
            text += "\n"
        return text, j

    def read_mapping(start: int, base_indent: int) -> tuple[dict[str, Any], int]:
        out: dict[str, Any] = {}
        j = start
        while j < n:
            s = lines[j]
            if s.strip() == "":
                j += 1
                continue
            ind = indent(s)
            if ind < base_indent:
                break
            if ind > base_indent:
                raise YamlShapeError(f"line {j + 1}: unexpected indent")
            body = s.strip()
            if body.startswith("- "):
                break
            m = _KV.match(body)
            if not m:
                raise YamlShapeError(f"line {j + 1}: not `key: value`: {body!r}")
            key = _scalar(m.group("key"))
            val = m.group("val")
            if val is None or val.strip() == "":
                # nested: list, mapping, or empty
                k = j + 1
                while k < n and lines[k].strip() == "":
                    k += 1
                # a block list may sit at the SAME indent as its key (PyYAML's
                # own dump style, which the generated route files use)
                if k < n and (indent(lines[k]) > ind
                              or (indent(lines[k]) == ind and lines[k].strip().startswith("- "))):
                    if lines[k].strip().startswith("- "):
                        out[key], j = read_list(k, indent(lines[k]))
                    else:
                        out[key], j = read_mapping(k, indent(lines[k]))
                    continue
                out[key] = None
                j += 1
                continue
            v = val.strip()
            if v in (">-", ">", "|", "|-"):
                out[key], j = read_block_scalar(j + 1, ind, v)
                continue
            out[key] = _scalar(v)
            j += 1
        return out, j

    def read_list(start: int, base_indent: int) -> tuple[list[Any], int]:
        out: list[Any] = []
        j = start
        while j < n:
            s = lines[j]
            if s.strip() == "":
                j += 1
                continue
            ind = indent(s)
            if ind < base_indent:
                break
            if ind > base_indent:
                raise YamlShapeError(f"line {j + 1}: unexpected indent in list")
            body = s.strip()
            if not body.startswith("- "):
                break
            first = body[2:].strip()
            m = _KV.match(first)
            if m:
                # a mapping item: rewrite the first key onto its own virtual line
                item_indent = ind + 2
                lines[j] = " " * item_indent + first
                item, j = read_mapping(j, item_indent)
                out.append(item)
            else:
                out.append(_scalar(first))
                j += 1
        return out, j

    while i < n and lines[i].strip() == "":
        i += 1
    if i >= n:
        return root
    if indent(lines[i]) != 0:
        raise YamlShapeError(f"line {i + 1}: top level must start at column 0")
    root, i = read_mapping(i, 0)
    while i < n and lines[i].strip() == "":
        i += 1
    if i < n:
        raise YamlShapeError(f"line {i + 1}: trailing content outside the top-level mapping")
    return root
