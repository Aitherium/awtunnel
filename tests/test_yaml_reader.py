"""The stdlib route-file reader: exact on the grammar, loud outside it.

Measured 2026-09-19 against the four real route files with PyYAML as the
oracle: whole-document equality on all four. These cases are the shapes that
were WRONG on the way there -- each one is a bug the oracle caught.
"""

from __future__ import annotations

import pytest

from awtunnel import _yaml

DOC = """\
# header comment
tunnel:
  name: aitheros-demo
routes:
  - hostname: blog.example
    service: http://aitheros-veil:3000
    critical: true
    access:
      required: false  # a trailing comment used to make this the STRING "false"
      allowed_emails:
        - "*@aitherium.com"   # comment after a quoted scalar
    description: >-
      folded text
      on two lines
    notes: |
      literal one
      literal two
  - hostname: '*.example'
    service: http_status:404
ingress:
- hostname: same-indent.example
  service: http://x:1
  originRequest:
    noTLSVerify: true
- service: http_status:404
warp_routing: null
count: 42
"""


def test_reads_the_route_grammar_exactly():
    d = _yaml._load_stdlib(DOC)
    assert d["tunnel"] == {"name": "aitheros-demo"}
    r0, r1 = d["routes"]
    assert r0["critical"] is True
    assert r0["access"]["required"] is False
    assert r0["access"]["allowed_emails"] == ["*@aitherium.com"]
    assert r0["description"] == "folded text on two lines"
    assert r0["notes"] == "literal one\nliteral two\n"
    assert r1 == {"hostname": "*.example", "service": "http_status:404"}
    assert d["ingress"] == [
        {"hostname": "same-indent.example", "service": "http://x:1",
         "originRequest": {"noTLSVerify": True}},
        {"service": "http_status:404"},
    ]
    assert d["warp_routing"] is None
    assert d["count"] == 42


def test_agrees_with_pyyaml_when_it_is_there():
    yaml = pytest.importorskip("yaml")
    assert _yaml._load_stdlib(DOC) == yaml.safe_load(DOC)


def test_outside_the_grammar_is_loud_not_a_guess():
    with pytest.raises(_yaml.YamlShapeError):
        _yaml._load_stdlib("routes:\n  - hostname: a\n   service: bad-indent\n")
    with pytest.raises(_yaml.YamlShapeError):
        _yaml._load_stdlib("- a top-level list\n")
    with pytest.raises(_yaml.YamlShapeError):
        _yaml._load_stdlib("key: value\n  orphan: indent\n")


def test_empty_and_comment_only_documents_are_empty():
    assert _yaml._load_stdlib("") == {}
    assert _yaml._load_stdlib("# nothing\n\n") == {}
