# awtunnel for agents

Read this if you are an agent (or a human) editing this package. Short on
purpose: the commands, the traps that cost a session, and where the rest lives.
Nothing here is read at runtime — it is for you.

## What this is

PyPI distribution **`awtunnel`** (version in `pyproject.toml`), import package
`awtunnel`, Python >= 3.10. Reach a service that has no public address —
validate cloudflared ingress rules and give one local port a public URL.
Everything an agent runs is behind NAT on somebody's laptop, and every
workaround becomes permanent.

This repository is a **synced mirror** of the AitherOS monorepo (lane
`.github/workflows/sync-awtunnel.yml`). Hand edits made here are overwritten on
the next sync — change the source and let the lane publish.

## Build, test, verify

```bash
python -m pytest tests -q        # the suite: 36 tests, green at v0.2.1
pip install -e .                 # editable install for developing against it
```

The suite was run from a source checkout with no prior install. The publish
lane (`publish-brick.yml`) additionally builds the wheel, installs it and
imports it — a tree that tests green can still ship a broken wheel.

## Rules that keep this useful

- **A tunnel rule that shadows another is an outage with a tidy config.**
  `test_shadowing.py` and `test_scheme_conflict.py` exist so that two rules
  claiming overlapping ingress fails at validation time, not at 3am when
  traffic lands on the wrong service. A new rule shape lands with its
  collision case.
- **Resolution is where DNS lies.** `test_hostname_resolution.py` pins how
  hostnames resolve before a rule is accepted — do not loosen it to make an
  environment pass; that is the environment telling you something.
- **Validate before you edit; adopt before you write.** `test_from_cloudflared.py`
  pins importing an existing cloudflared config — the validator's first job is
  telling a stranger what their current file actually does.
- **The registry drives the public surface.** This repo's README header,
  `llms.txt` and `aither-manifest.json` are generated from the ecosystem
  registry (one yaml in the AitherOS monorepo) and rewritten on every sync.
  Change the registry; do not hand-edit the generated blocks.

## Read next

- `llms.txt` — the install/use card written for an agent to execute
- `README.md` — the human front door
- `docs/` — the generated docs site source
