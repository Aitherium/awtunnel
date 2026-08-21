# awtunnel

Ingress rule validation that **catches scheme mismatches** and **detects shadowing**.

```bash
pip install awtunnel
```

```python
from awtunnel import validate_rules

rules = [
    {"hostname": "api.aitherium.com", "path": "^/v1", "origin": "http://gateway:8080"},
    {"hostname": "api.aitherium.com", "path": "^/auth", "origin": "https://identity:8115"},
]

result = validate_rules(rules)
if not result.ok:
    for finding in result.findings:
        print(finding)
```

```bash
awtunnel validate rules.yaml    # 0 ok · 1 real problem · 2 could not judge
awtunnel check   rules.yaml hostname path  # check if a specific route exists
```

## The bug this package is shaped around

Tunnel connectors are unforgiving: a rule saying `http://security-core:8115` while that
service serves **TLS** fails as **"origin unreachable"** rather than **"origin serves
TLS, rule is wrong"**. The symptom names the innocent service, costs a session debugging
the healthy container, and is completely silent to every configuration tool.

Three related traps, all invisible to config alone:

1. **Scheme mismatch**: `http://` into a TLS listener closes the socket immediately.
   The connector reports "Unable to reach the origin", but the origin is running and
   healthy. Nothing in the config says which is wrong.

2. **Duplicate schemes on same host:port**: One rule says `http://security-core:8115`,
   another says `https://security-core:8115`. They are different rules, both valid
   config, and one or both will fail at runtime depending on which the connector tries
   first.

3. **Shadowing**: A broad hostname pattern (`*.aitherium.com`) or a short path prefix
   (e.g., `^/api`) can match before a more specific rule. The more-specific rule's
   route is unreachable, and the request lands on the wrong origin. No error, no
   rejected config — the path works, just on the wrong host.

## What this package proves

`validate_rules()` reads a rule set and asserts three invariants:

- **No scheme conflicts**: the same `(host, port)` pair appears in at most one rule
- **No unresolvable hostnames**: every `host` either is an IP or resolves via DNS
- **No shadowing**: rule ordering cannot hide a later rule behind an earlier one

Each is its own finding, with the rule and the conflicting peer named. Because during
an incident they call for different responses:

| finding | fix |
|---|---|
| **SCHEME CONFLICT** | pick one scheme (likely TLS), remove the other rule |
| **UNRESOLVABLE HOST** | fix the hostname or move it behind a load balancer that does resolve |
| **SHADOWED** | reorder the rules, or narrow the pattern |

## What it does not do

This validates the **rule set alone**, not the **actual services**. A rule can pass
validation and still fail at runtime if the origin is down, the scheme is right but
the port is wrong, or the service binds a different interface.

- `validate_rules()` does NOT reach out to origins — that is runtime work.
- It does NOT check whether a hostname actually resolves (the resolver might not
  yet exist when rules are written).
- It does NOT verify that the origin actually listens on the declared scheme and port.

A rule that passes validation may still fail to serve requests. To get a real guarantee,
test the rule **live**: send a request through the connector and verify it reaches the
origin you intended.

## Design notes

- **No dependencies.** Config validation that needs an install before it can run is
  one nobody runs during an incident.
- **Findings name the rule.** A validator that reports "there is a problem" without
  saying which rule is shaped around the assumption that all rules are identical,
  which they are not.
- **Order matters.** `validate_rules()` checks shadowing by rule position, because
  routing is positional — the first matching rule wins. A rule that is valid in
  position 3 might be shadowed if moved to position 5.
- **Hostname patterns are literal.** Glob patterns and regex are interpreted by the
  connector, not this package. The validator does not parse them — it reads them as
  literal strings for collision detection. If two rules have the same hostname string,
  they conflict; if one is `*.aitherium.com` and another is `api.aitherium.com`, the
  validator does not know whether they overlap.

## Tests

Every finding has a test that produces it, and the suite includes both negative cases
(rules that should pass) and positive ones (rules that should fail). Tests run in
both directions: a suite that only checks for problems passes trivially if validation
always fails, so both "rule is valid" and "rule is invalid" assertions are present.

```bash
pip install -e ".[dev]" && pytest
```

## Where it sits

In a larger system, ingress rules live in multiple places with conflicting truths:

- `config files` (static YAML the owner wrote)
- `the connector's live config` (what Cloudflare/nginx is actually using right now)
- `the deployed services` (what origins are really listening)

This package validates the **config files**. To get a complete picture:

1. Validate the source config → `awtunnel` (this package)
2. Compare config to live connector → edge-specific tool (e.g., `cf_dns_list`)
3. Test the connector output → network tool (e.g., curl with the right User-Agent)

Only step 1 is portable. Steps 2 and 3 are connector-specific and belong elsewhere.

Apache-2.0.
