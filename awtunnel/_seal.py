"""Optional fail-closed Ed25519 seal verification for route/ingress files.

``awtunnel`` has zero required runtime dependencies. When neither an adjacent
``awseal.json`` nor an expected publisher public key is present, validation
proceeds normally on the unsealed route file. Whenever an adjacent
``awseal.json`` or ``--expect-key`` / ``AWTUNNEL_EXPECT_KEY`` is present,
verification is strictly fail-closed: missing ``awseal`` exits 2, while
tampered bytes, missing entries, malformed seals, or untrusted keys exit 1.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

SEAL_FILENAME = "awseal.json"
EXPECT_KEY_ENV = "AWTUNNEL_EXPECT_KEY"


def _verify_files_compat(
    seal: Any,
    files: dict[str, str],
    *,
    expect_key: str | None,
    load_public_key: Any,
    seal_canonical: Any,
    tree_digest: Any,
    seal_diff: Any,
) -> dict[str, Any]:
    """Verify ``seal`` against ``files`` using ``awseal >= 0.1.0`` primitives."""
    from cryptography.exceptions import InvalidSignature

    result: dict[str, Any] = {
        "subject": seal.subject,
        "created": seal.created,
        "public_key": seal.public_key,
        "signature_ok": False,
        "content_ok": False,
        "key_trusted": None,
        "diff": {"added": [], "removed": [], "modified": []},
    }
    pub = load_public_key(seal.public_key)
    try:
        pub.verify(bytes.fromhex(seal.signature), seal_canonical(seal.payload()))
        result["signature_ok"] = True
    except (InvalidSignature, ValueError, TypeError):
        result["signature_ok"] = False
    actual = {str(k): str(v) for k, v in dict(files or {}).items()}
    result["content_ok"] = (
        tree_digest(actual) == seal.tree_digest
        and tree_digest(seal.files) == seal.tree_digest
    )
    result["diff"] = seal_diff(seal.files, actual)
    if expect_key is not None:
        result["key_trusted"] = (
            str(seal.public_key).strip().lower() == expect_key.strip().lower()
        )
    result["ok"] = bool(
        result["signature_ok"]
        and result["content_ok"]
        and (result["key_trusted"] is not False)
    )
    return result


def verify_rules_seal(rules_path: Path, *, expect_key: str = "") -> tuple[int, str]:
    """Verify ``rules_path`` against adjacent ``awseal.json`` when sealed or keyed.

    Returns ``(exit_code, detail)`` where ``0`` means unsealed/verified,
    ``1`` means verification failed, and ``2`` means verification could not be
    judged (e.g. ``awseal`` not installed or rules file missing).
    """
    key = (expect_key or os.environ.get(EXPECT_KEY_ENV) or "").strip()
    seal_file = rules_path.parent / SEAL_FILENAME
    if not seal_file.is_file() and not key:
        return 0, "unsealed"

    if not rules_path.is_file():
        return 2, f"rules file not found: {rules_path}"

    try:
        import awseal as awseal_mod
        from awseal import SealError, load, load_public_key, tree_digest
        from awseal import diff as seal_diff
        from awseal.seal import canonical as seal_canonical
    except ImportError:
        return 2, "awseal is required to verify a sealed route file or --expect-key"

    try:
        if key:
            load_public_key(key)
        seal = load(rules_path.parent)
    except SealError as exc:
        return 1, f"seal check failed for {rules_path.name}: {exc}"

    if rules_path.name not in seal.files:
        return 1, f"{rules_path.name} is not covered by {seal_file}"

    try:
        raw = rules_path.read_bytes()
    except OSError as exc:
        return 2, f"cannot read {rules_path}: {exc}"

    digest = hashlib.sha256(raw).hexdigest()
    check_files = dict(seal.files)
    check_files[rules_path.name] = digest
    verify_fn = getattr(awseal_mod, "verify_files", None)
    try:
        if callable(verify_fn):
            res = verify_fn(seal, check_files, expect_key=key or None)
        else:
            res = _verify_files_compat(
                seal,
                check_files,
                expect_key=key or None,
                load_public_key=load_public_key,
                seal_canonical=seal_canonical,
                tree_digest=tree_digest,
                seal_diff=seal_diff,
            )
    except SealError as exc:
        return 1, f"seal verification failed for {rules_path.name}: {exc}"

    if (
        not res.get("ok")
        or not res.get("signature_ok")
        or not res.get("content_ok")
        or (key and res.get("key_trusted") is not True)
        or seal.files.get(rules_path.name) != digest
    ):
        return 1, (
            f"seal verification failed for {rules_path.name} "
            f"(signature_ok={res.get('signature_ok')}, "
            f"content_ok={res.get('content_ok')}, "
            f"key_trusted={res.get('key_trusted')})"
        )

    return 0, f"verified (key={seal.public_key[:12]}...)"
