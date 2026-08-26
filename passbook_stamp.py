# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""PassBook access stamps — a tamper-evident record of who read what.

Optional companion to `passbook.py`. The standard works without it; this adds
the audit half, and it is deliberately a separate file so a project can adopt
the store without adopting the ledger.

## What a stamp is, and is not

A stamp records that a credential was **read**, by **whom**, **when**, and
**which key names** — never a value. Rows are hash-chained, so a row cannot be
edited, removed, or backdated without breaking every row after it.

That makes this **tamper-evident, not tamper-proof**. A stamp does not stop an
access; it makes one impossible to hide. Prevention needs a broker that can
refuse — the stamp is what tells you it refused, or that it should have.

## Why this shape

HivemindOS already keeps hash-chained GitLawb proof ledgers for agent memory and
company governance (`src/lib/services/gitlawb/proof-chain.ts`). This is the same
chain, byte for byte: the same canonical JSON, the same `sha256:` digests, the
same `previousProofHash` / `proofHash` fields. So GitLawb's own verifier reads
these rows, and a credential access sits in the same evidence model as every
other proof — one ledger format, one story about provenance.
"""

from __future__ import annotations

import hashlib
import json
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

try:  # POSIX advisory locking; absent on Windows, where we fall back below.
    import fcntl
except ImportError:  # pragma: no cover — exercised on Windows only
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "PROOF_FILENAME",
    "ChainBreak",
    "canonical_json",
    "history_for_key",
    "proof_sha256",
    "usage_by_key",
    "read_stamps",
    "stamp",
    "verify_chain",
]

PROOF_FILENAME = "credential-access-proofs.jsonl"
PROOF_KIND = "credential-access"
SPEC_VERSION = 1

# Reading is the interesting one; the rest are here so a linked machine, a
# rotated key, or a decision about access leaves a row too.
#
# An op missing from this set raises, and `recorder()` swallows the raise — so
# forgetting to add one here does not fail loudly, it just quietly drops the
# event. That is exactly what happened to `ask`, `unlock` and `lock` when the
# access modes landed: the decisions the record exists to show were the ones
# not being written down. Add the op here in the same change that starts
# emitting it.
OPERATIONS = frozenset({
    "read", "write", "link", "unlink", "provision", "denied",
    "ask", "approve", "unlock", "lock", "reveal",
    # Opening and closing the vault. A refused sign-in is the row an intrusion
    # would show up in first, so it matters more than most of the ones above.
    "signin", "signout",
    # An OAuth grant renewed on the caller's behalf. Worth its own row: a
    # refresh that starts failing is the earliest sign a sign-in has died.
    "refresh",
    # A whole store leaving or entering the machine. The single most
    # consequential thing anyone can do here, and the row an audit looks for
    # first, so it is never folded into "read".
    "export", "import",
    # A recovery code minted. The code itself is never written down here — only
    # that one now exists, and when, because a second one appearing is
    # something the owner should be able to notice.
    "recovery",
    # Encrypting or decrypting the whole store.
    #
    # `unseal` is the most consequential operation in this file and it was the
    # one operation the record could not hold. A background sync decrypted 192
    # keys over about ninety minutes and left no row anywhere; the only reason
    # anyone noticed was a person wondering why Reveal still worked after they
    # pressed Lock. Every smaller act was recorded and the largest was not.
    "seal", "unseal",
})


def proof_path(root: Path | None = None) -> Path:
    if root is not None:
        return Path(root) / PROOF_FILENAME
    import passbook

    return passbook.root() / PROOF_FILENAME


# ── the chain, wire-compatible with proof-chain.ts ─────────────────────────


def canonical_json(value: Any) -> str:
    """Deterministic JSON, matching GitLawb's `proofCanonicalJson` exactly.

    Sorted keys, `None`-valued keys dropped, no whitespace, and non-ASCII left
    unescaped — that last one is what JavaScript's `JSON.stringify` does, and a
    Python default of `ensure_ascii=True` would silently produce a different
    digest for the same row.
    """
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if not isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    entries = sorted((key, item) for key, item in value.items() if item is not None)
    body = ",".join(
        f"{json.dumps(key, ensure_ascii=False)}:{canonical_json(item)}" for key, item in entries
    )
    return "{" + body + "}"


def proof_sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _previous_hash(path: Path) -> str | None:
    """The tail row's `proofHash` — what the next row must chain onto."""
    try:
        lines = [line for line in path.read_text(encoding="utf-8").strip().split("\n") if line]
    except (OSError, UnicodeDecodeError):
        return None
    if not lines:
        return None
    last = lines[-1]
    try:
        parsed = json.loads(last)
    except json.JSONDecodeError:
        # A torn tail still has to be chained onto, or the next row would claim
        # the row *before* it as its predecessor and the damage would vanish.
        return proof_sha256(last)
    found = parsed.get("proofHash")
    if isinstance(found, str):
        return found
    metadata = parsed.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("proofHash"), str):
        return metadata["proofHash"]
    return proof_sha256(last)


class _FileLock:
    """A cross-process lock so concurrent writers chain in a line, not a fork."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._handle = None

    def __enter__(self) -> "_FileLock":
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(self._path, "a+")  # noqa: SIM115 — released in __exit__
        if fcntl is not None:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._handle is None:
            return
        if fcntl is not None:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        self._handle.close()
        self._handle = None


# ── writing ────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _machine() -> str:
    """A stable, non-identifying name for this machine.

    The hostname itself can carry a person's name, so the row holds a digest of
    it. Two rows from the same machine match; nobody learns whose it is.
    """
    raw = f"{platform.system()}/{socket.gethostname()}"
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def stamp(
    *,
    op: str,
    keys: Iterable[str],
    app: str,
    workspace: str = "",
    actor_did: str = "",
    reason: str = "",
    granted: bool = True,
    root: Path | None = None,
) -> dict[str, Any]:
    """Append one access receipt and return it.

    Only key NAMES are recorded. There is no parameter that takes a value, which
    is the point: a ledger that could hold a secret would eventually hold one.
    """
    operation = str(op).strip().lower()
    if operation not in OPERATIONS:
        raise ValueError(f"op must be one of {', '.join(sorted(OPERATIONS))}")
    names = sorted({str(key).strip() for key in keys if str(key).strip()})

    path = proof_path(root)
    with _FileLock(path.with_suffix(path.suffix + ".lock")):
        previous = _previous_hash(path)
        row: dict[str, Any] = {
            "kind": PROOF_KIND,
            "specVersion": SPEC_VERSION,
            "at": _now(),
            "op": operation,
            "granted": bool(granted),
            "app": str(app).strip() or "unknown",
            "keys": names,
            "keyCount": len(names),
            "machine": _machine(),
            **({"workspace": workspace} if workspace else {}),
            **({"actorDid": actor_did} if actor_did else {}),
            **({"reason": str(reason)[:200]} if reason else {}),
            **({"previousProofHash": previous} if previous else {}),
        }
        row["proofHash"] = proof_sha256(canonical_json(row))
        line = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        _tighten(path)
    return row


def _tighten(path: Path) -> None:
    try:
        current = path.stat().st_mode & 0o777
        if current & ~0o600:
            path.chmod(current & 0o600)
    except OSError:
        pass


# ── reading and verifying ──────────────────────────────────────────────────


def read_stamps(*, limit: int = 200, root: Path | None = None) -> list[dict[str, Any]]:
    """The most recent receipts, newest last. Safe to show anyone."""
    path = proof_path(root)
    try:
        lines = [line for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]
    except (OSError, UnicodeDecodeError):
        return []
    rows = []
    for line in lines[-max(1, limit):]:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            rows.append({"kind": PROOF_KIND, "unreadable": True})
    return rows


def usage_by_key(*, root: Path | None = None, limit: int = 100000) -> dict[str, Any]:
    """When each key was last used, how often, and by what.

    Derived from the ledger rather than tracked separately, so it cannot drift
    from the record it summarises — and so a key that has never been read simply
    has no entry, rather than a zero that looks like data.
    """
    seen: dict[str, dict[str, Any]] = {}
    for row in read_stamps(limit=limit, root=root):
        at = row.get("at")
        app = str(row.get("app") or "")
        op = str(row.get("op") or "")
        for key in row.get("keys") or []:
            entry = seen.setdefault(str(key), {"count": 0, "last": "", "last_app": "", "last_op": "", "apps": []})
            entry["count"] += 1
            if app and app not in entry["apps"]:
                entry["apps"].append(app)
            # Rows are appended in order, so the last one wins without sorting.
            if at:
                entry["last"], entry["last_app"], entry["last_op"] = at, app, op
    return seen


def history_for_key(key: str, *, root: Path | None = None, limit: int = 200) -> list[dict[str, Any]]:
    """Every recorded event touching one key, newest last, with its proof.

    The hashes travel with the rows on purpose: a history a person cannot check
    is just a list, and the whole point of the chain is that this one can be.
    """
    name = str(key).strip()
    out = []
    for row in read_stamps(limit=100000, root=root):
        if name in (row.get("keys") or []):
            out.append({
                "at": row.get("at", ""),
                "app": row.get("app", ""),
                "op": row.get("op", ""),
                "granted": row.get("granted", True),
                "reason": row.get("reason", ""),
                "machine": row.get("machine", ""),
                "actor_did": row.get("actorDid", ""),
                "proof": row.get("proofHash", ""),
                "previous": row.get("previousProofHash", ""),
            })
    return out[-max(1, limit):]


class ChainBreak(dict):
    """One place the ledger stops adding up."""


def recompute_proof_hash(row: Mapping[str, Any]) -> str:
    return proof_sha256(canonical_json({key: value for key, value in row.items() if key != "proofHash"}))


def verify_chain(*, root: Path | None = None) -> dict[str, Any]:
    """Walk the ledger and report every break.

    A break means a row was edited, removed, reordered, or inserted — the three
    ways an access gets hidden. Nothing here can prove the ledger is *complete*
    (a writer that never stamped leaves no trace), only that what is written has
    not been altered since.
    """
    path = proof_path(root)
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {"ok": True, "rows": 0, "breaks": [], "detail": "No access ledger on this machine yet."}

    breaks: list[ChainBreak] = []
    expected_previous: str | None = None
    count = 0
    for index, line in enumerate((item for item in raw.split("\n") if item.strip()), start=1):
        count += 1
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            breaks.append(ChainBreak(row=index, reason="unreadable row"))
            expected_previous = proof_sha256(line)
            continue
        stated = row.get("previousProofHash")
        if expected_previous is not None and stated != expected_previous:
            breaks.append(ChainBreak(
                row=index,
                reason="row does not chain onto the one before it — a row was edited, removed or reordered",
            ))
        recomputed = recompute_proof_hash(row)
        if row.get("proofHash") != recomputed:
            breaks.append(ChainBreak(row=index, reason="row contents do not match its own hash"))
        expected_previous = row.get("proofHash") if isinstance(row.get("proofHash"), str) else recomputed
    return {
        "ok": not breaks,
        "rows": count,
        "breaks": breaks,
        "path": str(path),
        "detail": "Every access row chains onto the one before it."
        if not breaks
        else f"{len(breaks)} break(s) — the ledger has been altered since it was written.",
    }


# ── the hook passbook calls ────────────────────────────────────────────────


def recorder(app: str, *, workspace: str = "", actor_did: str = "") -> Callable[..., None]:
    """A stamping callback bound to one app, for `passbook.request(...)`.

    Stamping must never be able to fail a credential read — a ledger that can
    take the studio down is worse than no ledger. Failures are swallowed here on
    purpose; `verify_chain()` is what surfaces a ledger that stopped working.
    """

    def record(*, op: str, keys: Iterable[str], granted: bool = True, reason: str = "") -> None:
        try:
            stamp(
                op=op, keys=keys, app=app, workspace=workspace,
                actor_did=actor_did, reason=reason, granted=granted,
            )
        except Exception:  # noqa: BLE001 — never break a read to write a receipt
            pass

    return record
