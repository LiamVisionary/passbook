# SPDX-License-Identifier: Apache-2.0
"""Transactional metadata for managed applications. Never store credential values.

SQLite supplies cross-process serialization and crash recovery for grants,
approval challenges, and request idempotency. Vault material stays in the
existing encrypted store; this database contains public keys and safe metadata.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterator, Mapping

FILENAME = "passbook-integrations.sqlite3"
MAX_CLOCK_SKEW_MS = 120_000


class ManagedError(ValueError):
    def __init__(self, message: str, code: str = "invalid-request"):
        super().__init__(message)
        self.code = code


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def now_ms() -> int:
    return int(time.time() * 1000)


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def unb64(value: str) -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise ManagedError("The connection proof is invalid.", "invalid-proof") from exc


def identifier() -> str:
    return secrets.token_hex(16)


def installation_id(public_key: str) -> str:
    raw = unb64(public_key)
    if len(raw) != 32:
        raise ManagedError("The connection proof is invalid.", "invalid-proof")
    return hashlib.sha256(raw).hexdigest()


def signed_bytes(action: str, installation: str, issued_at: int, nonce: str, body_json: str) -> bytes:
    # Sign the original JSON text, not a reserialization: JS and Python differ
    # in number formatting. Only the parsed authenticated text may be executed.
    return canonical([1, action, installation, issued_at, nonce, body_json]).encode("utf-8")


def verified_body(envelope: Mapping[str, Any]) -> dict[str, Any]:
    raw = envelope.get("bodyJson")
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 48_000:
        raise ManagedError("The request is invalid.")
    try:
        body = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError) as exc:
        raise ManagedError("The request is invalid.") from exc
    if not isinstance(body, dict):
        raise ManagedError("The request is invalid.")
    return body


class Store:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.path = self.root / FILENAME

    @contextlib.contextmanager
    def transaction(self) -> Iterator["Transaction"]:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Refuse symlinks before SQLite gets an opportunity to follow one.
        if self.path.is_symlink():
            raise ManagedError("The connection records cannot be opened safely.", "storage-unavailable")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        conn = sqlite3.connect(str(self.path), timeout=20, isolation_level=None)
        try:
            conn.execute("PRAGMA busy_timeout=20000")
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT NOT NULL, "
                         "body TEXT NOT NULL, PRIMARY KEY(kind,id))")
            yield Transaction(conn)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()


class Transaction:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def get(self, kind: str, ident: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT body FROM records WHERE kind=? AND id=?", (kind, ident)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, kind: str, ident: str, value: Mapping[str, Any]) -> None:
        self.connection.execute("INSERT INTO records(kind,id,body) VALUES(?,?,?) "
                                "ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body", (kind, ident, canonical(value)))

    def delete(self, kind: str, ident: str) -> None:
        self.connection.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, ident))

    def all(self, kind: str) -> list[dict[str, Any]]:
        return [json.loads(row[0]) for row in self.connection.execute("SELECT body FROM records WHERE kind=?", (kind,))]


def verify(envelope: Mapping[str, Any], tx: Transaction) -> dict[str, Any]:
    ident = str(envelope.get("installationId") or "")
    binding = tx.get("binding", ident)
    if not binding or binding.get("revokedAt"):
        raise ManagedError("Connect PassBook to this app first.", "not-connected")
    return _verify_proof(envelope, tx, binding)


def _verify_proof(envelope: Mapping[str, Any], tx: Transaction, binding: Mapping[str, Any]) -> dict[str, Any]:
    """Verify a saved authority's exact proof without creating a live binding."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    ident = str(envelope.get("installationId") or "")
    if ident != binding.get("installationId"):
        raise ManagedError("The app could not verify this request.", "invalid-proof")
    issued = envelope.get("issuedAt")
    nonce = envelope.get("nonce")
    verified_body(envelope)
    if (not isinstance(issued, int) or isinstance(issued, bool)
            or abs(now_ms() - issued) > MAX_CLOCK_SKEW_MS
            or not isinstance(nonce, str) or not 16 <= len(nonce) <= 128):
        raise ManagedError("This connection proof has expired. Please try again.", "invalid-proof")
    try:
        Ed25519PublicKey.from_public_bytes(unb64(binding["publicKey"])).verify(
            unb64(str(envelope.get("signature") or "")),
            signed_bytes(str(envelope.get("action") or ""), ident, issued, nonce, envelope["bodyJson"]))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ManagedError("The app could not verify this request.", "invalid-proof") from exc
    replay_id = hashlib.sha256((ident + ":" + nonce).encode()).hexdigest()
    if tx.get("nonce", replay_id):
        raise ManagedError("This connection proof has already been used.", "replayed-proof")
    tx.put("nonce", replay_id, {"id": replay_id, "expires": issued + MAX_CLOCK_SKEW_MS})
    for item in tx.all("nonce"):
        if item["expires"] < now_ms():
            tx.delete("nonce", item["id"])
    return dict(binding)
