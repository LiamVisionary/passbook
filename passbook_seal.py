# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""PassBook encryption at rest — Tier 1.

Optional companion to `passbook.py`. The store keeps its shape and its key
NAMES in the clear; each value is replaced by a sealed blob whose key lives in
the operating system's own secret store.

## What this does and does not buy

It protects the store **at rest**: a stolen laptop, a Time Machine backup, a
home directory synced to a cloud drive, a `.env` accidentally copied into a
repo. Those are the ways credential files actually leak, and this closes them.

It does **not** protect against code running as you. Anything that can call this
module can unseal, exactly as anything that could read the plaintext file could
read it. That limit is inherent to a shared store and is not a bug to be fixed
here — it is what a broker (Tier 2) is for.

Being explicit matters: encryption at rest is often sold as if it stopped local
attackers. It does not. It stops the disk from being the leak.

## Shape

    OPENAI_API_KEY=hive-sealed:v1:<base64url nonce+ciphertext>

Key names stay readable, so `describe()`, the doctor, and a first-run screen all
work on a sealed store without unsealing anything. A mixed store — some sealed,
some not — reads correctly, so sealing can be adopted gradually and a hand-added
key keeps working until the next seal pass.
"""

from __future__ import annotations

import base64
import os
import platform
import subprocess
from pathlib import Path
from typing import Any, Mapping

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover — reported through `available()`
    AESGCM = None  # type: ignore[assignment]

__all__ = ["PREFIX", "available", "is_sealed", "seal_store", "status", "unseal_value", "unseal_all"]

PREFIX = "hive-sealed:v1:"
KEYCHAIN_SERVICE = "hive-env-encryption"


def available() -> tuple[bool, str]:
    """Can this machine seal? Returns (ok, why not)."""
    if AESGCM is None:
        return False, "the `cryptography` package is not installed"
    ok, detail = _keystore_available()
    return ok, detail


# ── the machine's own secret store ─────────────────────────────────────────


def _keystore_available() -> tuple[bool, str]:
    system = platform.system()
    # Report what `_key()` will actually use, in the same order it checks —
    # naming a keystore the seal did not come from would make an audit lie.
    if os.environ.get("HIVE_ENV_KEY"):
        return True, "HIVE_ENV_KEY"
    if system == "Darwin":
        if Path("/usr/bin/security").exists():
            return True, "macOS Keychain"
        return False, "the macOS `security` tool is missing"
    # Everywhere else the key rides in an environment variable the operator
    # supplies, rather than this module inventing a weaker store of its own.
    return False, (
        f"no supported OS key store on {system}; set HIVE_ENV_KEY to a base64 key, "
        "or leave the store unsealed"
    )


def _key(*, create: bool = True) -> bytes:
    """The sealing key, from the OS store. Never written to the hive root.

    Keeping the key somewhere the env file is not is the entire point: a copied
    `.env` is then inert.
    """
    supplied = os.environ.get("HIVE_ENV_KEY", "").strip()
    if supplied:
        return _decode_key(supplied)
    if platform.system() != "Darwin":
        raise RuntimeError("No OS key store available; set HIVE_ENV_KEY")

    account = os.environ.get("USER") or "hive"
    read = subprocess.run(
        ["/usr/bin/security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"],
        check=False, capture_output=True, timeout=10,
    )
    if read.returncode == 0 and read.stdout.strip():
        return _decode_key(read.stdout.strip().decode("ascii"))
    if not create:
        raise RuntimeError("The hive env sealing key is not in this machine's keychain")

    created = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    written = subprocess.run(
        ["/usr/bin/security", "add-generic-password", "-U",
         "-s", KEYCHAIN_SERVICE, "-a", account, "-w", created],
        check=False, capture_output=True, timeout=10,
    )
    if written.returncode != 0:
        raise RuntimeError("Could not store the hive env sealing key in the keychain")
    return _decode_key(created)


def _decode_key(value: str) -> bytes:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) < 32:
        raise RuntimeError("The hive env sealing key is too short")
    return raw[:32]


# ── sealing ────────────────────────────────────────────────────────────────


def is_sealed(value: str) -> bool:
    return str(value).startswith(PREFIX)


def seal_value(value: str, key: bytes | None = None) -> str:
    if AESGCM is None:
        raise RuntimeError("Sealing needs a runtime that setup has not provided yet — run `passbook install`")
    nonce = os.urandom(12)
    ciphertext = AESGCM(key or _key()).encrypt(nonce, value.encode("utf-8"), None)
    return PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def unseal_value(value: str, key: bytes | None = None) -> str:
    """Unseal one value; a value that was never sealed is returned unchanged.

    Passing plaintext through is what lets a store hold both kinds at once, so
    adopting sealing never has to be a flag day.
    """
    if not is_sealed(value):
        return value
    if AESGCM is None:
        raise RuntimeError("Reading a sealed store needs a runtime that setup has not provided yet — run `passbook install`")
    raw = base64.urlsafe_b64decode(value[len(PREFIX):] + "=" * (-len(value[len(PREFIX):]) % 4))
    return AESGCM(key or _key(create=False)).decrypt(raw[:12], raw[12:], None).decode("utf-8")


def unseal_all(values: Mapping[str, str]) -> dict[str, str]:
    """Unseal a whole mapping, leaving anything unsealed alone.

    One key read for the batch, and a value that cannot be unsealed is dropped
    rather than surfaced as ciphertext — handing a provider a sealed blob as if
    it were an API key produces a baffling 401 instead of an honest absence.
    """
    if not any(is_sealed(value) for value in values.values()):
        return dict(values)
    try:
        key = _key(create=False)
    except Exception:  # noqa: BLE001 — no key here: every sealed value stays shut
        return {name: value for name, value in values.items() if not is_sealed(value)}
    out: dict[str, str] = {}
    for name, value in values.items():
        try:
            out[name] = unseal_value(value, key)
        except Exception:  # noqa: BLE001 — a key sealed on another machine
            continue
    return out


def seal_store(*, root: Path | None = None) -> dict[str, Any]:
    """Seal every plaintext value in the store, in place.

    Rewrites through `passbook.set_values(overwrite=True)`, so comments,
    ordering, permissions and unrelated keys survive exactly as they were.
    """
    import passbook

    ok, detail = available()
    if not ok:
        return {"ok": False, "sealed": [], "detail": detail}

    path = passbook.env_path() if root is None else Path(root) / ".env"
    try:
        current = passbook.parse_env_text(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return {"ok": False, "sealed": [], "detail": f"No store to seal at {path}"}

    key = _key()
    plaintext = {name: value for name, value in current.items() if not is_sealed(value)}
    if not plaintext:
        return {"ok": True, "sealed": [], "already_sealed": sorted(current), "detail": "Every value is already sealed."}

    passbook.set_values({name: seal_value(value, key) for name, value in plaintext.items()}, overwrite=True)
    return {
        "ok": True,
        "sealed": sorted(plaintext),
        "already_sealed": sorted(name for name, value in current.items() if is_sealed(value)),
        "path": str(path),
        "detail": f"Sealed {len(plaintext)} value(s). The key is in {detail}, not in the store.",
    }


def status(*, root: Path | None = None) -> dict[str, Any]:
    """How much of the store is sealed. Names only."""
    import passbook

    ok, detail = available()
    path = passbook.env_path() if root is None else Path(root) / ".env"
    try:
        current = passbook.parse_env_text(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        current = {}
    sealed = sorted(name for name, value in current.items() if is_sealed(value))
    plain = sorted(name for name, value in current.items() if not is_sealed(value))
    return {
        "supported": ok,
        "keystore": detail,
        "sealed": sealed,
        "plaintext": plain,
        "fully_sealed": bool(current) and not plain,
        "detail": (
            "Every value is encrypted at rest." if current and not plain
            else f"{len(plain)} value(s) are still plaintext on disk." if current
            else "The store is empty."
        ),
    }
