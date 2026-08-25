# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Where a machine can hold a small secret for itself, on any OS it runs on.

Optional companion to `passbook_vault.py`, and used by exactly one thing: the
**device factor**, which lets a headless job open the vault without a human.

## Read this before you use it

Everything here hands a key to the operating system's own store, and every one
of those stores answers to *your user account* rather than to a particular
program. So a device factor means: anything running as you can open the vault.

That is the property `passbook_vault` exists to remove, which is why this is
opt-in, never the default, and labelled as a cost everywhere it is offered. It
buys one thing — a watchdog that survives a reboot without someone typing a
password — and it is worth that only when you have decided it is.

## The backends

  macOS            `security` generic passwords. No entitlement needed, because
                   there is deliberately no biometric access control on the
                   item; a guarded item requires a signed app, and this module
                   runs from a plain interpreter.
  Windows          DPAPI (`CryptProtectData`), user-scoped, blob on disk. The
                   OS ties it to the account, so a copied file is inert on any
                   other machine or user.
  Linux            `secret-tool`, when libsecret is installed and a Secret
                   Service is running. Absent on a headless server, which is
                   reported rather than papered over.
  anything else    nothing, honestly. `backend()` returns "" and the vault
                   falls back to asking for a password, which always works.

There is no file-with-a-hardcoded-key fallback. A store that pretends to protect
a key while keeping it next to the lock would make `status` a lie, and the
honest answer — "this machine cannot do that, type your password" — is a better
outcome than a fake one.
"""

from __future__ import annotations

import base64
import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

__all__ = ["available", "backend", "describe", "fetch", "forget", "store"]

SERVICE = "hive-env-vault"
_TIMEOUT = 10


def _account() -> str:
    return os.environ.get("USER") or os.environ.get("USERNAME") or "hive"


def backend() -> str:
    """Which store this machine actually has. "" means none."""
    override = os.environ.get("PASSBOOK_KEYSTORE", "").strip().lower()
    if override:
        return "" if override in {"none", "off", "0"} else override
    if sys.platform == "darwin":
        return "keychain" if Path("/usr/bin/security").exists() else ""
    if sys.platform == "win32":
        return "dpapi"
    if sys.platform.startswith("linux"):
        return "secret-service" if shutil.which("secret-tool") else ""
    return ""


def available() -> bool:
    return bool(backend())


def describe() -> str:
    return {
        "keychain": "the macOS keychain",
        "dpapi": "Windows DPAPI, tied to this user account",
        "secret-service": "the Linux Secret Service (libsecret)",
    }.get(backend(), "no OS keystore on this platform")


# ── macOS ──────────────────────────────────────────────────────────────────


def _keychain_store(name: str, value: str) -> dict[str, Any]:
    done = subprocess.run(
        ["/usr/bin/security", "add-generic-password", "-U",
         "-s", SERVICE, "-a", f"{_account()}:{name}", "-w", value],
        check=False, capture_output=True, timeout=_TIMEOUT)
    if done.returncode != 0:
        return {"ok": False, "backend": "keychain", "detail": "the keychain refused the item"}
    return {"ok": True, "backend": "keychain", "detail": "stored in the macOS keychain"}


def _keychain_fetch(name: str) -> str:
    done = subprocess.run(
        ["/usr/bin/security", "find-generic-password",
         "-s", SERVICE, "-a", f"{_account()}:{name}", "-w"],
        check=False, capture_output=True, timeout=_TIMEOUT)
    return done.stdout.strip().decode("ascii", "replace") if done.returncode == 0 else ""


def _keychain_forget(name: str) -> bool:
    done = subprocess.run(
        ["/usr/bin/security", "delete-generic-password",
         "-s", SERVICE, "-a", f"{_account()}:{name}"],
        check=False, capture_output=True, timeout=_TIMEOUT)
    return done.returncode == 0


# ── Windows ────────────────────────────────────────────────────────────────


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi_path(name: str) -> Path:
    import passbook

    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
    return passbook.root() / "keystore" / f"{safe}.dpapi"


def _dpapi_call(fn, payload: bytes) -> bytes | None:
    source = _Blob(len(payload), ctypes.cast(ctypes.create_string_buffer(payload, len(payload)),
                                             ctypes.POINTER(ctypes.c_char)))
    out = _Blob()
    entropy = _Blob(len(SERVICE), ctypes.cast(ctypes.create_string_buffer(SERVICE.encode(), len(SERVICE)),
                                              ctypes.POINTER(ctypes.c_char)))
    ok = fn(ctypes.byref(source), None, ctypes.byref(entropy), None, None, 0, ctypes.byref(out))
    if not ok:
        return None
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)  # type: ignore[attr-defined]


def _dpapi_store(name: str, value: str) -> dict[str, Any]:
    protected = _dpapi_call(ctypes.windll.crypt32.CryptProtectData, value.encode("utf-8"))  # type: ignore[attr-defined]
    if protected is None:
        return {"ok": False, "backend": "dpapi", "detail": "DPAPI refused to protect the value"}
    target = _dpapi_path(name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(protected)
    return {"ok": True, "backend": "dpapi", "detail": "protected by DPAPI for this account"}


def _dpapi_fetch(name: str) -> str:
    try:
        protected = _dpapi_path(name).read_bytes()
    except OSError:
        return ""
    opened = _dpapi_call(ctypes.windll.crypt32.CryptUnprotectData, protected)  # type: ignore[attr-defined]
    return opened.decode("utf-8") if opened else ""


def _dpapi_forget(name: str) -> bool:
    try:
        _dpapi_path(name).unlink()
        return True
    except OSError:
        return False


# ── Linux ──────────────────────────────────────────────────────────────────


def _secret_tool_store(name: str, value: str) -> dict[str, Any]:
    done = subprocess.run(
        ["secret-tool", "store", "--label", f"PassBook {name}", "service", SERVICE, "key", name],
        input=value.encode("utf-8"), check=False, capture_output=True, timeout=_TIMEOUT)
    if done.returncode != 0:
        return {"ok": False, "backend": "secret-service",
                "detail": "no Secret Service is running to hold the value"}
    return {"ok": True, "backend": "secret-service", "detail": "stored in the Secret Service"}


def _secret_tool_fetch(name: str) -> str:
    done = subprocess.run(
        ["secret-tool", "lookup", "service", SERVICE, "key", name],
        check=False, capture_output=True, timeout=_TIMEOUT)
    return done.stdout.decode("utf-8", "replace").strip() if done.returncode == 0 else ""


def _secret_tool_forget(name: str) -> bool:
    done = subprocess.run(
        ["secret-tool", "clear", "service", SERVICE, "key", name],
        check=False, capture_output=True, timeout=_TIMEOUT)
    return done.returncode == 0


# ── the one door each ──────────────────────────────────────────────────────


def store(name: str, value: str) -> dict[str, Any]:
    """Hold a small secret for this machine. Never raises; reports instead."""
    try:
        kind = backend()
        if kind == "keychain":
            return _keychain_store(name, value)
        if kind == "dpapi":
            return _dpapi_store(name, value)
        if kind == "secret-service":
            return _secret_tool_store(name, value)
        return {"ok": False, "backend": "", "detail": describe()}
    except Exception as error:  # noqa: BLE001 — a keystore must not take the caller down
        return {"ok": False, "backend": backend(), "detail": f"the keystore failed: {error}"}


def fetch(name: str) -> str:
    """What this machine is holding under that name. "" when it holds nothing."""
    try:
        kind = backend()
        if kind == "keychain":
            return _keychain_fetch(name)
        if kind == "dpapi":
            return _dpapi_fetch(name)
        if kind == "secret-service":
            return _secret_tool_fetch(name)
        return ""
    except Exception:  # noqa: BLE001 — absent and broken are the same answer here
        return ""


def forget(name: str) -> bool:
    try:
        kind = backend()
        if kind == "keychain":
            return _keychain_forget(name)
        if kind == "dpapi":
            return _dpapi_forget(name)
        if kind == "secret-service":
            return _secret_tool_forget(name)
        return False
    except Exception:  # noqa: BLE001
        return False
