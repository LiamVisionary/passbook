# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Standing access — one app keeps one key while the vault is locked.

Optional companion to `passbook_broker.py` and `passbook_vault.py`.

## The problem this exists for

A sealed store is dark until somebody signs in, and the broker forgets the data
key whenever it stops. So after a reboot, an update, or a crash, every service
that reads a credential at 3am fails with an auth error until a person comes
back — and the only existing remedy, `passbook vault --stay-open on`, answers it
by letting anything running as you open the WHOLE vault with nobody present.

Most services need one key, not three hundred. This lets the owner say exactly
that: "this app may use this key even while the vault is locked", and nothing
wider.

## How

When the owner grants it — with the vault password, because it widens access —
the key's current value is sealed again under a separate **escrow key** that
lives in the OS keystore, beside the device factor, and written to
`standing.json` in the store directory. That file holds, per workspace and per
key, the apps allowed to use it, the ciphertext, and a digest of the store's own
sealed value at the moment it was kept.

The broker is the only thing that opens it. When a request for a sealed key
cannot be answered because the vault is shut, and the asking app is on that
key's standing list, the broker opens the escrow copy instead — after the same
policy, guard and pin checks every other read goes through, so standing access
lifts the lock and nothing else.

## Staying current

The digest is what keeps an escrow copy from outliving the value it copied. If
the store's sealed value has changed since the key was kept — rotated here or
replicated from another machine — the escrow copy is refused rather than served,
because a rotated-away credential is the confusing failure: the service gets a
401 that names the wrong problem. The next time the vault is open and the key is
read, the broker re-seals the new value into the escrow on its own, and signing
in refreshes every kept key at once.

A key removed from the store stops being served immediately, whatever the
escrow still holds: the broker only ever opens a name the store still lists.

## The cost, stated plainly

The escrow key sits in the OS keystore, which answers to your user account, not
to a program. So anything running as you can fetch it and decrypt the kept keys
— exactly the property `passbook_keystore` warns about for the device factor.
What this narrows is the blast radius: only the keys somebody kept are exposed
that way, not the vault. And the app name the broker checks is a claim, as it is
everywhere in PassBook; `passbook pin` is what makes it a checked one.

The escrow is local to this machine. It never syncs; the escrow key would not
open it anywhere else.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover — reported through `available()`
    AESGCM = None  # type: ignore[assignment]

__all__ = [
    "FILENAME",
    "GENERIC_APPS",
    "StandingError",
    "available",
    "entries",
    "forget_key",
    "keep",
    "kept_names",
    "open_for",
    "refresh",
    "release",
]

FILENAME = "standing.json"
VERSION = 1
KEYSTORE_NAME = "standing-escrow"
#: An operator-supplied escrow key, base64, instead of the OS keystore — the
#: same escape `passbook_seal` offers as HIVE_ENV_KEY, for a machine with no
#: keystore and for tests, whose broker is another process.
KEY_ENV = "PASSBOOK_STANDING_KEY"
PREFIX = "hive-standing:v1:"

#: Names a caller gets when it did not say who it is. Keeping a key for one of
#: these would keep it for every unnamed `passbook run` on the machine, which is
#: the stay-open switch with extra steps.
GENERIC_APPS = frozenset({"", "unknown", "any", "*", "passbook", "passbook-run",
                          "passbook-cli", "passbook-get", "cli"})

_LOCK = threading.Lock()
_KEY_CACHE: dict[str, bytes] = {}


class StandingError(RuntimeError):
    """Anything standing access refuses to do. The message is for a person."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def available() -> tuple[bool, str]:
    """Can this machine hold standing access? Returns (ok, why not)."""
    if AESGCM is None:
        return False, "the `cryptography` package is not installed"
    if os.environ.get(KEY_ENV, "").strip():
        return True, KEY_ENV
    import passbook_keystore

    if not passbook_keystore.available():
        return False, passbook_keystore.describe()
    return True, passbook_keystore.describe()


def digest(stored: str) -> str:
    """A fingerprint of the store's own sealed value. Ciphertext, so not secret."""
    return hashlib.sha256(str(stored).encode("utf-8")).hexdigest()


# ── the file ───────────────────────────────────────────────────────────────


def _path(root: Path) -> Path:
    return Path(root) / FILENAME


def _read(root: Path) -> dict[str, Any]:
    try:
        data = json.loads(_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": VERSION, "workspaces": {}}
    if not isinstance(data, dict) or not isinstance(data.get("workspaces"), dict):
        return {"version": VERSION, "workspaces": {}}
    return data


def _write(root: Path, data: Mapping[str, Any]) -> None:
    path = _path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp{os.getpid()}.{threading.get_ident()}")
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(handle, text.encode("utf-8"))
    finally:
        os.close(handle)
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover — a filesystem without modes
        pass


# ── the escrow key ─────────────────────────────────────────────────────────


def _escrow_key(*, create: bool) -> bytes:
    """The key the escrow is sealed under, from the OS keystore.

    Cached for the life of the process: the broker would otherwise shell out to
    the keystore on every locked read. Nothing here ever replaces the key once
    it exists, so the cache cannot go stale.
    """
    import passbook_keystore

    cached = _KEY_CACHE.get("key")
    if cached:
        return cached
    supplied = os.environ.get(KEY_ENV, "").strip()
    if supplied:
        key = _unb64(supplied)
        if len(key) < 32:
            raise StandingError(f"{KEY_ENV} is too short to be a key")
        return key[:32]
    held = passbook_keystore.fetch(KEYSTORE_NAME)
    if held:
        key = _unb64(held)
        if len(key) >= 32:
            _KEY_CACHE["key"] = key[:32]
            return key[:32]
    if not create:
        raise StandingError("this machine's keystore holds no standing-access key")
    created = os.urandom(32)
    stored = passbook_keystore.store(KEYSTORE_NAME, _b64(created))
    if not stored.get("ok"):
        raise StandingError(stored.get("detail") or "the keystore refused the standing-access key")
    _KEY_CACHE["key"] = created
    return created


def _aad(workspace: str, name: str) -> bytes:
    return f"passbook-standing:v1:{workspace}:{name}".encode("utf-8")


def _seal(workspace: str, name: str, value: str, key: bytes) -> str:
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, value.encode("utf-8"), _aad(workspace, name))
    return PREFIX + _b64(nonce + sealed)


def _open(workspace: str, name: str, blob: str, key: bytes) -> str:
    if not str(blob).startswith(PREFIX):
        raise StandingError("not a standing-access value")
    raw = _unb64(blob[len(PREFIX):])
    return AESGCM(key).decrypt(raw[:12], raw[12:], _aad(workspace, name)).decode("utf-8")


# ── what the owner does ────────────────────────────────────────────────────


def _clean_apps(apps: Iterable[str]) -> list[str]:
    cleaned = sorted({str(app).strip() for app in apps if str(app).strip()})
    generic = [app for app in cleaned if app.lower() in GENERIC_APPS]
    if generic:
        raise StandingError(
            f"{', '.join(generic)} is what an unnamed caller is called, so keeping a key "
            f"for it would keep it for every caller. Name the app, and run it with "
            f"`passbook run --app <name>`.")
    if not cleaned:
        raise StandingError("say which app may keep it: --app <name>")
    return cleaned


def keep(name: str, value: str, stored: str, *, apps: Iterable[str], workspace: str,
         root: Path, by: str = "owner") -> dict[str, Any]:
    """Let these apps use this key while the vault is locked.

    `value` is the plaintext, which only somebody who opened the vault has.
    `stored` is what the store holds for it on disk — the sealed text — whose
    digest is how a later rotation is noticed. Apps already on the list stay.
    """
    ok, why = available()
    if not ok:
        raise StandingError(f"standing access needs an OS keystore: {why}")
    if not value:
        raise StandingError(f"{name} has no value to keep")
    wanted = _clean_apps(apps)
    key = _escrow_key(create=True)
    with _LOCK:
        data = _read(root)
        space = data["workspaces"].setdefault(workspace, {})
        entry = space.get(name) if isinstance(space.get(name), dict) else {}
        merged = sorted(set(entry.get("apps") or []) | set(wanted))
        space[name] = {
            "apps": merged,
            "sealed": _seal(workspace, name, value, key),
            "source": digest(stored),
            "kept_at": entry.get("kept_at") or _now(),
            "refreshed_at": _now(),
            "by": by,
        }
        _write(root, data)
    return {"ok": True, "key": name, "workspace": workspace, "apps": merged,
            "added": [app for app in wanted if app not in (entry.get("apps") or [])]}


def release(name: str, *, apps: Iterable[str] = (), workspace: str,
            root: Path) -> dict[str, Any]:
    """Take standing access away from these apps, or from every app."""
    only = {str(app).strip() for app in apps if str(app).strip()}
    with _LOCK:
        data = _read(root)
        space = data["workspaces"].get(workspace) or {}
        entry = space.get(name)
        if not isinstance(entry, dict):
            return {"ok": True, "key": name, "removed": [], "apps": []}
        before = list(entry.get("apps") or [])
        left = [app for app in before if only and app not in only]
        removed = [app for app in before if app not in left]
        if left:
            entry["apps"] = left
        else:
            space.pop(name, None)
            if not space:
                data["workspaces"].pop(workspace, None)
        _write(root, data)
    return {"ok": True, "key": name, "removed": removed, "apps": left}


def forget_key(name: str, *, root: Path, workspace: str = "") -> bool:
    """Drop a key's escrow copy everywhere, or in one workspace. True if held."""
    with _LOCK:
        data = _read(root)
        dropped = False
        for space_name in ([workspace] if workspace else list(data["workspaces"])):
            space = data["workspaces"].get(space_name) or {}
            if space.pop(name, None) is not None:
                dropped = True
            if not space:
                data["workspaces"].pop(space_name, None)
        if dropped:
            _write(root, data)
    return dropped


def entries(*, root: Path, stored: Mapping[str, Mapping[str, str]] | None = None) -> list[dict[str, Any]]:
    """What is kept, for whom, and whether it still matches the store. Never a value.

    `stored` is {workspace: {name: sealed text}}; a key it does not list is
    reported as gone rather than current, since the broker would not serve it.
    """
    rows = []
    for space_name, space in sorted(_read(root)["workspaces"].items()):
        for name, entry in sorted((space or {}).items()):
            if not isinstance(entry, dict):
                continue
            state = "unknown"
            if stored is not None:
                held = (stored.get(space_name) or {}).get(name)
                state = ("gone" if held is None
                         else "current" if digest(held) == entry.get("source")
                         else "stale")
            rows.append({"key": name, "workspace": space_name,
                         "apps": list(entry.get("apps") or []), "state": state,
                         "kept_at": entry.get("kept_at", ""),
                         "refreshed_at": entry.get("refreshed_at", "")})
    return rows


# ── what the broker does ───────────────────────────────────────────────────


def kept_names(workspace: str, *, root: Path) -> set[str]:
    """Which keys have standing access in this workspace. Cheap; no keystore."""
    space = _read(root)["workspaces"].get(workspace) or {}
    return {name for name, entry in space.items() if isinstance(entry, dict)}


def open_for(app: str, workspace: str, stored: Mapping[str, str], *,
             root: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Open the kept copies of these keys for this app, if it may have them.

    `stored` is {name: what the store holds on disk}. Returns (opened, refused)
    where refused maps a name to why — never raises, because a locked read that
    cannot be helped must still answer the way it would have without this.
    """
    opened: dict[str, str] = {}
    refused: dict[str, str] = {}
    app = str(app or "").strip()
    space = _read(root)["workspaces"].get(workspace) or {}
    candidates = {name: space[name] for name in stored
                  if isinstance(space.get(name), dict) and app in (space[name].get("apps") or [])}
    if not candidates or app.lower() in GENERIC_APPS or AESGCM is None:
        return opened, refused
    try:
        key = _escrow_key(create=False)
    except Exception as error:  # noqa: BLE001 — keystore gone: nothing opens
        return opened, {name: str(error) for name in candidates}
    for name, entry in candidates.items():
        if digest(stored[name]) != entry.get("source"):
            refused[name] = (f"{name} changed since standing access was given, so the kept "
                             f"copy is out of date; sign in once to refresh it")
            continue
        try:
            opened[name] = _open(workspace, name, str(entry.get("sealed") or ""), key)
        except Exception:  # noqa: BLE001 — tampered, or sealed under another key
            refused[name] = f"the kept copy of {name} could not be opened"
    return opened, refused


def refresh(workspace: str, current: Mapping[str, tuple[str, str]], *,
            root: Path) -> list[str]:
    """Re-seal kept keys whose value changed. `current` is {name: (stored, plaintext)}.

    Called by the broker whenever it opens a kept key with the vault open, so a
    rotation reaches the escrow the first time anything reads the new value.
    Only a changed value costs a keystore read and a write; an unchanged one is
    a digest comparison.
    """
    if not current or AESGCM is None:
        return []
    space = _read(root)["workspaces"].get(workspace) or {}
    changed = [name for name, (stored, value) in current.items()
               if isinstance(space.get(name), dict) and value
               and digest(stored) != space[name].get("source")]
    if not changed:
        return []
    try:
        key = _escrow_key(create=False)
    except Exception:  # noqa: BLE001 — no keystore key: nothing to refresh into
        return []
    with _LOCK:
        data = _read(root)
        space = data["workspaces"].get(workspace) or {}
        done = []
        for name in changed:
            entry = space.get(name)
            if not isinstance(entry, dict):
                continue
            stored, value = current[name]
            entry["sealed"] = _seal(workspace, name, value, key)
            entry["source"] = digest(stored)
            entry["refreshed_at"] = _now()
            done.append(name)
        if done:
            _write(root, data)
    return done


def _reset_cache() -> None:
    """For tests: forget the cached key."""
    _KEY_CACHE.clear()
