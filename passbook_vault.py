# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""PassBook vault — profiles, sign-in factors, and encryption that travels.

Optional companion to `passbook.py`, and the successor to `passbook_seal.py`.

## What changed, and why it had to

`passbook_seal` (v1) encrypts the store with a key kept in the machine's own
keystore. That stops a stolen disk from being readable, which is real. But the
key is handed to anything running as you, for the asking, forever — so it is
encryption at rest with no sign-in in front of it, and it is macOS-shaped.

This module fixes both. A value is encrypted under a **data key** that is never
written down anywhere in usable form. The data key is instead **wrapped** by one
or more **factors** — a password, a passkey, optionally the OS keystore — and
opening the vault means satisfying one of them. Locking is then a real thing
that can happen: forget the data key, and the store on disk is inert again.

## Portable on purpose

Everything here is `hashlib` and AES-GCM. There is no Security.framework, no
DPAPI, no libsecret in the critical path, because the vault has to open the same
way on macOS, Windows, Linux and eventually iOS — and because a probe showed
that an unsigned interpreter cannot persist biometric-guarded key material on
macOS at all (`errSecMissingEntitlement`). Building the floor on an OS keystore
would have made the floor different on every OS and missing on one of them.

So the two factors that matter are portable by construction:

  password   `hashlib.scrypt` — standard library, identical everywhere
  passkey    a WebAuthn PRF secret — the same passkey works in a browser on
             macOS, Windows and Linux, in the app's webview, and on iOS

The OS keystore survives only as a third, **opt-in** factor for headless jobs
that must start without a human. It is a convenience with a cost, it is labelled
as one, and nothing depends on it existing.

## Rewrapping, not re-encrypting

Changing a password rewraps 32 bytes. It does not re-encrypt 279 values. That is
the entire reason for a data key, and it is what makes rotating a factor cheap
enough that people actually do it.

## Shape

    OPENAI_API_KEY=hive-sealed:v2:<base64url nonce+ciphertext>

Key names stay in the clear, exactly as in v1, so a locked vault still lists
what it holds and a first-run screen still works. A v1 value alongside a v2 one
reads correctly, so adopting this is gradual rather than a flag day.

Ciphertext is bound to its key name and profile through AES-GCM's associated
data, so a value cannot be lifted from one key — or one profile — and pasted
onto another without the tag failing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover — reported through `available()`
    AESGCM = None  # type: ignore[assignment]

__all__ = [
    "PREFIX",
    "VAULT_FILENAME",
    "InvalidFactor",
    "Locked",
    "VaultError",
    "add_device_factor",
    "add_passkey_factor",
    "add_password_factor",
    "available",
    "change_password",
    "DEFAULT_SKIP",
    "PUBLIC_PREFIXES",
    "create_profile",
    "is_sealed",
    "is_sealed_v1",
    "matches_skip",
    "profiles",
    "read_vault",
    "remove_factor",
    "remove_profile",
    "seal_store",
    "set_skip_list",
    "skip_list",
    "seal_value",
    "status",
    "unlock_with_device",
    "unlock_with_passkey",
    "unlock_with_password",
    "unseal_mapping",
    "unseal_store",
    "unseal_value",
]

PREFIX = "hive-sealed:v2:"
PREFIX_V1 = "hive-sealed:v1:"
VAULT_FILENAME = "vault.json"
VAULT_VERSION = 2

# 64 MiB of scrypt. Chosen to be painful for an offline cracker and survivable
# on a phone; `params` rides in the factor so it can be raised later without
# stranding vaults written today.
SCRYPT_N = 1 << 16
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 256 * 1024 * 1024


class VaultError(RuntimeError):
    """Anything the vault refuses to do."""


class Locked(VaultError):
    """The vault is shut and no factor was offered that could open it."""


class InvalidFactor(VaultError):
    """The password was wrong, or the passkey was not the enrolled one."""


def available() -> tuple[bool, str]:
    """Can this machine run a vault at all? Returns (ok, why not)."""
    if AESGCM is None:
        return False, "the `cryptography` package is not installed"
    return True, "portable (scrypt + AES-GCM)"


# ── small helpers ──────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _require_crypto() -> None:
    if AESGCM is None:
        raise VaultError("This needs a runtime that setup has not provided yet — run `passbook install`")


def vault_path(root: Path | None = None) -> Path:
    if root is not None:
        return Path(root) / VAULT_FILENAME
    import passbook

    return passbook.root() / VAULT_FILENAME


def _write_private(path: Path, payload: Mapping[str, Any]) -> Path:
    """Write 0600, atomically. The vault is not a secret, but it is not public."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp{os.getpid()}")
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
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
    return path


def read_vault(*, root: Path | None = None) -> dict[str, Any]:
    """The vault as stored. Contains wrapped key material, never a bare key."""
    try:
        loaded = json.loads(vault_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": VAULT_VERSION, "profiles": [], "active": ""}
    if not isinstance(loaded, dict):
        return {"version": VAULT_VERSION, "profiles": [], "active": ""}
    loaded.setdefault("version", VAULT_VERSION)
    loaded.setdefault("profiles", [])
    loaded.setdefault("active", "")
    return loaded


def _save_vault(vault: Mapping[str, Any], *, root: Path | None = None) -> Path:
    return _write_private(vault_path(root), vault)


def _find_profile(vault: Mapping[str, Any], profile_id: str) -> dict[str, Any]:
    wanted = str(profile_id or vault.get("active") or "").strip()
    for profile in vault.get("profiles", []):
        if profile.get("id") == wanted:
            return profile
    raise VaultError(f"No such profile: {profile_id or '(none active)'}")


# ── wrapping the data key ──────────────────────────────────────────────────


def _wrap(dek: bytes, kek: bytes, *, profile_id: str, factor_id: str) -> str:
    _require_crypto()
    nonce = os.urandom(12)
    aad = f"passbook/v2/wrap/{profile_id}/{factor_id}".encode("utf-8")
    return _b64(nonce + AESGCM(kek).encrypt(nonce, dek, aad))


def _unwrap(blob: str, kek: bytes, *, profile_id: str, factor_id: str) -> bytes:
    _require_crypto()
    raw = _unb64(blob)
    aad = f"passbook/v2/wrap/{profile_id}/{factor_id}".encode("utf-8")
    try:
        return AESGCM(kek).decrypt(raw[:12], raw[12:], aad)
    except Exception as error:  # noqa: BLE001 — one shape of failure for the caller
        raise InvalidFactor("That did not open the vault") from error


def _password_kek(password: str, params: Mapping[str, Any]) -> bytes:
    """Derive a key-encryption key from a password. No pepper, no secret salt.

    The salt is public and per-factor, which is what a salt is for; the cost is
    what makes this hard. Anyone holding the vault file can attack this offline,
    so the cost has to be real rather than decorative.
    """
    salt = _unb64(str(params.get("salt", "")))
    if len(salt) < 16:
        raise VaultError("This factor has no usable salt")
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=int(params.get("n", SCRYPT_N)),
        r=int(params.get("r", SCRYPT_R)),
        p=int(params.get("p", SCRYPT_P)),
        dklen=32,
        maxmem=SCRYPT_MAXMEM,
    )


def _passkey_kek(prf_secret: bytes, params: Mapping[str, Any]) -> bytes:
    """Turn a WebAuthn PRF output into a key-encryption key.

    The authenticator already returns 32 uniformly random bytes bound to the
    credential and to the salt the ceremony asked for, so this is a domain
    separation step rather than a strengthening one — there is no low-entropy
    secret here to stretch, and pretending otherwise by running scrypt over it
    would only cost a phone battery.
    """
    if len(prf_secret) < 32:
        raise VaultError("The passkey secret is too short to be a PRF output")
    salt = _unb64(str(params.get("salt", "")))
    return hashlib.blake2b(prf_secret, salt=salt[:16], person=b"passbook/prf", digest_size=32).digest()


# ── profiles ───────────────────────────────────────────────────────────────


def profiles(*, root: Path | None = None) -> list[dict[str, Any]]:
    """Every profile, described. Names, labels and factor kinds — never a key."""
    vault = read_vault(root=root)
    active = vault.get("active", "")
    out: list[dict[str, Any]] = []
    for profile in vault.get("profiles", []):
        factors = profile.get("factors", [])
        out.append({
            "id": profile.get("id", ""),
            "label": profile.get("label", ""),
            "created_at": profile.get("created_at", ""),
            "active": profile.get("id") == active,
            "factors": [
                {"id": f.get("id", ""), "kind": f.get("kind", ""),
                 "label": f.get("label", ""), "created_at": f.get("created_at", "")}
                for f in factors
            ],
            "kinds": sorted({str(f.get("kind", "")) for f in factors}),
        })
    return out


def create_profile(
    label: str,
    *,
    password: str,
    root: Path | None = None,
    make_active: bool = True,
) -> dict[str, Any]:
    """Create a profile with a fresh data key, opened by a password.

    A password is required rather than optional: a profile whose only factor was
    the machine's keystore would be a vault that unlocks itself, which is the
    thing this module exists to stop.
    """
    _require_crypto()
    if not str(label).strip():
        raise VaultError("A profile needs a label")
    if len(password) < 8:
        raise VaultError("A vault password must be at least 8 characters")

    vault = read_vault(root=root)
    profile_id = _b64(os.urandom(9))
    dek = os.urandom(32)
    profile: dict[str, Any] = {
        "id": profile_id,
        "label": str(label).strip(),
        "created_at": _now(),
        "factors": [],
    }
    vault.setdefault("profiles", []).append(profile)
    _attach_password(profile, dek, password, label="password")
    if make_active or not vault.get("active"):
        vault["active"] = profile_id
    _save_vault(vault, root=root)
    return {"id": profile_id, "label": profile["label"], "active": vault["active"] == profile_id}


def remove_profile(profile_id: str, *, root: Path | None = None) -> dict[str, Any]:
    """Forget a profile. Anything its data key sealed becomes unreadable."""
    vault = read_vault(root=root)
    before = len(vault.get("profiles", []))
    vault["profiles"] = [p for p in vault.get("profiles", []) if p.get("id") != profile_id]
    if len(vault["profiles"]) == before:
        raise VaultError(f"No such profile: {profile_id}")
    if vault.get("active") == profile_id:
        vault["active"] = vault["profiles"][0]["id"] if vault["profiles"] else ""
    _save_vault(vault, root=root)
    return {"removed": profile_id, "active": vault.get("active", "")}


def set_active_profile(profile_id: str, *, root: Path | None = None) -> dict[str, Any]:
    vault = read_vault(root=root)
    _find_profile(vault, profile_id)
    vault["active"] = profile_id
    _save_vault(vault, root=root)
    return {"active": profile_id}


def active_profile_id(*, root: Path | None = None) -> str:
    return str(read_vault(root=root).get("active", ""))


# ── factors ────────────────────────────────────────────────────────────────


def _attach_password(profile: dict[str, Any], dek: bytes, password: str, *, label: str) -> dict[str, Any]:
    factor_id = _b64(os.urandom(6))
    params = {"kdf": "scrypt", "salt": _b64(os.urandom(16)),
              "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}
    factor = {
        "id": factor_id,
        "kind": "password",
        "label": label,
        "created_at": _now(),
        "params": params,
        "wrapped": _wrap(dek, _password_kek(password, params),
                         profile_id=profile["id"], factor_id=factor_id),
    }
    profile.setdefault("factors", []).append(factor)
    return factor


def add_password_factor(
    profile_id: str, new_password: str, *, dek: bytes, label: str = "password",
    root: Path | None = None,
) -> dict[str, Any]:
    """Add another password. Needs the data key, so it needs an open vault."""
    if len(new_password) < 8:
        raise VaultError("A vault password must be at least 8 characters")
    vault = read_vault(root=root)
    profile = _find_profile(vault, profile_id)
    factor = _attach_password(profile, dek, new_password, label=label)
    _save_vault(vault, root=root)
    return {"id": factor["id"], "kind": "password", "label": label}


def add_passkey_factor(
    profile_id: str, *, dek: bytes, credential_id: str, prf_secret: bytes,
    label: str = "passkey", rp_id: str = "", transports: Iterable[str] = (),
    root: Path | None = None,
) -> dict[str, Any]:
    """Enrol a passkey, wrapping the data key with its PRF output.

    The credential id is kept so a sign-in screen can name which passkey to ask
    for; the PRF output itself is never stored, because storing it would make
    the passkey ceremony decorative.
    """
    vault = read_vault(root=root)
    profile = _find_profile(vault, profile_id)
    factor_id = _b64(os.urandom(6))
    params = {"salt": _b64(os.urandom(16)), "credential_id": str(credential_id),
              "rp_id": str(rp_id), "transports": sorted({str(t) for t in transports if t})}
    factor = {
        "id": factor_id,
        "kind": "passkey",
        "label": label,
        "created_at": _now(),
        "params": params,
        "wrapped": _wrap(dek, _passkey_kek(prf_secret, params),
                         profile_id=profile["id"], factor_id=factor_id),
    }
    profile.setdefault("factors", []).append(factor)
    _save_vault(vault, root=root)
    return {"id": factor_id, "kind": "passkey", "label": label,
            "credential_id": params["credential_id"]}


def add_device_factor(
    profile_id: str, *, dek: bytes, label: str = "this device", root: Path | None = None,
) -> dict[str, Any]:
    """Let this machine open the vault without a human. Weaker, and says so.

    This exists for jobs that start at boot. It hands the opening key to the
    OS keystore, which means anything running as you can ask for it — the exact
    property the rest of this module removes. Offer it, name the cost, and never
    make it the default.
    """
    import passbook_keystore

    vault = read_vault(root=root)
    profile = _find_profile(vault, profile_id)
    factor_id = _b64(os.urandom(6))
    kek = os.urandom(32)
    stored = passbook_keystore.store(f"passbook-vault-{profile['id']}-{factor_id}", _b64(kek))
    if not stored.get("ok"):
        raise VaultError(stored.get("detail", "This machine has no keystore to hold a device factor"))
    factor = {
        "id": factor_id,
        "kind": "device",
        "label": label,
        "created_at": _now(),
        "params": {"backend": stored.get("backend", "")},
        "wrapped": _wrap(dek, kek, profile_id=profile["id"], factor_id=factor_id),
    }
    profile.setdefault("factors", []).append(factor)
    _save_vault(vault, root=root)
    return {"id": factor_id, "kind": "device", "label": label, "backend": stored.get("backend", "")}


def remove_factor(profile_id: str, factor_id: str, *, root: Path | None = None) -> dict[str, Any]:
    """Drop a factor, refusing to leave a profile with no way in."""
    vault = read_vault(root=root)
    profile = _find_profile(vault, profile_id)
    factors = profile.get("factors", [])
    remaining = [f for f in factors if f.get("id") != factor_id]
    if len(remaining) == len(factors):
        raise VaultError(f"No such factor: {factor_id}")
    if not remaining:
        raise VaultError("That is the only way into this profile; add another factor first")
    if not any(f.get("kind") == "password" for f in remaining):
        raise VaultError("A profile must keep at least one password factor")
    gone = next(f for f in factors if f.get("id") == factor_id)
    if gone.get("kind") == "device":
        try:
            import passbook_keystore

            passbook_keystore.forget(f"passbook-vault-{profile['id']}-{factor_id}")
        except Exception:  # noqa: BLE001 — the vault entry is the record that matters
            pass
    profile["factors"] = remaining
    _save_vault(vault, root=root)
    return {"removed": factor_id}


# ── opening ────────────────────────────────────────────────────────────────


def _factors_of(profile: Mapping[str, Any], kind: str) -> list[dict[str, Any]]:
    return [f for f in profile.get("factors", []) if f.get("kind") == kind]


def unlock_with_password(profile_id: str, password: str, *, root: Path | None = None) -> bytes:
    """Open the vault with a password. Returns the data key; hold it carefully.

    Every password factor is tried, so a profile with a personal password and a
    shared one opens on either without the caller having to say which.
    """
    vault = read_vault(root=root)
    profile = _find_profile(vault, profile_id)
    candidates = _factors_of(profile, "password")
    if not candidates:
        raise Locked("This profile has no password factor")
    for factor in candidates:
        try:
            kek = _password_kek(password, factor.get("params", {}))
            return _unwrap(factor["wrapped"], kek, profile_id=profile["id"], factor_id=factor["id"])
        except InvalidFactor:
            continue
    raise InvalidFactor("Wrong password")


def unlock_with_passkey(
    profile_id: str, *, credential_id: str, prf_secret: bytes, root: Path | None = None,
) -> bytes:
    """Open the vault with an enrolled passkey's PRF output."""
    vault = read_vault(root=root)
    profile = _find_profile(vault, profile_id)
    for factor in _factors_of(profile, "passkey"):
        if factor.get("params", {}).get("credential_id") != str(credential_id):
            continue
        kek = _passkey_kek(prf_secret, factor.get("params", {}))
        return _unwrap(factor["wrapped"], kek, profile_id=profile["id"], factor_id=factor["id"])
    raise InvalidFactor("That passkey is not enrolled on this profile")


def unlock_with_device(profile_id: str = "", *, root: Path | None = None) -> bytes:
    """Open the vault using this machine's keystore, if a device factor exists."""
    import passbook_keystore

    vault = read_vault(root=root)
    profile = _find_profile(vault, profile_id)
    for factor in _factors_of(profile, "device"):
        held = passbook_keystore.fetch(f"passbook-vault-{profile['id']}-{factor['id']}")
        if not held:
            continue
        return _unwrap(factor["wrapped"], _unb64(held),
                       profile_id=profile["id"], factor_id=factor["id"])
    raise Locked("This profile has no device factor on this machine")


def change_password(
    profile_id: str, *, dek: bytes, new_password: str, factor_id: str = "",
    root: Path | None = None,
) -> dict[str, Any]:
    """Rewrap the data key under a new password. 32 bytes, not 279 values."""
    if len(new_password) < 8:
        raise VaultError("A vault password must be at least 8 characters")
    vault = read_vault(root=root)
    profile = _find_profile(vault, profile_id)
    candidates = _factors_of(profile, "password")
    target = next((f for f in candidates if f.get("id") == factor_id), None) if factor_id else (
        candidates[0] if candidates else None)
    if target is None:
        raise VaultError("No password factor to change")
    params = {"kdf": "scrypt", "salt": _b64(os.urandom(16)),
              "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}
    target["params"] = params
    target["wrapped"] = _wrap(dek, _password_kek(new_password, params),
                              profile_id=profile["id"], factor_id=target["id"])
    target["rotated_at"] = _now()
    _save_vault(vault, root=root)
    return {"id": target["id"], "rotated_at": target["rotated_at"]}


# ── sealing values ─────────────────────────────────────────────────────────


def is_sealed(value: str) -> bool:
    return str(value).startswith(PREFIX)


def is_sealed_v1(value: str) -> bool:
    return str(value).startswith(PREFIX_V1)


def _aad(profile_id: str, name: str) -> bytes:
    return f"passbook/v2/value/{profile_id}/{name}".encode("utf-8")


def seal_value(name: str, value: str, dek: bytes, *, profile_id: str) -> str:
    """Encrypt one value, bound to its key name and profile."""
    _require_crypto()
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, str(value).encode("utf-8"), _aad(profile_id, name))
    return PREFIX + _b64(nonce + ciphertext)


def unseal_value(name: str, value: str, dek: bytes, *, profile_id: str) -> str:
    """Decrypt one value. Anything not sealed at v2 is returned unchanged."""
    if not is_sealed(value):
        return value
    _require_crypto()
    raw = _unb64(str(value)[len(PREFIX):])
    try:
        return AESGCM(dek).decrypt(raw[:12], raw[12:], _aad(profile_id, name)).decode("utf-8")
    except Exception as error:  # noqa: BLE001
        raise InvalidFactor(f"{name} did not open with this data key") from error


def unseal_mapping(
    values: Mapping[str, str], dek: bytes | None, *, profile_id: str = "",
) -> dict[str, str]:
    """Unseal a whole store. A value that will not open is dropped, not surfaced.

    Handing a provider a sealed blob as if it were an API key produces a
    baffling 401 instead of an honest absence, so a locked vault reads as "no
    credentials" rather than as "credentials that do not work".
    """
    if not any(is_sealed(v) for v in values.values()):
        return dict(values)
    if not dek:
        return {name: value for name, value in values.items() if not is_sealed(value)}
    out: dict[str, str] = {}
    for name, value in values.items():
        if not is_sealed(value):
            out[name] = value
            continue
        try:
            out[name] = unseal_value(name, value, dek, profile_id=profile_id)
        except InvalidFactor:
            continue
    return out


def skip_list(*, root: Path | None = None) -> list[str]:
    """Keys this machine deliberately leaves readable.

    Not everything in the store is a credential. Feature flags are read by code
    that runs before anything could sign in — a boot hook, an instrumentation
    file that is forbidden from importing anything — and such a reader compares
    the value to "1" or "false" rather than sending it anywhere. Sealing one of
    those does not protect a secret; it silently changes a setting, because a
    sealed blob is not equal to "1".
    """
    return sorted(read_vault(root=root).get("skip", []))


def set_skip_list(names: Iterable[str], *, root: Path | None = None) -> list[str]:
    vault = read_vault(root=root)
    vault["skip"] = sorted({str(name).strip() for name in names if str(name).strip()})
    _save_vault(vault, root=root)
    return vault["skip"]


# Framework conventions for "this value is compiled into client-side code".
# Every one of these is public by construction — the build inlines it into a
# browser bundle — so sealing one protects nothing and breaks a build that runs
# long before anybody could sign in.
PUBLIC_PREFIXES = (
    "NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_",
    "EXPO_PUBLIC_", "GATSBY_", "NUXT_PUBLIC_",
)

DEFAULT_SKIP = tuple(f"{prefix}*" for prefix in PUBLIC_PREFIXES)


def matches_skip(name: str, patterns: Iterable[str]) -> bool:
    """Exact names, or a trailing `*` for a family.

    `NEXT_PUBLIC_*` is the case that made this worth having: Next.js inlines
    every one of those into the browser bundle at build time, so they are public
    by construction and there are fifteen of them. Listing each would be a list
    nobody keeps up to date.
    """
    for pattern in patterns:
        pattern = str(pattern).strip()
        if not pattern:
            continue
        if pattern.endswith("*"):
            if name.startswith(pattern[:-1]):
                return True
        elif name == pattern:
            return True
    return False


def seal_store(
    dek: bytes, *, profile_id: str = "", root: Path | None = None, path: Path | None = None,
    skip: Iterable[str] = (),
) -> dict[str, Any]:
    """Seal every plaintext value in the store, in place.

    Rewrites through `passbook.set_values(overwrite=True)`, so comments,
    ordering, permissions and unrelated keys survive exactly as they were.

    `skip` names keys to leave readable, and is remembered so a later seal pass
    does not quietly swallow them.
    """
    import passbook

    _require_crypto()
    profile_id = profile_id or active_profile_id(root=root)
    if not profile_id:
        raise VaultError("No active profile to seal under")
    target = Path(path) if path is not None else (
        passbook.env_path() if root is None else Path(root) / ".env")
    try:
        current = passbook.parse_env_text(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return {"ok": False, "sealed": [], "detail": f"No store to seal at {target}"}

    patterns = set(skip_list(root=root)) | {str(name).strip() for name in skip if str(name).strip()}
    if skip:
        patterns = set(set_skip_list(patterns, root=root))
    exempt = {n for n in current if matches_skip(n, patterns)}

    plain = {n: v for n, v in current.items()
             if not is_sealed(v) and not is_sealed_v1(v) and n not in exempt}
    if not plain:
        return {"ok": True, "sealed": [], "detail": "Every value is already sealed.",
                "skipped": sorted(exempt),
                "already_sealed": sorted(n for n, v in current.items() if is_sealed(v))}
    passbook.set_values(
        {n: seal_value(n, v, dek, profile_id=profile_id) for n, v in plain.items()},
        overwrite=True,
    )
    left = sorted(exempt)
    return {"ok": True, "sealed": sorted(plain), "path": str(target), "profile": profile_id,
            "skipped": left,
            "detail": f"Sealed {len(plain)} value(s) under profile {profile_id}."
                      + (f" Left {len(left)} readable on purpose." if left else "")}


def unseal_store(
    dek: bytes, *, profile_id: str = "", root: Path | None = None, path: Path | None = None,
) -> dict[str, Any]:
    """Put the store back to plaintext. The door out.

    Sealing without this is a one-way trip, and a security feature you cannot
    reverse is one people are right to refuse to turn on.
    """
    import passbook

    _require_crypto()
    profile_id = profile_id or active_profile_id(root=root)
    target = Path(path) if path is not None else (
        passbook.env_path() if root is None else Path(root) / ".env")
    try:
        current = passbook.parse_env_text(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return {"ok": False, "opened": [], "detail": f"No store at {target}"}

    sealed = {n: v for n, v in current.items() if is_sealed(v)}
    if not sealed:
        return {"ok": True, "opened": [], "detail": "Nothing is sealed at v2."}
    opened: dict[str, str] = {}
    stuck: list[str] = []
    for name, value in sealed.items():
        try:
            opened[name] = unseal_value(name, value, dek, profile_id=profile_id)
        except InvalidFactor:
            stuck.append(name)
    if opened:
        # `exact` because this is a move, not a set: whatever was encrypted has
        # to come back byte for byte, trailing whitespace included. One real
        # store had a trailing space inside a quoted OAuth client id, and a
        # rollback that quietly trimmed it would be a migration that edits
        # credentials — which is a migration nobody should trust.
        passbook.set_values(opened, overwrite=True, exact=True)
    return {"ok": not stuck, "opened": sorted(opened), "stuck": sorted(stuck),
            "path": str(target),
            "detail": (f"Opened {len(opened)} value(s) back to plaintext."
                       + (f" {len(stuck)} would not open with this key." if stuck else ""))}


def status(*, root: Path | None = None, path: Path | None = None) -> dict[str, Any]:
    """How much of the store is sealed, and what could open it. Names only."""
    import passbook

    ok, detail = available()
    vault = read_vault(root=root)
    target = Path(path) if path is not None else (
        passbook.env_path() if root is None else Path(root) / ".env")
    try:
        current = passbook.parse_env_text(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        current = {}
    sealed = sorted(n for n, v in current.items() if is_sealed(v))
    legacy = sorted(n for n, v in current.items() if is_sealed_v1(v))
    plain = sorted(n for n, v in current.items() if not is_sealed(v) and not is_sealed_v1(v))
    known = profiles(root=root)
    return {
        "supported": ok,
        "crypto": detail,
        "version": 2,
        "profiles": known,
        "active": vault.get("active", ""),
        "sealed": sealed,
        "legacy_v1": legacy,
        "plaintext": plain,
        "fully_sealed": bool(current) and not plain and not legacy,
        "detail": (
            "The store is empty." if not current
            else "Every value is encrypted and needs a sign-in." if not plain and not legacy
            else f"{len(plain) + len(legacy)} value(s) are still readable without signing in."
        ),
    }
