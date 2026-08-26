# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Getting a store out of one machine and into another.

Three shapes, because the reasons people export are not the same reason:

  encrypted   the default. A `passbook-export:v1` envelope: scrypt over a
              passphrase you choose, AES-GCM over the body. Portable, needs
              nothing installed at the other end but PassBook itself.
  gpg         for machines that already keep secrets in GPG — HivemindOS backs
              its wallet vault up this way, into `Operations/Secure/`, and a
              second mechanism beside that one would be a second thing to keep
              working. Needs `gpg` on PATH.
  plain       a readable `.env`. Every value in the clear, which is sometimes
              exactly what you need — moving to a machine that has no PassBook
              yet — and is never safe to leave lying around.

Import takes any of the three and works out which by looking, because the person
importing a file did not choose its shape and should not have to describe it.

What this module will not do:

  * Export without opening the vault. There is no path here that reads sealed
    bytes and writes them out still sealed under a key the other machine cannot
    have. An export is a decryption, and it is recorded as one.
  * Write a plaintext export without being told twice. `--plain` is not enough;
    the caller has to say it understands, because "export" reads like a backup
    and a plaintext backup is a copy of every credential you own.
  * Put a passphrase in argv. Everything here takes it from stdin or a prompt.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable, Mapping

MARKER = "passbook-export:v1"
GPG_MARKER = "-----BEGIN PGP MESSAGE-----"
SCRYPT_N = 1 << 16
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 128 * SCRYPT_R * SCRYPT_N * 2
FILE_MODE = 0o600


class BackupError(RuntimeError):
    """Something about an export or an import could not be done."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as error:
        raise BackupError("This file's contents are not valid base64") from error


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as error:  # pragma: no cover - platform dependent
        raise BackupError(
            "This machine has no `cryptography` module, so an encrypted export "
            "cannot be made. Install PassBook's dependencies, or use --gpg."
        ) from error
    return AESGCM


# ── what an export contains ────────────────────────────────────────────────

def body(values: Mapping[str, str], *, workspace: str = "",
         machine: str = "", note: str = "") -> dict[str, Any]:
    """The exported document, before any encryption.

    Key names and values only. Not the access policy, not the ledger, not the
    profiles: those describe THIS machine's arrangements, and carrying them to
    another machine would import somebody else's answers to questions the new
    machine has not been asked yet.
    """
    return {
        "format": "passbook-export",
        "version": 1,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "workspace": workspace,
        "machine": machine,
        "note": note,
        "count": len(values),
        "keys": dict(values),
    }


# ── encrypted (the default) ────────────────────────────────────────────────

def encrypt(values: Mapping[str, str], passphrase: str, **meta: Any) -> str:
    if len(passphrase) < 8:
        raise BackupError("An export passphrase must be at least 8 characters")
    AESGCM = _aesgcm()
    salt = os.urandom(16)
    kek = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=SCRYPT_N,
                         r=SCRYPT_R, p=SCRYPT_P, dklen=32, maxmem=SCRYPT_MAXMEM)
    nonce = os.urandom(12)
    payload = json.dumps(body(values, **meta), separators=(",", ":")).encode("utf-8")
    sealed = AESGCM(kek).encrypt(nonce, payload, MARKER.encode("ascii"))
    envelope = {
        "format": "passbook-export",
        "version": 1,
        "kdf": {"name": "scrypt", "salt": _b64(salt), "n": SCRYPT_N,
                "r": SCRYPT_R, "p": SCRYPT_P},
        "cipher": "AES-256-GCM",
        "body": _b64(nonce + sealed),
    }
    # The marker line is what `detect` reads, so an import never has to guess
    # from a filename someone renamed.
    return MARKER + "\n" + json.dumps(envelope, indent=2) + "\n"


def decrypt(text: str, passphrase: str) -> dict[str, Any]:
    AESGCM = _aesgcm()
    _, _, rest = text.partition(MARKER)
    try:
        envelope = json.loads(rest)
    except json.JSONDecodeError as error:
        raise BackupError("This export's header is damaged") from error
    kdf = envelope.get("kdf") or {}
    salt = _unb64(str(kdf.get("salt", "")))
    if len(salt) < 16:
        raise BackupError("This export has no usable salt")
    kek = hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt,
        n=int(kdf.get("n", SCRYPT_N)), r=int(kdf.get("r", SCRYPT_R)),
        p=int(kdf.get("p", SCRYPT_P)), dklen=32, maxmem=SCRYPT_MAXMEM)
    raw = _unb64(str(envelope.get("body", "")))
    if len(raw) < 13:
        raise BackupError("This export's body is truncated")
    try:
        opened = AESGCM(kek).decrypt(raw[:12], raw[12:], MARKER.encode("ascii"))
    except Exception as error:  # cryptography raises its own InvalidTag
        raise BackupError(
            "That passphrase does not open this export. Nothing here can tell "
            "you whether the passphrase is wrong or the file is damaged — that "
            "is the same guarantee that stops anyone else opening it."
        ) from error
    return json.loads(opened.decode("utf-8"))


# ── gpg ────────────────────────────────────────────────────────────────────

def gpg_available() -> bool:
    return shutil.which("gpg") is not None


def gpg_encrypt(values: Mapping[str, str], *, recipient: str = "",
                passphrase: str = "", **meta: Any) -> str:
    """Armoured GPG, to a recipient's key or symmetric under a passphrase.

    Matches how HivemindOS backs up its wallet vault, so a machine that already
    has a recipient configured and a `Operations/Secure/` folder can keep one
    habit rather than two.
    """
    if not gpg_available():
        raise BackupError("`gpg` is not on PATH, so a GPG export cannot be made.")
    if not recipient and not passphrase:
        raise BackupError("A GPG export needs either a recipient or a passphrase.")
    payload = json.dumps(body(values, **meta), indent=2).encode("utf-8")
    argv = ["gpg", "--batch", "--yes", "--armor"]
    if recipient:
        argv += ["--encrypt", "--recipient", recipient]
    else:
        # `--passphrase-fd 0` keeps it off the command line, where `ps` reads.
        argv += ["--symmetric", "--passphrase-fd", "0", "--pinentry-mode", "loopback"]
        payload = passphrase.encode("utf-8") + b"\n" + payload
    done = subprocess.run(argv, input=payload, capture_output=True)
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise BackupError(f"gpg refused: {detail[-1] if detail else 'no reason given'}")
    return done.stdout.decode("utf-8")


def gpg_decrypt(text: str, *, passphrase: str = "") -> dict[str, Any]:
    if not gpg_available():
        raise BackupError("`gpg` is not on PATH, so this export cannot be opened.")
    argv = ["gpg", "--batch", "--yes", "--decrypt"]
    payload = text.encode("utf-8")
    if passphrase:
        argv += ["--passphrase-fd", "0", "--pinentry-mode", "loopback"]
        payload = passphrase.encode("utf-8") + b"\n" + payload
    done = subprocess.run(argv, input=payload, capture_output=True)
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise BackupError(f"gpg could not open it: {detail[-1] if detail else 'no reason given'}")
    try:
        return json.loads(done.stdout.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise BackupError("That GPG file did not contain a PassBook export") from error


# ── plain ──────────────────────────────────────────────────────────────────

PLAIN_HEADER = """# PassBook export — EVERY VALUE BELOW IS IN THE CLEAR.
#
# Anything that can read this file has every credential in it. It is not a
# backup you keep; it is a thing you move and then destroy. Do not put it in a
# repository, a synced folder, a backup set, or a chat.
#
# Import it with:  passbook import {path}
"""


def plain(values: Mapping[str, str], *, path: str = "FILE") -> str:
    # `_format_line` is the store's own quoting. Writing a second one here
    # would be a second answer to "how is a value with a space in it written",
    # and the two would disagree the first time either changed.
    from passbook import _format_line

    lines = [_format_line(name, values[name]) for name in sorted(values)]
    return PLAIN_HEADER.format(path=path) + "\n" + "\n".join(lines) + "\n"


# ── reading whatever someone hands you ─────────────────────────────────────

def detect(text: str) -> str:
    """Which of the three shapes this is: 'encrypted', 'gpg' or 'plain'."""
    head = text.lstrip()
    if head.startswith(MARKER):
        return "encrypted"
    if head.startswith(GPG_MARKER):
        return "gpg"
    return "plain"


def read(text: str, *, passphrase: str = "") -> dict[str, Any]:
    """Open an export of any shape and return its document.

    The caller does not say which shape it is, because the person importing a
    file did not choose its shape.
    """
    shape = detect(text)
    if shape == "encrypted":
        if not passphrase:
            raise BackupError("This export is encrypted and needs its passphrase.")
        return decrypt(text, passphrase)
    if shape == "gpg":
        return gpg_decrypt(text, passphrase=passphrase)
    from passbook import parse_env_text

    values = parse_env_text(text)
    if not values:
        raise BackupError(
            "Nothing in that file looked like a credential. An export is either "
            "a PassBook envelope, a GPG message, or KEY=value lines."
        )
    return body(values, note="imported from a plaintext file")


def keys_of(document: Mapping[str, Any]) -> dict[str, str]:
    keys = document.get("keys")
    if not isinstance(keys, dict):
        raise BackupError("That export has no keys in it")
    return {str(name): str(value) for name, value in keys.items()}


def write_private(path: Path, text: str) -> Path:
    """Write an export 0600, and never leave a readable half-file behind."""
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.partial")
    handle = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.chmod(temporary, FILE_MODE)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return path
