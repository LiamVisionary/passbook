# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Keeping an encrypted export on the relay, and getting it back on a machine that has nothing.

`passbook export` writes an encrypted file, and then the file is the person's problem: where it
lives, whether it is current, whether it survives the laptop. This keeps that same text on the relay
instead (`relay/src/backup.ts`).

What is sent is exactly what `passbook_backup.encrypt` makes: scrypt over a passphrase the person
chose, AES-256-GCM over the body. The passphrase never leaves this machine, so the relay holds
ciphertext it cannot open. That is the whole security argument, and it has one consequence worth
saying out loud: **a forgotten passphrase is a lost backup.** Nobody can reset it, the relay least
of all.

**Getting it back.** The machine that made a backup can read it back any time; it is that
machine's, by its key. But the reason to keep a backup off a machine is that the machine may be
gone, and its key with it. So storing one also makes a *recovery code*:

    pbb1.<backup id>.<secret>

The relay is sent only the SHA-256 of the secret. Any machine that presents the secret is given the
ciphertext, which still needs the passphrase. Two things to keep, ideally in two places: the code
and the passphrase. Neither alone opens anything.

The code is shown once, when the backup is made. It is not written anywhere on this machine,
because a recovery code kept on the machine it recovers is not one.

**The passphrase is the whole of the protection, so PassBook makes it.** Whoever holds the
ciphertext (the relay, or anybody who breaks into it) can guess at the passphrase for as long as
they like; scrypt makes each guess slow and a short passphrase is still short. A file on your own
disk is one thing. A copy of every credential kept on somebody else's computer is another, and
"at least 8 characters" is the wrong floor for it. So by default the passphrase is generated here
(`generate_passphrase`, 125 random bits, in the alphabet recovery codes already use), shown once
for a password manager, and never chosen. A person who wants their own may have it, at 16
characters or more (`check_passphrase`). Liam, 2026-11-26, of the advice to "use a passphrase you
generate, not one you invent": "do this first".
"""
from __future__ import annotations

import hashlib
import re
import secrets
from pathlib import Path
from typing import Any, Mapping

import passbook_backup
import passbook_join as join
import passbook_link as link

# The floor for a passphrase somebody types themselves. Five ordinary words clear it.
MIN_PASSPHRASE = 16
PASSPHRASE_GROUPS, PASSPHRASE_GROUP = 5, 5
CODE_VERSION = "pbb1"
CODE_SHAPE = re.compile(r"^pbb1\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{20,64})(?:\.([A-Za-z0-9_-]{4,200}))?$")
ID_SHAPE = re.compile(r"^[A-Za-z0-9_-]{22}$")
MAX_BYTES = 1_000_000


class CloudBackupError(join.JoinError):
    """A backup could not be stored or read back. The message is safe to show a person."""

    def __init__(self, message: str, code: str = "") -> None:
        super().__init__(message)
        self.code = code


def _alphabet() -> str:
    # The one recovery codes use: no I, L, O or U, so nothing in it is mistaken for something else.
    import passbook_vault
    return passbook_vault.RECOVERY_ALPHABET


def generate_passphrase() -> str:
    """A passphrase nobody could guess: 25 characters of 32, which is 125 bits, in five groups.

    Made to be kept in a password manager and pasted, not remembered. Grouped so that a person who
    does have to read it off paper one day can keep their place.
    """
    alphabet = _alphabet()
    return "-".join("".join(secrets.choice(alphabet) for _ in range(PASSPHRASE_GROUP)) for _ in range(PASSPHRASE_GROUPS))


def check_passphrase(passphrase: str) -> None:
    """Refuse a passphrase too short to protect a backup that is kept on a relay."""
    if len(str(passphrase)) < MIN_PASSPHRASE:
        raise CloudBackupError(
            f"A passphrase for a backup kept on the relay needs at least {MIN_PASSPHRASE} characters: whoever holds the backup "
            "can guess at it for as long as they like. Five random words would do, or let PassBook make one.")


def candidates(passphrase: str) -> list[str]:
    """The passphrase as typed, and, if it looks like one PassBook made, as PassBook wrote it.

    A made passphrase read back off paper arrives in lower case, with spaces, or without its
    dashes. That is the same passphrase, and refusing it would lose a backup over a hyphen.
    """
    typed = str(passphrase)
    alphabet = set(_alphabet())
    bare = "".join(typed.split()).replace("-", "").upper()
    out = [typed]
    if len(bare) == PASSPHRASE_GROUPS * PASSPHRASE_GROUP and set(bare) <= alphabet:
        made = "-".join(bare[i:i + PASSPHRASE_GROUP] for i in range(0, len(bare), PASSPHRASE_GROUP))
        if made != typed:
            out.append(made)
    return out


def _ask(method: str, path: str, body: Mapping[str, Any] | None = None, *, relay: str = "",
         root: Path | None = None, opener: join.Opener | None = None) -> tuple[str, int, dict[str, Any]]:
    chosen = join.relay_url(relay)
    status, answer = join._call(chosen, method, path, body, link.identity(root=root), opener=opener)
    return chosen, status, answer if isinstance(answer, dict) else {}


def _refuse(answer: Mapping[str, Any], fallback: str) -> CloudBackupError:
    return CloudBackupError(str(answer.get("error") or fallback), str(answer.get("code") or ""))


def _code(backup_id: str, secret: str, relay: str) -> str:
    import passbook_web_link as web_link
    suffix = "" if relay == web_link.relays()[0] else "." + join._b64(relay.encode("utf-8"))
    return f"{CODE_VERSION}.{backup_id}.{secret}{suffix}"


def parse_code(code: str) -> dict[str, str]:
    """A recovery code's parts. The relay it names must be one this machine is allowed to use."""
    match = CODE_SHAPE.fullmatch("".join(str(code).split()))
    if not match:
        raise CloudBackupError("That is not a PassBook recovery code. It starts with pbb1 and has three parts.")
    backup_id, secret, relay = match.groups()
    try:
        chosen = join.relay_url(join._unb64(relay).decode("utf-8") if relay else "")
    except (ValueError, UnicodeDecodeError):
        raise CloudBackupError("That recovery code is damaged. Copy it again, whole.") from None
    except join.JoinError:
        # Said without repeating the address: a damaged code decodes to anything at all.
        raise CloudBackupError("That recovery code is for a relay this machine does not use. "
                               "If it is yours, add it to PASSBOOK_WEB_RELAYS first.") from None
    return {"id": backup_id, "secret": secret, "relay": chosen}


def store(text: str, *, label: str = "", relay: str = "", root: Path | None = None,
          opener: join.Opener | None = None) -> dict[str, Any]:
    """Keep an encrypted export on the relay. Returns its id and the recovery code, once.

    `text` must be an encrypted export. A plaintext or GPG one is refused here as well as by the
    relay, so that a value in the clear cannot leave this machine by this road even to a relay
    that would have taken it.
    """
    if passbook_backup.detect(text) != "encrypted":
        raise CloudBackupError("Only an export encrypted with a passphrase is kept on the relay.")
    if len(text) > MAX_BYTES:
        raise CloudBackupError("This store is too large to keep on the relay. Export it to a file instead.")
    secret = join._b64(secrets.token_bytes(32))
    body = {"blob": text, "label": label or join.machine_label(),
            "recovery": hashlib.sha256(secret.encode("utf-8")).hexdigest()}
    chosen, status, answer = _ask("POST", "/api/passbook/backups", body, relay=relay, root=root, opener=opener)
    if status != 200 or not answer.get("ok") or not ID_SHAPE.fullmatch(str(answer.get("id") or "")):
        raise _refuse(answer, "The relay did not keep the backup. Try again in a moment.")
    return {"ok": True, "id": answer["id"], "at": str(answer.get("at") or ""), "bytes": len(text),
            "kept": int(answer.get("kept") or 0), "code": _code(answer["id"], secret, chosen)}


def stored(*, relay: str = "", root: Path | None = None, opener: join.Opener | None = None) -> list[dict[str, Any]]:
    """This machine's backups on the relay, newest first. Never their contents."""
    _, status, answer = _ask("GET", "/api/passbook/backups", relay=relay, root=root, opener=opener)
    if status == 404:
        return []  # a relay that keeps no backups has none of ours
    if status != 200 or not answer.get("ok"):
        raise _refuse(answer, "The relay did not list this machine's backups. Try again in a moment.")
    return [{"id": str(row.get("id") or ""), "label": str(row.get("label") or ""), "bytes": int(row.get("bytes") or 0),
             "at": str(row.get("at") or "")} for row in answer.get("backups") or [] if isinstance(row, Mapping)]


def _checked(answer: Mapping[str, Any]) -> str:
    text = str(answer.get("blob") or "")
    if passbook_backup.detect(text) != "encrypted":
        raise CloudBackupError("What the relay returned is not an encrypted PassBook export.")
    digest = str(answer.get("digest") or "")
    if digest and hashlib.sha256(text.encode("utf-8")).hexdigest() != digest:
        raise CloudBackupError("The backup the relay returned is damaged.")
    return text


def fetch(code_or_id: str, *, relay: str = "", root: Path | None = None, opener: join.Opener | None = None) -> str:
    """The encrypted text of one backup: by recovery code from any machine, or by id from its own."""
    wanted = "".join(str(code_or_id).split())
    if wanted.startswith(CODE_VERSION + "."):
        parsed = parse_code(wanted)
        _, status, answer = _ask("POST", f"/api/passbook/backups/{parsed['id']}/recover", {"secret": parsed["secret"]},
                                 relay=parsed["relay"], root=root, opener=opener)
        if status == 404:
            raise CloudBackupError("No backup matches that recovery code. Check it was copied whole.")
    elif ID_SHAPE.fullmatch(wanted):
        _, status, answer = _ask("GET", f"/api/passbook/backups/{wanted}", relay=relay, root=root, opener=opener)
        if status == 404:
            raise CloudBackupError("That backup is not on the relay, or was made by another machine. "
                                   "From another machine, use its recovery code.")
    else:
        raise CloudBackupError("Give a recovery code (pbb1.…) or the id of one of this machine's backups.")
    if status != 200 or not answer.get("ok"):
        raise _refuse(answer, "The relay did not return that backup. Try again in a moment.")
    return _checked(answer)


def remove(backup_id: str, *, relay: str = "", root: Path | None = None, opener: join.Opener | None = None) -> bool:
    """Delete one of this machine's backups from the relay."""
    if not ID_SHAPE.fullmatch(str(backup_id)):
        raise CloudBackupError("That is not a backup's id.")
    _, status, answer = _ask("DELETE", f"/api/passbook/backups/{backup_id}", relay=relay, root=root, opener=opener)
    if status == 404:
        raise CloudBackupError("That backup is not on the relay, or was made by another machine.")
    if status != 200 or not answer.get("ok"):
        raise _refuse(answer, "The relay did not remove that backup. Try again in a moment.")
    return True
