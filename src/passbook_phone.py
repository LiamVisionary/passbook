# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Answering a request for a key from a phone.

When an agent or an app asks for a key the policy says to ask about, PassBook holds the request and
waits for its owner. Until now that question appeared on the machine that was asked and waited for
somebody sitting at it; a job that needed a key at night failed with "no answer in time". This
carries the question to a phone and the answer back, through the relay (`relay/src/phones.ts`).

The relay is a mailbox and is not trusted with either half:

  * **It cannot read the question.** The request (app, key names, reason, machine) is encrypted
    here to a key that exists only in the phone's browser: an ephemeral P-256 exchange, HKDF-SHA256,
    AES-256-GCM. Key names are never values, but they are still nobody else's business.
  * **It cannot make the answer.** The phone signs `allow` or `deny` together with the SHA-256 of
    the exact request text it decrypted, the request's id, and the time (ECDSA P-256). `verify`
    checks that against the key this machine accepted when the phone was linked. An answer that was
    invented, replayed, or moved from another request does not verify and is ignored.
  * **It cannot link a phone of its own.** Linking starts from a code shown on this machine. The
    relay is told only its id; the phone proves it read the secret with an HMAC over its two public
    keys, which `check` verifies before the phone is offered for confirmation. Then a person
    confirms it by name. Nothing is ever sent to a phone that was not confirmed.

**What a phone may answer is narrow on purpose.** Only a request to *use* a key (`read`). A
request to add, change or delete a key is never sent to a phone, because those change the store and
belong in front of it. And a phone may allow once, or for one hour; never "always".

**The limit, said plainly.** The page the phone opens is served by the relay. Everything above
holds against a relay that stores and forwards. It does not hold against a relay changed to serve
the phone a different page, because that page would hold the phone's key. So every answer a phone
gives is written to this machine's record as approved by that phone, by name, where a wrong one can
be seen; and somebody who needs more than that runs their own relay.

**There is no push notification.** A phone sees a request when the page is open (it checks every
three seconds). If balance alerts already go to a Telegram bot of yours, the same bot is told a
request is waiting, with a button that opens the page. That is the whole of the notifying.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any, Mapping

import passbook
import passbook_join as join
import passbook_link as link

PHONES_FILENAME = "passbook-phones.json"
CODE_VERSION = "pbp1"
SEAL_PREFIX = "pbps1"
ID_SHAPE = re.compile(r"^[A-Za-z0-9_-]{22}$")
# What a phone may be asked about, and for how long it may say yes.
ASKABLE_KINDS = ("read",)
REMEMBER_SECONDS = (0, 3600)
ANSWER_SKEW_SECONDS = 15 * 60
P256_POINT = 65


class PhoneError(join.JoinError):
    """Something about a phone could not be done. The message is safe to show a person."""

    def __init__(self, message: str, code: str = "") -> None:
        super().__init__(message)
        self.code = code


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError:
        raise PhoneError("Answering from a phone needs a runtime that setup has not provided yet. "
                         "Run `passbook install`.") from None
    return ec, hashes, serialization, AESGCM, HKDF, encode_dss_signature, InvalidSignature


# ── what this machine remembers ─────────────────────────────────────────────


def phones_path(root: Path | None = None) -> Path:
    return (Path(root) if root else passbook.root()) / PHONES_FILENAME


def _read(root: Path | None = None) -> dict[str, Any]:
    try:
        loaded = json.loads(phones_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        loaded = {}
    loaded = loaded if isinstance(loaded, dict) else {}
    return {"version": 1, "phones": [p for p in loaded.get("phones", []) if isinstance(p, dict)],
            "pending": [p for p in loaded.get("pending", []) if isinstance(p, dict)]}


def _write(state: Mapping[str, Any], root: Path | None = None) -> None:
    path = phones_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        json.dump(state, stream, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def linked(root: Path | None = None) -> list[dict[str, Any]]:
    """Phones this machine will ask. Their public keys only; a phone's private keys never leave it."""
    return [dict(phone) for phone in _read(root)["phones"]]


def any_linked(root: Path | None = None) -> bool:
    """Cheap enough to call on every request: is there a phone to ask at all?"""
    try:
        return phones_path(root).exists() and bool(_read(root)["phones"])
    except OSError:
        return False


def _ask(relay: str, method: str, path: str, body: Mapping[str, Any] | None = None, *, root: Path | None = None,
         opener: join.Opener | None = None) -> tuple[int, dict[str, Any]]:
    status, answer = join._call(relay, method, path, body, link.identity(root=root), opener=opener)
    return status, answer if isinstance(answer, dict) else {}


# ── linking a phone ─────────────────────────────────────────────────────────


def _join_mac(secret: bytes, phone_id: str, sign_key: str, seal_key: str) -> str:
    message = f"passbook-phone-join:v1\n{phone_id}\n{sign_key}\n{seal_key}".encode("utf-8")
    return join._b64(hmac.new(secret, message, hashlib.sha256).digest())


def begin(*, label: str = "", relay: str = "", root: Path | None = None, opener: join.Opener | None = None) -> dict[str, Any]:
    """Open a link for a phone. Returns the address to open on it, good for fifteen minutes.

    The address is a secret until it is used: whoever opens it first is the phone that joins. That
    is why `confirm` is a separate step a person takes after seeing which phone it was.
    """
    chosen = join.relay_url(relay)
    status, answer = _ask(chosen, "POST", "/api/passbook/phones", {"label": label or "A phone"}, root=root, opener=opener)
    if status != 200 or not answer.get("ok") or not ID_SHAPE.fullmatch(str(answer.get("phoneId") or "")):
        raise PhoneError(str(answer.get("error") or "The relay did not open a link for a phone. Try again in a moment."),
                         str(answer.get("code") or ""))
    secret = secrets.token_bytes(32)
    me = link.identity(root=root)
    code = ".".join([CODE_VERSION, answer["phoneId"], join._b64(secret), join._b64(me["did"].encode("utf-8")),
                     join._b64(join.machine_label().encode("utf-8"))])
    now = link._stamp(link._now())
    state = _read(root)
    state["pending"] = [item for item in state["pending"] if item.get("expires", "") > now]
    state["pending"].append({"id": answer["phoneId"], "secret": join._b64(secret), "relay": chosen,
                             "expires": str(answer.get("expiresAt") or "")})
    _write(state, root)
    return {"ok": True, "id": answer["phoneId"], "url": f"{chosen}/phone#{code}", "expires": str(answer.get("expiresAt") or "")}


def _pending(phone_id: str, root: Path | None) -> dict[str, Any]:
    item = next((entry for entry in _read(root)["pending"] if entry.get("id") == phone_id), None)
    if item is None:
        raise PhoneError("That phone link was not started on this machine, or has been finished already.")
    return item


def check(phone_id: str, *, root: Path | None = None, opener: join.Opener | None = None) -> dict[str, Any]:
    """Has a phone joined, and is it the one that read this machine's code?

    `waiting`, `joined` (with the phone's own name for itself), `expired`, or `refused` when
    something joined without the code's secret. A refused link is closed here and on the relay.
    """
    item = _pending(phone_id, root)
    status, seen = _ask(item["relay"], "GET", f"/api/passbook/phones/{phone_id}", root=root, opener=opener)
    if status != 200 or seen.get("status") in ("expired", "revoked"):
        return {"ok": True, "status": "expired", "label": ""}
    if seen.get("status") != "joined":
        return {"ok": True, "status": "waiting", "label": ""}
    sign_key, seal_key = str(seen.get("signKey") or ""), str(seen.get("sealKey") or "")
    expected = _join_mac(join._unb64(item["secret"]), phone_id, sign_key, seal_key)
    if not _is_point(sign_key) or not _is_point(seal_key) or not hmac.compare_digest(expected, str(seen.get("mac") or "")):
        remove(phone_id, root=root, opener=opener)
        return {"ok": True, "status": "refused", "label": "",
                "detail": "Something joined without this link's secret, so it was turned away. Start again."}
    return {"ok": True, "status": "joined", "label": str(seen.get("label") or "A phone")[:40]}


def _is_point(text: str) -> bool:
    try:
        raw = join._unb64(text)
    except (ValueError, TypeError):
        return False
    return len(raw) == P256_POINT and raw[0] == 4


def confirm(phone_id: str, *, root: Path | None = None, opener: join.Opener | None = None) -> dict[str, Any]:
    """The person has seen which phone joined and wants it. From now on it may be asked."""
    item = _pending(phone_id, root)
    seen_status = check(phone_id, root=root, opener=opener)
    if seen_status["status"] != "joined":
        raise PhoneError({"waiting": "No phone has opened that link yet.",
                          "expired": "That link ran out. Start again.",
                          "refused": seen_status.get("detail", "That link was refused.")}.get(seen_status["status"], "That link cannot be confirmed."))
    # Read the keys again and keep exactly what the HMAC covered: what is stored is what was checked.
    status, seen = _ask(item["relay"], "GET", f"/api/passbook/phones/{phone_id}", root=root, opener=opener)
    sign_key, seal_key = str(seen.get("signKey") or ""), str(seen.get("sealKey") or "")
    expected = _join_mac(join._unb64(item["secret"]), phone_id, sign_key, seal_key)
    if status != 200 or not hmac.compare_digest(expected, str(seen.get("mac") or "")):
        raise PhoneError("That phone changed between being shown and being confirmed. Start again.")
    status, answer = _ask(item["relay"], "POST", f"/api/passbook/phones/{phone_id}/confirm", {}, root=root, opener=opener)
    if status != 200 or not answer.get("ok"):
        raise PhoneError(str(answer.get("error") or "The relay did not confirm that phone. Try again in a moment."))
    phone = {"id": phone_id, "label": seen_status["label"], "relay": item["relay"], "signKey": sign_key,
             "sealKey": seal_key, "linkedAt": link._stamp(link._now())}
    state = _read(root)
    state["pending"] = [entry for entry in state["pending"] if entry.get("id") != phone_id]
    state["phones"] = [entry for entry in state["phones"] if entry.get("id") != phone_id] + [phone]
    _write(state, root)
    link._record("link", [], granted=True, reason=f"phone linked: {phone['label']}", root=root, workspace=passbook.workspace())
    return {"ok": True, "phone": {"id": phone_id, "label": phone["label"]}}


def remove(phone_id: str, *, root: Path | None = None, opener: join.Opener | None = None) -> dict[str, Any]:
    """Unlink a phone, or abandon a link that was started. It is asked nothing more."""
    state = _read(root)
    known = next((entry for entry in [*state["phones"], *state["pending"]] if entry.get("id") == phone_id), None)
    if known is None:
        raise PhoneError("That phone is not linked to this machine.")
    told = True
    try:
        _ask(known["relay"], "DELETE", f"/api/passbook/phones/{phone_id}", root=root, opener=opener)
    except join.JoinError:
        told = False
    was_linked = any(entry.get("id") == phone_id for entry in state["phones"])
    state["phones"] = [entry for entry in state["phones"] if entry.get("id") != phone_id]
    state["pending"] = [entry for entry in state["pending"] if entry.get("id") != phone_id]
    _write(state, root)
    if was_linked:
        link._record("unlink", [], granted=True, reason=f"phone unlinked: {known.get('label', '')}", root=root,
                     workspace=passbook.workspace())
    # Local first and always: this machine stops trusting the phone's key whether or not the relay heard.
    return {"ok": True, "told": told}


def listed(*, root: Path | None = None, opener: join.Opener | None = None) -> list[dict[str, Any]]:
    """Linked phones, with when each last looked for requests if the relay can say."""
    phones = linked(root)
    seen: dict[str, str] = {}
    for relay in sorted({phone["relay"] for phone in phones}):
        try:
            status, answer = _ask(relay, "GET", "/api/passbook/phones", root=root, opener=opener)
        except join.JoinError:
            continue
        if status == 200:
            seen.update({str(row.get("id")): str(row.get("seenAt") or "") for row in answer.get("phones") or [] if isinstance(row, Mapping)})
    return [{"id": phone["id"], "label": phone.get("label", ""), "linkedAt": phone.get("linkedAt", ""),
             "seenAt": seen.get(phone["id"], "")} for phone in phones]


# ── asking ──────────────────────────────────────────────────────────────────


def seal(plaintext: str, seal_key: str) -> str:
    """Encrypt a request to a phone. Only that phone's browser can open it."""
    ec, hashes, serialization, AESGCM, HKDF, _, _ = _crypto()
    theirs_raw = join._unb64(seal_key)
    theirs = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), theirs_raw)
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    mine_raw = ephemeral.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    shared = ephemeral.exchange(ec.ECDH(), theirs)
    # The same derivation the page does: both public keys are bound in, so a box cannot be re-aimed.
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"",
               info=b"passbook-phone-seal:v1" + mine_raw + theirs_raw).derive(shared)
    nonce = secrets.token_bytes(12)
    box = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return ".".join([SEAL_PREFIX, join._b64(mine_raw), join._b64(nonce), join._b64(box)])


def request_text(*, rid: str, owner: str, app: str, keys: list[str], reason: str, kind: str, workspace: str,
                 seconds: float) -> str:
    """The exact text a phone is shown and signs the digest of. Key names, never values."""
    now = int(time.time())
    return json.dumps({"v": 1, "rid": rid, "owner": owner, "machine": join.machine_label(), "app": str(app)[:80],
                       "keys": sorted(str(key) for key in keys)[:50], "reason": str(reason)[:200], "kind": kind,
                       "workspace": str(workspace)[:64], "asked": now, "expires": now + int(seconds)},
                      separators=(",", ":"), sort_keys=True)


def ask(*, rid: str, app: str, keys: list[str], reason: str = "", kind: str = "read", workspace: str = "",
        seconds: float = 120, root: Path | None = None, opener: join.Opener | None = None) -> list[dict[str, Any]]:
    """Send one waiting request to every linked phone. Returns what to poll, or [] if none was asked.

    Never raises for a phone that could not be reached: a request that cannot go to a phone is
    still waiting at the machine, exactly as it was before phones existed.
    """
    if kind not in ASKABLE_KINDS:
        return []
    phones = linked(root)
    if not phones:
        return []
    owner = link.identity(root=root)["did"]
    text = request_text(rid=rid, owner=owner, app=app, keys=keys, reason=reason, kind=kind, workspace=workspace, seconds=seconds)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    sent: list[dict[str, Any]] = []
    for phone in phones:
        try:
            status, answer = _ask(phone["relay"], "POST", "/api/passbook/approvals",
                                  {"phone": phone["id"], "sealed": seal(text, phone["sealKey"]), "seconds": int(seconds)},
                                  root=root, opener=opener)
        except (join.JoinError, ValueError):
            continue
        if status == 200 and answer.get("ok") and ID_SHAPE.fullmatch(str(answer.get("approvalId") or "")):
            sent.append({"approval": answer["approvalId"], "phone": phone["id"], "label": phone.get("label", ""),
                         "relay": phone["relay"], "signKey": phone["signKey"], "rid": rid, "digest": digest, "owner": owner})
    return sent


def verify(answer_text: str, asked: Mapping[str, Any], *, now: float | None = None) -> dict[str, Any] | None:
    """A phone's answer, if and only if that phone signed it for this request. Otherwise None.

    Everything is checked against what this machine sent and what it stored when the phone was
    linked. Nothing in the answer is believed because the answer says so.
    """
    ec, hashes, _, _, _, encode_dss_signature, InvalidSignature = _crypto()
    try:
        answer = json.loads(answer_text)
        decision, remember, at = str(answer["decision"]), int(answer["remember"]), int(answer["at"])
        signature = join._unb64(str(answer["signature"]))
    except (ValueError, KeyError, TypeError):
        return None
    if answer.get("rid") != asked["rid"] or answer.get("digest") != asked["digest"]:
        return None
    if decision not in ("allow", "deny") or remember not in REMEMBER_SECONDS or len(signature) != 64:
        return None
    if abs((time.time() if now is None else now) - at) > ANSWER_SKEW_SECONDS:
        return None
    message = "\n".join(["passbook-approval:v1", asked["owner"], asked["rid"], asked["digest"], decision,
                         str(remember), str(at)]).encode("utf-8")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), join._unb64(asked["signKey"]))
        # WebCrypto signs as r||s; `cryptography` wants DER.
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        key.verify(der, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return None
    return {"approve": decision == "allow", "remember": remember, "label": asked.get("label", ""), "phone": asked["phone"]}


def poll(sent: list[Mapping[str, Any]], *, root: Path | None = None, opener: join.Opener | None = None) -> dict[str, Any] | None:
    """The first verified answer among what was sent, or None while none has arrived."""
    for asked in sent:
        try:
            status, answer = _ask(asked["relay"], "GET", f"/api/passbook/approvals/{asked['approval']}", root=root, opener=opener)
        except join.JoinError:
            continue
        if status == 200 and answer.get("status") == "decided" and answer.get("answer"):
            verdict = verify(str(answer["answer"]), asked)
            if verdict is not None:
                return verdict
    return None


def withdraw(sent: list[Mapping[str, Any]], *, root: Path | None = None, opener: join.Opener | None = None) -> None:
    """Take a request back off every phone: it was answered at the machine, or it ran out."""
    for asked in sent:
        try:
            _ask(asked["relay"], "DELETE", f"/api/passbook/approvals/{asked['approval']}", root=root, opener=opener)
        except join.JoinError:
            pass


def page_url(root: Path | None = None) -> str:
    """Where a linked phone goes to answer. No secret in it: the phone already has its key."""
    phones = linked(root)
    return f"{phones[0]['relay']}/phone" if phones else ""
