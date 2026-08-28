# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""PassBook machine linking — lending named keys to a second machine.

Optional companion to `passbook.py`. A machine works fine without it; this adds
the multi-machine half, and it is a separate file so a project can adopt the
store without adopting linking.

## What linking is

Machine A lends machine B **named keys**, for a **stated period**, after a human
on A has confirmed B's fingerprint out of band. Not the store — named keys. A
laptop that renders video gets the three keys it renders with, not all 273.

## The four properties this is built for

**Membership is not authorization.** Being on the same tailnet, LAN, or account
grants nothing. Every key that moves moves because a human on the owning machine
approved a specific fingerprint for a specific list. There is no listening
service here on purpose: nothing to reach, so reachability decides nothing.

**The second factor is the fingerprint.** A pairing token could be intercepted
and swapped for the attacker's own — that attack is invisible if the only check
is "did the token arrive". So the token carries a short fingerprint that both
machines print, and approving requires typing it back. The human comparing two
screens is what a swapped token cannot survive.

**Values are sealed to the device, not to the network.** The envelope is
encrypted to B's device key with an ephemeral ECDH exchange, so it is safe on
any transport — a shared drive, a paste buffer, `scp`, a tailnet copy. Whoever
carries it learns nothing.

**A grant is narrow and it expires.** Named keys, one workspace, an expiry, and
a nonce that cannot be replayed.

## What it does NOT do

Revoking a grant stops the *next* envelope. It cannot reach back into machine B
and unsend a value that has already been delivered — nothing can. **A revoked
key that mattered must be rotated at the provider.** Anything that claimed
otherwise would be lying about what a credential is.

Nor is there a transport in here. The envelope is a string; move it however you
already move things between your machines. Keeping transport out is what keeps
the first property true.

Accepted keys land in the receiving machine's *active* workspace store, so a
borrowed key is scoped on arrival rather than dropped machine-wide. Workspace
ids are local to each machine and are not compared across the link: the sender
scopes what it lends, the receiver scopes where it lands, and neither has to
know the other's naming.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, NamedTuple

import passbook

__all__ = [
    "DEVICE_FILENAME",
    "GRANTS_FILENAME",
    "LinkError",
    "accept",
    "available",
    "fingerprint_of",
    "grant",
    "grants",
    "identity",
    "pairing_token",
    "read_pairing_token",
    "revoke",
]

DEVICE_FILENAME = "passbook-device.json"
GRANTS_FILENAME = "passbook-grants.json"
SPEC_VERSION = 1

PAIR_PREFIX = "passbook-pair:v1:"
ENVELOPE_PREFIX = "passbook-env:v1:"

PAIRING_TTL_SECONDS = 600
DEFAULT_GRANT_DAYS = 30


class LinkError(RuntimeError):
    """Something about a link is wrong. The message is safe to show a person."""


def available() -> bool:
    """Whether this machine can link at all."""
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


def _require_crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError:  # pragma: no cover — exercised on a host without it
        raise LinkError(
            "Machine linking needs a runtime that setup has not provided yet. "
            "Run `passbook install`, which provisions one without touching the "
            "system Python."
        ) from None
    return _Crypto(serialization, ed25519, x25519, AESGCM, HKDF, hashes)


class _Crypto(NamedTuple):
    serialization: Any
    ed25519: Any
    x25519: Any
    AESGCM: Any
    HKDF: Any
    hashes: Any


def _derive(shared: bytes, crypto: "_Crypto") -> bytes:
    """One place that turns an ECDH result into a key, so both sides cannot drift."""
    return crypto.HKDF(
        algorithm=crypto.hashes.SHA256(), length=32, salt=None, info=b"passbook-link:v1",
    ).derive(shared)


# ── did:key, so a DID *is* a public key ────────────────────────────────────
#
# Using did:key rather than a registry means a receiving machine can verify a
# signature from the DID alone. There is nothing to look up, so there is no
# lookup to poison, and an envelope carries its own proof of origin.

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 58)
        out = _B58[remainder] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def _b58decode(text: str) -> bytes:
    number = 0
    for character in text:
        index = _B58.find(character)
        if index < 0:
            raise LinkError("That is not a valid identifier.")
        number = number * 58 + index
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def did_from_public(sign_public: bytes) -> str:
    """A `did:key` for an Ed25519 public key — multicodec 0xed01, base58btc."""
    return "did:key:z" + _b58encode(b"\xed\x01" + sign_public)


def public_from_did(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise LinkError(f"{did!r} is not a did:key identifier.")
    raw = _b58decode(did[len("did:key:z"):])
    if not raw.startswith(b"\xed\x01") or len(raw) != 34:
        raise LinkError("That identifier is not an Ed25519 did:key.")
    return raw[2:]


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def fingerprint_of(sign_public: bytes, seal_public: bytes) -> str:
    """A short string a human can compare across two screens.

    Base32 over a digest of both public keys: no lookalike characters, and
    short enough to read aloud without losing the thread. This is the second
    factor — a swapped pairing token cannot produce a matching fingerprint.
    """
    digest = hashlib.sha256(sign_public + seal_public).digest()[:10]
    text = base64.b32encode(digest).decode("ascii").rstrip("=")
    return "-".join(text[index:index + 4] for index in range(0, len(text), 4))


# ── this machine's identity ────────────────────────────────────────────────


def device_path(root: Path | None = None) -> Path:
    return (Path(root) if root is not None else passbook.root()) / DEVICE_FILENAME


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _stamp(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _parse_stamp(text: str) -> datetime:
    return datetime.fromisoformat(str(text).replace("Z", "+00:00"))


def identity(*, root: Path | None = None) -> dict[str, Any]:
    """This machine's DID and fingerprint, generating the keys on first use.

    The private keys sit in a `0600` file beside the store, which is the same
    protection the store itself has: it stops another account on this box, not
    code running as you. Moving them into the OS keychain is the upgrade, and
    it does not change anything a caller sees.
    """
    crypto = _require_crypto()
    serialization, ed25519, x25519 = crypto.serialization, crypto.ed25519, crypto.x25519
    path = device_path(root)
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
        sign_private = ed25519.Ed25519PrivateKey.from_private_bytes(_unb64(saved["sign_private"]))
        seal_private = x25519.X25519PrivateKey.from_private_bytes(_unb64(saved["seal_private"]))
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        sign_private = ed25519.Ed25519PrivateKey.generate()
        seal_private = x25519.X25519PrivateKey.generate()
        saved = {
            "spec_version": SPEC_VERSION,
            "created": _stamp(_now()),
            "sign_private": _b64(sign_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )),
            "seal_private": _b64(seal_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        # Written 0600 from the start — never created readable and tightened
        # afterwards, because the gap between those two is the whole exposure.
        handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(saved, stream, indent=2)
        os.chmod(path, 0o600)

    sign_public = sign_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    seal_public = seal_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return {
        "did": did_from_public(sign_public),
        "fingerprint": fingerprint_of(sign_public, seal_public),
        "sign_public": sign_public,
        "seal_public": seal_public,
        "_sign_private": sign_private,
        "_seal_private": seal_private,
        "created": saved.get("created", ""),
    }


def describe_identity(*, root: Path | None = None) -> dict[str, str]:
    """The public half only — safe to print, log, or hand to another machine."""
    me = identity(root=root)
    return {"did": me["did"], "fingerprint": me["fingerprint"], "created": me["created"]}


# ── pairing ────────────────────────────────────────────────────────────────


def pairing_token(*, ttl_seconds: int = PAIRING_TTL_SECONDS, root: Path | None = None) -> dict[str, str]:
    """Run on the JOINING machine. Hand the token to the machine that has the keys.

    The token is public: it holds two public keys and an expiry, nothing else.
    Intercepting it achieves nothing, and *swapping* it is what the fingerprint
    check is there to catch.
    """
    me = identity(root=root)
    expires = _now() + timedelta(seconds=max(60, ttl_seconds))
    payload = {
        "v": SPEC_VERSION,
        "did": me["did"],
        "seal": _b64(me["seal_public"]),
        "exp": _stamp(expires),
    }
    token = PAIR_PREFIX + _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return {"token": token, "fingerprint": me["fingerprint"], "did": me["did"], "expires": payload["exp"]}


def read_pairing_token(token: str) -> dict[str, Any]:
    """Parse and expiry-check a pairing token. Raises rather than half-trusting."""
    text = str(token).strip()
    if not text.startswith(PAIR_PREFIX):
        raise LinkError("That does not look like a pairing token.")
    try:
        payload = json.loads(_unb64(text[len(PAIR_PREFIX):]).decode("utf-8"))
        sign_public = public_from_did(payload["did"])
        seal_public = _unb64(payload["seal"])
        expires = _parse_stamp(payload["exp"])
    except LinkError:
        raise
    except Exception:
        raise LinkError("That pairing token is damaged; ask for a fresh one.") from None
    if len(seal_public) != 32:
        raise LinkError("That pairing token is damaged; ask for a fresh one.")
    if expires <= _now():
        raise LinkError("That pairing token has expired. Run `passbook-link request` again.")
    return {
        "did": payload["did"],
        "sign_public": sign_public,
        "seal_public": seal_public,
        "fingerprint": fingerprint_of(sign_public, seal_public),
        "expires": payload["exp"],
    }


# ── grants ─────────────────────────────────────────────────────────────────


def grants_path(root: Path | None = None) -> Path:
    return (Path(root) if root is not None else passbook.root()) / GRANTS_FILENAME


def _read_grants(root: Path | None = None) -> dict[str, Any]:
    try:
        loaded = json.loads(grants_path(root).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {"version": SPEC_VERSION, "issued": [], "accepted": []}
    if not isinstance(loaded, dict):
        return {"version": SPEC_VERSION, "issued": [], "accepted": []}
    loaded.setdefault("issued", [])
    loaded.setdefault("accepted", [])
    return loaded


def _write_grants(state: Mapping[str, Any], root: Path | None = None) -> None:
    path = grants_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        json.dump(state, stream, indent=2, sort_keys=True)
    os.chmod(path, 0o600)


def _canonical(value: Any) -> str:
    """Same canonical JSON as the access ledger, so one signature rule serves both."""
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    if not isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    entries = sorted((key, item) for key, item in value.items() if item is not None)
    body = ",".join(f"{json.dumps(key, ensure_ascii=False)}:{_canonical(item)}" for key, item in entries)
    return "{" + body + "}"


def grant(
    token: str,
    keys: Iterable[str],
    *,
    confirm_fingerprint: str,
    workspace: str = "",
    days: int = DEFAULT_GRANT_DAYS,
    root: Path | None = None,
    stores: Iterable[str | Path] | None = None,
) -> dict[str, Any]:
    """Run on the OWNING machine. Approve a device for named keys and seal them.

    `confirm_fingerprint` is not a formality: it is the whole second factor, and
    it is a required argument rather than an optional flag so that no caller can
    skip the human check by forgetting one.

    Returns the grant and a sealed envelope. Keys the store does not hold are
    reported as missing rather than silently dropped — a link that quietly
    delivers two of three keys is worse than one that fails.
    """
    crypto = _require_crypto()
    serialization, x25519, AESGCM = crypto.serialization, crypto.x25519, crypto.AESGCM
    peer = read_pairing_token(token)

    given = "".join(str(confirm_fingerprint).split()).upper().replace("-", "")
    expected = peer["fingerprint"].replace("-", "")
    if not secrets.compare_digest(given, expected):
        raise LinkError(
            "That fingerprint does not match the pairing token.\n"
            "Stop: either it was mistyped, or the token you were given is not "
            "the one the other machine printed. Compare both screens again."
        )

    wanted = sorted({str(key).strip() for key in keys if str(key).strip()})
    if not wanted:
        raise LinkError("Name at least one key to lend.")

    me = identity(root=root)
    if peer["did"] == me["did"]:
        raise LinkError("That pairing token is this machine's own.")

    available_values = passbook.request(
        wanted, app="passbook-link", reason=f"link to {peer['did']}",
        workspace_id=workspace or passbook.workspace(), stores=stores,
    )
    missing = [key for key in wanted if key not in available_values]
    if missing:
        raise LinkError(f"Not in this machine's store: {', '.join(missing)}.")

    issued = _now()
    expires = issued + timedelta(days=max(1, int(days)))
    # UCAN's shape: issuer, audience, attenuated capability, validity window.
    # `att` says what may be done and with which keys, so a grant is readable as
    # a capability rather than as a blob of trust.
    body = {
        "kind": "passbook-grant",
        "specVersion": SPEC_VERSION,
        "iss": me["did"],
        "aud": peer["did"],
        "att": [{
            "with": f"passbook://{workspace or passbook.workspace() or 'main'}",
            "can": "env/read",
            "nb": {"keys": wanted},
        }],
        "nbf": _stamp(issued),
        "exp": _stamp(expires),
        "nonce": _b64(secrets.token_bytes(16)),
    }

    # Seal to the peer's device: an ephemeral exchange, so the envelope's key
    # exists only for this envelope and compromising the device later does not
    # retroactively open envelopes captured earlier.
    ephemeral = x25519.X25519PrivateKey.generate()
    shared = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(peer["seal_public"]))
    secret = _derive(shared, crypto)
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps({"keys": available_values, "grant_nonce": body["nonce"]},
                           separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(secret).encrypt(nonce, plaintext, _canonical(body).encode("utf-8"))

    envelope: dict[str, Any] = {
        "v": SPEC_VERSION,
        "grant": body,
        # The issuer's sealing key travels inside the signed envelope so the
        # receiver can compute the issuer's fingerprint and check it against the
        # sending machine's screen. Without this the receiver can verify only
        # that SOME key signed the envelope, not whose.
        "iss_seal": _b64(me["seal_public"]),
        "eph": _b64(ephemeral.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)),
        "nonce": _b64(nonce),
        "ct": _b64(ciphertext),
    }
    envelope["sig"] = _b64(me["_sign_private"].sign(_canonical(envelope).encode("utf-8")))

    state = _read_grants(root)
    state["issued"] = [item for item in state["issued"] if item.get("aud") != peer["did"]]
    state["issued"].append({**body, "fingerprint": peer["fingerprint"], "revoked": False})
    _write_grants(state, root)
    _record("link", wanted, granted=True, reason=f"granted to {peer['fingerprint']}")

    return {
        "grant": body,
        "envelope": ENVELOPE_PREFIX + _b64(json.dumps(envelope, separators=(",", ":")).encode("utf-8")),
        "keys": wanted,
        "fingerprint": peer["fingerprint"],
        "issuer_fingerprint": me["fingerprint"],
        "did": peer["did"],
        "expires": body["exp"],
    }


def envelope_issuer(envelope: str) -> dict[str, Any]:
    """Who an envelope claims to be from, with its signature already checked.

    Safe to call before accepting: it verifies the signature and returns the
    issuer's DID and fingerprint so a person can compare them against the
    sending machine, but writes nothing and opens nothing.
    """
    crypto = _require_crypto()
    text = str(envelope).strip()
    if not text.startswith(ENVELOPE_PREFIX):
        raise LinkError("That does not look like a PassBook envelope.")
    try:
        parsed = json.loads(_unb64(text[len(ENVELOPE_PREFIX):]).decode("utf-8"))
        body = parsed["grant"]
        signature = _unb64(parsed["sig"])
        issuer_public = public_from_did(body["iss"])
        issuer_seal = _unb64(parsed["iss_seal"])
    except LinkError:
        raise
    except Exception:
        raise LinkError("That envelope is damaged; ask for a fresh one.") from None

    unsigned = {key: value for key, value in parsed.items() if key != "sig"}
    try:
        crypto.ed25519.Ed25519PublicKey.from_public_bytes(issuer_public).verify(
            signature, _canonical(unsigned).encode("utf-8"))
    except Exception:
        raise LinkError(
            "That envelope's signature does not match the machine it claims to be from. "
            "Do not use it."
        ) from None

    keys: list[str] = []
    for capability in body.get("att", []):
        if capability.get("can") == "env/read":
            keys.extend(capability.get("nb", {}).get("keys", []))
    return {
        "did": body["iss"],
        "fingerprint": fingerprint_of(issuer_public, issuer_seal),
        "keys": sorted(set(keys)),
        "expires": body.get("exp", ""),
        "_parsed": parsed,
    }


def known_issuer(did: str, *, root: Path | None = None) -> bool:
    """Whether this machine has already accepted an envelope from that DID.

    The first envelope from a machine needs its fingerprint confirmed by a
    person. After that the DID is established, so later envelopes from the same
    machine do not re-ask — the check exists to bind an identity once, not to be
    a recurring ritual people learn to click through.
    """
    return any(item.get("iss") == str(did) for item in _read_grants(root).get("accepted", []))


def accept(
    envelope: str,
    *,
    confirm_fingerprint: str = "",
    root: Path | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Run on the JOINING machine. Open an envelope and write the keys in.

    Every check that could fail closed does: the signature must verify against
    the issuing DID, the issuer must be one this machine has confirmed, the
    audience must be this machine, the grant must be in its validity window, and
    a nonce already seen is refused outright.

    The issuer check is not symmetry for its own sake. Anyone who saw this
    machine's pairing token knows its public key, and could seal a valid
    envelope of their OWN keys to it — keys pointing at a proxy that logs every
    prompt. Accepting an envelope is therefore as much a trust decision as
    granting one, and it gets the same fingerprint.
    """
    crypto = _require_crypto()
    x25519, AESGCM = crypto.x25519, crypto.AESGCM
    issuer = envelope_issuer(envelope)
    parsed = issuer["_parsed"]
    body = parsed["grant"]

    me = identity(root=root)
    # Cheapest and most common honest failure first: the envelope simply is not
    # for this machine. Saying so beats a trust warning about a stranger.
    if body.get("aud") != me["did"]:
        raise LinkError("That envelope was sealed for a different machine.")

    if not known_issuer(issuer["did"], root=root):
        given = "".join(str(confirm_fingerprint).split()).upper().replace("-", "")
        if not given:
            raise LinkError(
                f"This envelope is from a machine this one has not accepted from before.\n"
                f"Its fingerprint is {issuer['fingerprint']}.\n"
                "Check that against the sending machine's screen, then accept with "
                "--confirm and that fingerprint."
            )
        if not secrets.compare_digest(given, issuer["fingerprint"].replace("-", "")):
            raise LinkError(
                "That fingerprint does not match the machine that signed this envelope.\n"
                "Stop: the envelope did not come from the machine you think it did."
            )

    if _parse_stamp(body["exp"]) <= _now():
        raise LinkError("That grant has expired. Ask for a new one.")
    if _parse_stamp(body["nbf"]) > _now() + timedelta(minutes=5):
        raise LinkError("That grant is not valid yet; check both machines' clocks.")

    state = _read_grants(root)
    if any(item.get("nonce") == body.get("nonce") for item in state["accepted"]):
        raise LinkError("That envelope has already been used. Ask for a new one.")

    shared = me["_seal_private"].exchange(x25519.X25519PublicKey.from_public_bytes(_unb64(parsed["eph"])))
    secret = _derive(shared, crypto)
    try:
        opened = json.loads(AESGCM(secret).decrypt(
            _unb64(parsed["nonce"]), _unb64(parsed["ct"]), _canonical(body).encode("utf-8")))
    except Exception:
        raise LinkError("That envelope could not be opened on this machine.") from None

    permitted = set()
    for capability in body.get("att", []):
        if capability.get("can") == "env/read":
            permitted.update(capability.get("nb", {}).get("keys", []))
    # The grant, not the ciphertext, decides what lands. If they ever disagree
    # the signed half wins, so a tampered payload cannot widen a grant.
    values = {key: value for key, value in opened.get("keys", {}).items() if key in permitted}
    if not values:
        raise LinkError("That envelope carried nothing this grant permits.")

    # Lands in the receiver's ACTIVE workspace store, not machine-wide — a
    # borrowed key should be no broader on arrival than the scope that asked
    # for it.
    written = passbook.set_values(values, overwrite=overwrite)
    state["accepted"].append({
        "iss": body["iss"], "nonce": body["nonce"], "exp": body["exp"],
        "keys": sorted(values), "at": _stamp(_now()),
    })
    _write_grants(state, root)
    _record("link", sorted(values), granted=True, reason=f"accepted from {body['iss']}")

    return {
        "from": body["iss"],
        "keys": sorted(values),
        "added": written["added"],
        "kept": written["kept"],
        "updated": written["updated"],
        "path": written["path"],
        "workspace": passbook.workspace(),
        "expires": body["exp"],
    }


# ── tailnet adoption ───────────────────────────────────────────────────────
#
# A machine can hold this store for a second reason: it shares the tailnet, and
# replication reaches it. That is real access and it belonged on the Machines
# page, but it is NOT a grant and must never be recorded as one.
#
# A grant is signed, names the keys it covers, and required a person to compare
# a fingerprint on two screens. A tailnet adoption has none of that: the trust
# came from tailnet membership, which somebody established elsewhere. Writing
# it into `issued` would make the page say a fingerprint was checked when none
# was, and the fingerprint check is the entire second factor.
#
# So it gets its own list, surfaces beside grants with `via` saying which kind
# it is, and revokes through the same door.

def adopt(host: str, *, keys: Iterable[str] = (), node: str = "",
          root: Path | None = None) -> dict[str, Any]:
    """Record that a tailnet machine receives this store. Idempotent."""
    name = str(host).strip()
    if not name:
        raise LinkError("Which machine?")
    state = _read_grants(root)
    adopted = state.setdefault("tailnet", [])
    for entry in adopted:
        if entry.get("host") == name:
            entry["seen"] = _stamp(_now())
            entry["keys"] = sorted({*entry.get("keys", []), *[str(k) for k in keys]})
            entry.pop("revoked", None)
            _write_grants(state, root)
            return dict(entry)
    entry = {
        "host": name,
        "node": str(node or ""),
        "keys": sorted({str(k) for k in keys}),
        "adopted": _stamp(_now()),
        "seen": _stamp(_now()),
    }
    adopted.append(entry)
    _write_grants(state, root)
    _record("link", sorted(entry["keys"]), granted=True,
            reason=f"adopted tailnet machine {name}")
    return dict(entry)


def forget(host: str, *, root: Path | None = None) -> dict[str, Any]:
    """Stop counting a tailnet machine as holding this store.

    Like `revoke`, this does not unsend anything. The store is already on that
    machine; what changes is that PassBook stops saying it belongs there.
    """
    name = str(host).strip()
    state = _read_grants(root)
    for entry in state.get("tailnet", []):
        if entry.get("host") == name:
            entry["revoked"] = _stamp(_now())
            _write_grants(state, root)
            _record("unlink", sorted(entry.get("keys", [])), granted=True,
                    reason=f"forgot tailnet machine {name}")
            return {"host": name, "revoked": True,
                    "rotate": sorted(entry.get("keys", []))}
    raise LinkError(f"No tailnet machine called {name!r} is recorded here.")


def adopted(*, root: Path | None = None) -> list[dict[str, Any]]:
    return [dict(entry) for entry in _read_grants(root).get("tailnet", [])]


def grants(*, root: Path | None = None) -> dict[str, Any]:
    """What this machine has lent and borrowed. Key names only."""
    state = _read_grants(root)
    now = _now()

    def shape(entry: Mapping[str, Any], role: str) -> dict[str, Any]:
        keys: list[str] = []
        for capability in entry.get("att", []):
            keys.extend(capability.get("nb", {}).get("keys", []))
        expired = _parse_stamp(entry["exp"]) <= now if entry.get("exp") else False
        return {
            "role": role,
            "did": entry.get("aud") if role == "lent" else entry.get("iss"),
            "fingerprint": entry.get("fingerprint", ""),
            "keys": sorted(keys or entry.get("keys", [])),
            "expires": entry.get("exp", ""),
            "revoked": bool(entry.get("revoked")),
            "active": not expired and not entry.get("revoked"),
        }

    def shape_tailnet(entry: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "role": "lent",
            "via": "tailnet",
            "host": entry.get("host", ""),
            "did": "",
            "fingerprint": "",
            "keys": sorted(entry.get("keys", [])),
            "expires": "",
            "revoked": bool(entry.get("revoked")),
            "active": not entry.get("revoked"),
            "adopted": entry.get("adopted", ""),
            "seen": entry.get("seen", ""),
        }

    return {
        "did": describe_identity(root=root)["did"] if available() else "",
        "lent": [{**shape(item, "lent"), "via": "grant"} for item in state["issued"]],
        "borrowed": [{**shape(item, "borrowed"), "via": "grant"}
                     for item in state["accepted"]],
        "tailnet": [shape_tailnet(item) for item in state.get("tailnet", [])],
    }


def revoke(did: str, *, root: Path | None = None) -> dict[str, Any]:
    """Stop lending to a machine.

    This prevents the next envelope. It cannot unsend what was already
    delivered, so the returned `rotate` list is the real remediation — those
    keys are on the other machine until they are changed at the provider.
    """
    state = _read_grants(root)
    target = str(did).strip()
    hit = [item for item in state["issued"] if item.get("aud") == target and not item.get("revoked")]
    if not hit:
        return {"ok": False, "detail": f"No active grant to {target}.", "rotate": []}
    exposed: set[str] = set()
    for item in hit:
        item["revoked"] = True
        item["revoked_at"] = _stamp(_now())
        for capability in item.get("att", []):
            exposed.update(capability.get("nb", {}).get("keys", []))
    _write_grants(state, root)
    _record("unlink", sorted(exposed), granted=True, reason=f"revoked {target}")
    return {
        "ok": True,
        "did": target,
        "rotate": sorted(exposed),
        "detail": (
            f"Revoked. {len(exposed)} key(s) were already delivered to that machine "
            "and are still valid until you rotate them at the provider."
        ),
    }


def _record(op: str, keys: Iterable[str], *, granted: bool, reason: str) -> None:
    """Stamp a link event. A missing ledger must never break a link."""
    try:
        import passbook_stamp

        passbook_stamp.stamp(op=op, keys=keys, app="passbook-link", granted=granted, reason=reason)
    except Exception:  # noqa: BLE001 — a receipt is never worth failing the operation for
        pass
