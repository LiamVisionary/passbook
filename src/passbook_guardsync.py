# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Guarded keys between paired machines: sealed to the machine, carrying their guard.

Liam, 2026-11-28: "i designed passbook to keep keys in sync", and then "Yes, build it". A guarded key
(`passbook guard`) may not leave its machine as plaintext, so fleet sync keeps it home. That left his
two Macs out of step on exactly the keys that matter most. This is how a guarded key travels instead:

- **Only to a machine paired here on purpose.** Pairing takes the other machine's code, its
  fingerprint typed back, and this vault's password or recovery code. A process running as the owner
  can approve a broker request, but it does not know the password, so it cannot pair a device of its
  own and have every guarded key sealed to it.
- **Sealed to that machine.** Each envelope is encrypted to the paired machine's sealing key (an
  ephemeral X25519 exchange, HKDF, AES-GCM) and signed with this machine's signing key, as
  `passbook link` seals a grant. Whoever carries it, a collector or a tailnet, learns nothing.
- **Opened only inside the broker.** Both device keys and the list of paired machines are store keys
  sealed under the vault's data key, which only the signed-in broker holds, and they never sync
  (`is_local_only`). So no process can open an envelope by reading a file.
- **With its guard.** The receiving broker writes the guard first, then the value, sealed at rest, so a
  guarded key is guarded on every machine it reaches. A guard cleared on one machine travels as a
  dated note and is cleared on the other.
- **By the rules plain sync already keeps.** The newer value wins, by the sender's own stamp; an
  identical value is never rewritten and no stamp moves; a key removed here is not brought back; a
  stamp from the future is refused; an envelope is bound to its issuer, its audience and its issue
  time, so an old one cannot be replayed.

This file is the format and the rules, with no I/O: the broker (`passbook_broker`) holds the keys and
does the reading and writing.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Iterable, Mapping

import passbook_link as link

# Store keys, sealed under the vault's data key, never synced (passbook_sync.is_local_only).
KEY_PREFIX = "PASSBOOK_GUARD_SYNC_"
DEVICE_KEY = KEY_PREFIX + "DEVICE"
PEERS_KEY = KEY_PREFIX + "PEERS"
# Beside the store: the envelopes waiting for each paired machine, ciphertext only. A collector serves it
# as `guardedFor` next to (never inside) the plaintext values a peer receives.
OUTBOX_FILENAME = "passbook-guardsync-outbox.json"
CODE_PREFIX = "passbook-guardsync:v1:"
ENVELOPE_PREFIX = "passbook-guarded:v1:"
SPEC = 1
# How a received envelope is taken (plan_apply). Raise it when that changes: content_digest folds it in.
# 2: an undated guard is taken where nothing was decided (2026-11-28).
RULES = 2
# How far ahead of this machine's clock a stamp may be before it is refused as from the future.
SKEW_SECONDS = 300


class GuardSyncError(RuntimeError):
    """Something an owner should read: what is wrong and what to do."""


class AlreadyTaken(GuardSyncError):
    """The envelope last taken from that machine, offered again: nothing changed there, so nothing to do."""


# ── this machine's guard-sync device ───────────────────────────────────────


def new_device() -> str:
    """A fresh device: a signing key and a sealing key, as the JSON kept in DEVICE_KEY."""
    crypto = link._require_crypto()
    sign = crypto.ed25519.Ed25519PrivateKey.generate()
    seal = crypto.x25519.X25519PrivateKey.generate()
    raw = crypto.serialization.Encoding.Raw
    private = crypto.serialization.PrivateFormat.Raw
    none = crypto.serialization.NoEncryption()
    return json.dumps({
        "v": SPEC,
        "sign": link._b64(sign.private_bytes(encoding=raw, format=private, encryption_algorithm=none)),
        "seal": link._b64(seal.private_bytes(encoding=raw, format=private, encryption_algorithm=none)),
        "created": int(time.time()),
    }, separators=(",", ":"))


def load_device(text: str) -> dict[str, Any]:
    crypto = link._require_crypto()
    try:
        saved = json.loads(text)
        sign = crypto.ed25519.Ed25519PrivateKey.from_private_bytes(link._unb64(saved["sign"]))
        seal = crypto.x25519.X25519PrivateKey.from_private_bytes(link._unb64(saved["seal"]))
    except Exception:
        raise GuardSyncError("This machine's guard-sync keys are damaged.") from None
    raw = crypto.serialization.Encoding.Raw
    public = crypto.serialization.PublicFormat.Raw
    sign_public = sign.public_key().public_bytes(encoding=raw, format=public)
    seal_public = seal.public_key().public_bytes(encoding=raw, format=public)
    return {
        "did": link.did_from_public(sign_public),
        "fingerprint": link.fingerprint_of(sign_public, seal_public),
        "sign_public": sign_public, "seal_public": seal_public,
        "_sign": sign, "_seal": seal,
    }


def pairing_code(device: Mapping[str, Any], name: str = "") -> str:
    """The public half, for the other machine to pair with this one. Safe to show and to copy."""
    body = {"v": SPEC, "did": device["did"], "seal": link._b64(device["seal_public"]),
            "name": str(name)[:60]}
    return CODE_PREFIX + link._b64(json.dumps(body, separators=(",", ":")).encode("utf-8"))


def read_pairing_code(code: str) -> dict[str, Any]:
    text = "".join(str(code).split())
    if not text.startswith(CODE_PREFIX):
        raise GuardSyncError("That is not a guard-sync pairing code. Run `passbook pair code` on the other machine.")
    try:
        body = json.loads(link._unb64(text[len(CODE_PREFIX):]).decode("utf-8"))
        sign_public = link.public_from_did(body["did"])
        seal_public = link._unb64(body["seal"])
    except Exception:
        raise GuardSyncError("That pairing code is damaged; copy it again.") from None
    if len(seal_public) != 32:
        raise GuardSyncError("That pairing code is damaged; copy it again.")
    return {"did": body["did"], "sign_public": sign_public, "seal_public": seal_public,
            "fingerprint": link.fingerprint_of(sign_public, seal_public), "name": str(body.get("name") or "")[:60]}


def same_fingerprint(typed: str, expected: str) -> bool:
    clean = lambda text: "".join(str(text).split()).upper().replace("-", "")  # noqa: E731
    return bool(typed) and secrets.compare_digest(clean(typed), clean(expected))


# ── paired machines ────────────────────────────────────────────────────────


def read_peers(text: str | None) -> list[dict[str, Any]]:
    """The paired machines as PEERS_KEY keeps them; anything malformed is dropped."""
    try:
        rows = json.loads(text or "[]")
    except (TypeError, ValueError):
        return []
    out = []
    for row in rows if isinstance(rows, list) else []:
        try:
            sign_public = link.public_from_did(row["did"])
            seal_public = link._unb64(row["seal"])
        except Exception:
            continue
        if len(seal_public) != 32 or link.fingerprint_of(sign_public, seal_public) != row.get("fingerprint"):
            continue
        out.append({"did": row["did"], "seal": row["seal"], "fingerprint": row["fingerprint"],
                    "name": str(row.get("name") or "")[:60], "pairedAt": float(row.get("pairedAt") or 0),
                    "lastIssued": float(row.get("lastIssued") or 0),
                    # The RULES the last envelope was taken under; 0 for one taken before this was kept (RULES 1).
                    "lastRules": int(row.get("lastRules") or 0)})
    return out


def write_peers(peers: Iterable[Mapping[str, Any]]) -> str:
    rows = [{**{key: peer[key] for key in ("did", "seal", "fingerprint", "name", "pairedAt", "lastIssued")},
             "lastRules": int(peer.get("lastRules") or 0)} for peer in peers]
    return json.dumps(sorted(rows, key=lambda row: row["fingerprint"]), separators=(",", ":"))


def with_peer(peers: list[dict[str, Any]], code: Mapping[str, Any], now: float) -> list[dict[str, Any]]:
    kept = [peer for peer in peers if peer["fingerprint"] != code["fingerprint"]]
    return kept + [{"did": code["did"], "seal": link._b64(code["seal_public"]), "fingerprint": code["fingerprint"],
                    "name": code.get("name", ""), "pairedAt": now, "lastIssued": 0.0, "lastRules": RULES}]


# ── envelopes ──────────────────────────────────────────────────────────────


def seal_bundle(device: Mapping[str, Any], peer: Mapping[str, Any], items: Mapping[str, Mapping[str, Any]],
                cleared: Mapping[str, float], *, issued: float) -> str:
    """Everything guarded this machine sends to one paired machine, sealed to it and signed.

    `items`: KEY -> {value, updatedAt, guard (commands/destinations), guardAt}. `cleared`: KEY -> when its
    guard was cleared here. The values are inside the ciphertext; the signed header names only the two
    machines and the issue time, so a carrier learns which machines talk and nothing else.
    """
    crypto = link._require_crypto()
    header = {"kind": "passbook-guarded", "v": SPEC, "iss": device["did"], "aud": peer["did"],
              "iat": round(float(issued), 3), "nonce": link._b64(secrets.token_bytes(16))}
    body = {"items": {str(key): dict(item) for key, item in items.items()},
            "cleared": {str(key): float(at) for key, at in cleared.items()}}
    ephemeral = crypto.x25519.X25519PrivateKey.generate()
    shared = ephemeral.exchange(crypto.x25519.X25519PublicKey.from_public_bytes(link._unb64(peer["seal"])))
    nonce = secrets.token_bytes(12)
    ciphertext = crypto.AESGCM(link._derive(shared, crypto)).encrypt(
        nonce, json.dumps(body, separators=(",", ":")).encode("utf-8"), link._canonical(header).encode("utf-8"))
    envelope = {"header": header, "eph": link._b64(ephemeral.public_key().public_bytes(
        encoding=crypto.serialization.Encoding.Raw, format=crypto.serialization.PublicFormat.Raw)),
        "nonce": link._b64(nonce), "ct": link._b64(ciphertext)}
    envelope["sig"] = link._b64(device["_sign"].sign(link._canonical(envelope).encode("utf-8")))
    return ENVELOPE_PREFIX + link._b64(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))


def open_bundle(text: str, device: Mapping[str, Any], peers: list[Mapping[str, Any]], *,
                now: float | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """(the paired machine it came from, what it carries), or GuardSyncError.

    Refused: anything not signed by a machine paired here, anything addressed to another machine, an
    issue time no newer than the last one taken from that machine (a replay), or one from the future.
    """
    crypto = link._require_crypto()
    moment = time.time() if now is None else now
    if not str(text).startswith(ENVELOPE_PREFIX):
        raise GuardSyncError("not a guarded envelope")
    try:
        envelope = json.loads(link._unb64(str(text)[len(ENVELOPE_PREFIX):]).decode("utf-8"))
        header = envelope["header"]
        signature = link._unb64(envelope.pop("sig"))
    except Exception:
        raise GuardSyncError("damaged envelope") from None
    peer = next((row for row in peers if row["did"] == header.get("iss")), None)
    if peer is None:
        raise GuardSyncError("from a machine not paired here")
    try:
        crypto.ed25519.Ed25519PublicKey.from_public_bytes(link.public_from_did(peer["did"])).verify(
            signature, link._canonical(envelope).encode("utf-8"))
    except Exception:
        raise GuardSyncError("signature does not verify") from None
    if header.get("aud") != device["did"]:
        raise GuardSyncError("addressed to another machine")
    issued = float(header.get("iat") or 0)
    if issued > moment + SKEW_SECONDS:
        raise GuardSyncError("issued in the future")
    # The same envelope again is "already taken", unless it was taken under older RULES: then it is read once more
    # under these. A release that changes plan_apply may reach the receiving machine after the sender re-issued, and
    # that envelope would otherwise never be read under the rule that was released for it.
    if issued == float(peer.get("lastIssued") or 0) and int(peer.get("lastRules") or 0) >= RULES:
        raise AlreadyTaken("already taken")
    if issued < float(peer.get("lastIssued") or 0):
        raise GuardSyncError("older than the last one taken from that machine")
    try:
        shared = device["_seal"].exchange(crypto.x25519.X25519PublicKey.from_public_bytes(link._unb64(envelope["eph"])))
        plain = crypto.AESGCM(link._derive(shared, crypto)).decrypt(
            link._unb64(envelope["nonce"]), link._unb64(envelope["ct"]), link._canonical(header).encode("utf-8"))
        body = json.loads(plain.decode("utf-8"))
    except Exception:
        raise GuardSyncError("cannot be opened here") from None
    return {**peer, "issued": issued}, body


# ── what to do with what arrived ───────────────────────────────────────────


def _rule(guard: Any) -> dict[str, list[str]]:
    guard = guard if isinstance(guard, Mapping) else {}
    rule = {}
    for field in ("commands", "destinations"):
        items = sorted({str(item).strip() for item in (guard.get(field) or []) if str(item).strip()})
        if items:
            rule[field] = items
    return rule


def plan_apply(body: Mapping[str, Any], *, local: Mapping[str, str], stamps: Mapping[str, float],
               guards: Mapping[str, Any], guard_changes: Mapping[str, float],
               now: float | None = None) -> dict[str, Any]:
    """What a received envelope changes here, decided by the same rules plain sync keeps.

    `local` is this machine's opened values; `stamps` its per-key updatedAt (a stamp with no value is a key
    removed here); `guards`/`guard_changes` its guard rules and when each changed. Returns `values`
    (KEY -> (value, sender's stamp)), `guard` (KEY -> (rule, sender's time)), `clear` (KEY -> time) and
    `kept` (KEY -> why it was not taken). Nothing here reads or writes anything.
    """
    moment = time.time() if now is None else now
    soon = moment + SKEW_SECONDS
    values: dict[str, tuple[str, float]] = {}
    guard: dict[str, tuple[dict[str, list[str]], float]] = {}
    clear: dict[str, float] = {}
    kept: dict[str, str] = {}
    items = body.get("items") if isinstance(body.get("items"), Mapping) else {}
    for key, item in items.items():
        key = str(key)
        if not isinstance(item, Mapping) or not link_key(key):
            kept[key] = "not a key name"
            continue
        value = item.get("value")
        stamp = float(item.get("updatedAt") or 0)
        guard_at = float(item.get("guardAt") or 0)
        rule = _rule(item.get("guard"))
        if not rule:
            kept[key] = "sent without a guard"
            continue
        # The guard first: a key is never written here unguarded, so whatever decides the value, the guard
        # is decided on its own dates. A newer local change wins, and the same rule again changes nothing.
        if guard_at > soon:
            kept[key] = "guard stamped in the future"
            continue
        local_rule = _rule(guards.get(key))
        # A guard set before guards were dated arrives at 0. Where this machine never decided anything about the
        # key (no guard, no dated change) it is taken anyway, toward guarded: 2026-11-28 every guard on the NYC Mac
        # predated the dates, so the M2 kept all 19 as "unguarded here since" and served them in plaintext.
        undecided_here = not local_rule and key not in guard_changes
        if local_rule != rule and (guard_at > float(guard_changes.get(key, 0)) or undecided_here):
            guard[key] = (rule, guard_at)
        will_be_guarded = bool(local_rule) or key in guard
        if not isinstance(value, str) or not value or value.startswith(("hive-sealed:", ENVELOPE_PREFIX)):
            kept[key] = "no usable value"
            continue
        if stamp > soon:
            kept[key] = "value stamped in the future"
            continue
        if not will_be_guarded:
            # Its guard was cleared here after the sender guarded it: here it is a plain key now, and plain
            # sync carries it. Never written from a guarded envelope as an unguarded value.
            kept[key] = "unguarded here since"
            continue
        if key not in local and key in stamps:
            kept[key] = "removed here"
            continue
        if local.get(key) == value:
            continue  # identical: nothing written, no stamp moved
        if key in local and stamp <= float(stamps.get(key, 0)):
            kept[key] = "this machine's copy is as new or newer"
            continue
        values[key] = (value, stamp)
    cleared = body.get("cleared") if isinstance(body.get("cleared"), Mapping) else {}
    for key, at in cleared.items():
        key, at = str(key), float(at or 0)
        if key in guards and at <= soon and at > float(guard_changes.get(key, 0)):
            clear[key] = at
    return {"values": values, "guard": guard, "clear": clear, "kept": kept}


def content_digest(device_secret: str, peer_fingerprint: str, items: Mapping[str, Any], cleared: Mapping[str, float]) -> str:
    """Whether what would be sealed for a machine changed since the last envelope: keyed by this machine's own secret,
    so the digest says nothing about the values to whoever reads the outbox. Unchanged, the last envelope stands,
    and the receiving machine has nothing to do."""
    import hashlib
    import hmac

    # RULES is in it so a release that changes how envelopes are taken issues each one afresh: an unchanged envelope
    # is "already taken" at the other end, and would never be read again under the new rules.
    text = link._canonical({"to": peer_fingerprint, "items": dict(items), "cleared": dict(cleared), "rules": RULES})
    return hmac.new(hashlib.sha256(device_secret.encode("utf-8")).digest(), text.encode("utf-8"), "sha256").hexdigest()


def link_key(name: str) -> bool:
    return bool(name) and name.replace("_", "").isalnum() and name[0].isalpha() and not name.startswith(KEY_PREFIX)


def bundle_items(*, guards: Mapping[str, Any], guard_changes: Mapping[str, float], values: Mapping[str, str],
                 stamps: Mapping[str, float], travels: Mapping[str, bool]) -> tuple[dict[str, dict[str, Any]], dict[str, float]]:
    """What this machine sends a paired machine: each guarded key whose reach lets it leave (`travels`),
    with its value, stamp, guard and guard time; and each guard cleared here, dated."""
    items: dict[str, dict[str, Any]] = {}
    for key, guard in guards.items():
        rule = _rule(guard)
        value = values.get(key)
        if not rule or not travels.get(key) or not isinstance(value, str) or not value or not link_key(key):
            continue
        items[key] = {"value": value, "updatedAt": float(stamps.get(key, 0)), "guard": rule,
                      "guardAt": float(guard_changes.get(key, 0))}
    cleared = {key: float(at) for key, at in guard_changes.items()
               if key not in guards and travels.get(key, True) and link_key(key)}
    return items, cleared


# ── words two screens can compare ──────────────────────────────────────────
#
# Pairing in the window shows the same four words on both machines, made from both machines' fingerprints. A person
# who sees the same words on both screens has checked what typing a fingerprint back checks (a swapped code cannot
# show the same words on the other screen), without typing anything.

WORDS = tuple("""acid acorn actor adapt agent alarm album alert alley amber anchor angle ankle apple apron arena arrow aspen atlas attic autumn award bacon badge bagel baker bamboo banjo barley basil basin beach beacon beard beetle bell bench berry bison blade blanket blaze bloom blossom board bonfire bottle boulder bounce bracket branch bread breeze brick bridge brook broom bubble bucket buffalo bundle butter button cabin cactus camel candle canoe canyon carbon carpet carrot castle cedar cellar chalk cherry chimney cider cinnamon circle citrus clover cobalt cocoa coffee comet compass copper coral cotton cougar crane crayon cricket crystal cupcake curtain dagger daisy dancer delta denim desert diamond dinner dolphin donkey dragon drum eagle easel echo eclipse elbow ember engine falcon fennel ferry fiddle finch flame flannel flute forest fossil fountain fox galaxy garden garlic gecko ginger glacier globe goblet granite grape gravel guitar hammer harbor harvest hazel helmet heron hickory honey hornet island ivory jacket jaguar jasmine jelly jigsaw juniper kayak kettle kitten koala ladder lagoon lantern laurel lemon lettuce lilac linen lizard lobster locket lotus magnet mango maple marble meadow melon meteor mint mirror mitten moose mosaic muffin mustard napkin nectar needle noodle nutmeg oasis ocean olive onion orange orchid otter oyster paddle palace panda paprika parrot peach pebble pelican pepper piano pickle pigeon pillow pine planet plum pocket pony poppy prism pumpkin puzzle quail quartz rabbit radish raven ribbon river robin rocket saddle salmon sapphire satchel scarf shell shovel silver sparrow spider spruce squash stone sugar summit sunset swan tablet tangerine teapot thistle thunder tiger timber""".split())


def pair_words(fingerprint_a: str, fingerprint_b: str, count: int = 4) -> list[str]:
    """The same `count` words on both machines: from both fingerprints, in an order neither machine chooses."""
    import hashlib

    clean = sorted("".join(str(fp).split()).upper().replace("-", "") for fp in (fingerprint_a, fingerprint_b))
    digest = hashlib.sha256(("passbook-pair-words:v1:" + "|".join(clean)).encode("utf-8")).digest()
    return [WORDS[digest[index]] for index in range(count)]


# ── this machine's public card ─────────────────────────────────────────────
#
# What other machines may know about this one's guard sync, served by its collector as `guardSync`: its fingerprint, a
# name, its pairing code (public keys only), which machines it is paired with, and which machine it has asked to pair
# with it. Nothing here opens or seals anything.

PUBLIC_FILENAME = "passbook-guardsync-public.json"
ASK_SECONDS = 30 * 60


def public_card(device: Mapping[str, Any], name: str, peers: list[Mapping[str, Any]],
                asks: Mapping[str, float], *, now: float) -> dict[str, Any]:
    return {"v": SPEC, "fingerprint": device["fingerprint"], "name": str(name)[:60],
            "code": pairing_code(device, name), "paired": sorted(peer["fingerprint"] for peer in peers),
            "asks": {fp: at for fp, at in asks.items() if now - float(at) < ASK_SECONDS}}


def read_card(value: Any, *, now: float | None = None) -> dict[str, Any] | None:
    """Another machine's card as its collector served it, checked: a code that names the same fingerprint, or nothing."""
    moment = time.time() if now is None else now
    if not isinstance(value, Mapping):
        return None
    try:
        code = read_pairing_code(str(value.get("code") or ""))
    except GuardSyncError:
        return None
    if code["fingerprint"] != value.get("fingerprint"):
        return None
    asks = value.get("asks") if isinstance(value.get("asks"), Mapping) else {}
    return {"fingerprint": code["fingerprint"], "name": str(value.get("name") or code["name"] or "")[:60],
            "code": str(value["code"]), "paired": [str(fp) for fp in (value.get("paired") or []) if isinstance(fp, str)][:64],
            "asks": {str(fp): float(at) for fp, at in asks.items()
                     if isinstance(at, (int, float)) and moment - float(at) < ASK_SECONDS}}
