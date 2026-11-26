# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Sharing keys with other people.

PassBook's model is one owner lending named keys to machines: a grant is signed by the owning
machine, sealed to the receiving one, narrow, and it expires. A *member* is that same thing with a
person on the other end instead of the owner's own second computer. Nothing about what is trusted
changes, and that is deliberate: a member is invited with the same one-line invite, joins with
`passbook join`, is kept current by the same refresh, and loses the keys the same way when removed.
What this module adds is the part that is about people:

  * **A name and a role**, carried in the signed half of the grant so they cannot be stripped or
    changed on the way. `read`: the member holds the key like one of their own. `use`: the key
    arrives guarded on their machine, so their apps and agents can use it through the broker and it
    is never printed or revealed there.
  * **Seats.** The relay counts members apart from the owner's computers.
  * **One record of who used what.** Each member's PassBook reports uses of the keys it was lent
    (`report`, run on the member's existing ten-minute schedule), sealed to the owner's key before
    it leaves. The owner reads them with `activity`. The relay stores who reported and when, and
    cannot read which key, which app or why.
  * **Offboarding.** Removing a member unlinks them and returns the keys to rotate.

**What a role is not.** A member's machine is the member's. `use` keeps a key off their screen and
out of an agent's transcript; it does not stop a person who sets out to take it, because the value
is on their machine in order to be used. This is the same thing the README says about every key on
your own machine, and it is why removing a member ends with a list of keys to rotate at the
provider rather than a claim that they are gone.

**What the record is not.** It is what members' machines volunteer. A member who has changed their
PassBook can leave things out. It tells an owner what honest machines did, which is what an audit
of people you chose to share with is for. It is not a control.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any, Mapping

import passbook
import passbook_join as join
import passbook_link as link

ROLES = ("use", "read")
EVENT_PREFIX = "pbts1"
ACTIVITY_FILENAME = "passbook-team-activity.json"
KEPT_EVENTS = 2000
BATCH = 50
# Rows of a member's own record worth telling the owner about: the key was handed over, used,
# shown, refused, or left the machine.
REPORTED_OPS = ("read", "use", "reveal", "denied", "export", "standing")
_INFO = b"passbook-team-event:v1"


class TeamError(join.JoinError):
    """Something about sharing with a person could not be done. Safe to show."""


# ── the owner ───────────────────────────────────────────────────────────────


def invite(name: str, selection: Mapping[str, Any], *, role: str = "use", caveats: Mapping[str, Any] | None = None,
           days: int = join.DEFAULT_DAYS, live: bool = True, workspace: str = "", relay: str = "",
           root: Path | None = None, opener: join.Opener | None = None) -> dict[str, Any]:
    """Make an invite for another person. They run the line it returns on their own machine."""
    who = " ".join(str(name).split())[:60]
    if not who:
        raise TeamError("Give the person a name, so you can tell who has what later.")
    if role not in ROLES:
        raise TeamError("A role is `use` (their apps can use the key, PassBook never shows it to them) or `read`.")
    made = join.create_invite(selection, caveats={**dict(caveats or {}), "role": [role], "member": [who]}, days=days,
                              live=live, workspace=workspace, label=join.machine_label(), relay=relay, root=root,
                              opener=opener, kind="member")
    return {**made, "name": who, "role": role}


def _one(values: Any, fallback: str = "") -> str:
    return str(values[0]) if isinstance(values, list) and values else fallback


def members(*, root: Path | None = None) -> list[dict[str, Any]]:
    """Everyone this PassBook shares with now. Names of keys, never values."""
    rows = []
    for item in link._read_grants(root)["issued"]:
        if item.get("kind") != "member" or item.get("revoked"):
            continue
        caveats = item.get("caveats") or {}
        keys: set[str] = set()
        for capability in item.get("att", []):
            keys.update(capability.get("nb", {}).get("keys", []))
        rows.append({"did": item["aud"], "name": _one(caveats.get("member"), item.get("label", "") or "Somebody"),
                     "role": _one(caveats.get("role"), "read"), "keys": sorted(keys), "expires": item.get("exp", ""),
                     "sentAt": item.get("sentAt", ""), "machine": item.get("label", "")})
    return sorted(rows, key=lambda row: row["name"].lower())


def remove(did: str, *, root: Path | None = None, opener: join.Opener | None = None) -> dict[str, Any]:
    """Stop sharing with one person. Returns the keys to rotate: unlinking cannot unsend them."""
    if not any(row["did"] == did for row in members(root=root)):
        raise TeamError("This PassBook does not share with that person.")
    return join.unlink(did, root=root, opener=opener)


def _names(root: Path | None) -> dict[str, str]:
    """did -> the name the owner gave, for everyone ever shared with (a removed member's rows stay readable)."""
    out: dict[str, str] = {}
    for item in link._read_grants(root)["issued"]:
        if item.get("kind") == "member":
            out[item["aud"]] = _one((item.get("caveats") or {}).get("member"), item.get("label", "") or "Somebody")
    return out


def _activity_path(root: Path | None) -> Path:
    return (Path(root) if root else passbook.root()) / ACTIVITY_FILENAME


def _read_activity(root: Path | None) -> dict[str, Any]:
    try:
        loaded = json.loads(_activity_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        loaded = {}
    loaded = loaded if isinstance(loaded, dict) else {}
    return {"cursors": dict(loaded.get("cursors") or {}), "events": [e for e in loaded.get("events") or [] if isinstance(e, dict)]}


def _write_activity(state: Mapping[str, Any], root: Path | None) -> None:
    path = _activity_path(root)
    handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        json.dump(state, stream, separators=(",", ":"))


def activity(*, root: Path | None = None, opener: join.Opener | None = None, limit: int = 200) -> list[dict[str, Any]]:
    """What members reported, newest first. Collects anything new from the relay first.

    A report that does not open with this machine's key, or does not parse, is dropped: the relay
    is not trusted to have stored what a member sent, and a row is only shown if it opened.
    """
    state = _read_activity(root)
    names = _names(root)
    me = link.identity(root=root)
    relays = sorted({item["relay"] for item in link._read_grants(root)["issued"]
                     if item.get("kind") == "member" and item.get("relay")})
    for relay in relays:
        after, after_id = (state["cursors"].get(relay) or ["", ""])[:2]
        for _ in range(40):  # 8,000 events at most in one go; the relay keeps 5,000
            query = f"/api/passbook/team/events?after={after}&afterId={after_id}" if after else "/api/passbook/team/events"
            try:
                status, answer = join._call(relay, "GET", query, None, me, opener=opener)
            except join.JoinError:
                break
            if status != 200 or not answer.get("ok"):
                break
            page = [row for row in answer.get("events") or [] if isinstance(row, Mapping)]
            for row in page:
                opened = _open_event(str(row.get("sealed") or ""), me)
                after, after_id = str(row.get("at") or after), str(row.get("id") or after_id)
                if opened is None:
                    continue
                member = str(row.get("member") or "")
                state["events"].append({"at": str(opened.get("at") or row.get("at") or ""), "member": names.get(member, "Somebody removed"),
                                        "did": member, "op": str(opened.get("op") or ""), "granted": bool(opened.get("granted")),
                                        "app": str(opened.get("app") or "")[:80], "keys": [str(k) for k in opened.get("keys") or []][:50],
                                        "reason": str(opened.get("reason") or "")[:200]})
            state["cursors"][relay] = [after, after_id]
            if not answer.get("more") or not page:
                break
    state["events"] = sorted(state["events"], key=lambda event: event["at"])[-KEPT_EVENTS:]
    _write_activity(state, root)
    return list(reversed(state["events"]))[:max(1, limit)]


# ── sealing a report to the owner ───────────────────────────────────────────


def _seal_event(event: Mapping[str, Any], owner_seal: str) -> str:
    crypto = link._require_crypto()
    ephemeral = crypto.x25519.X25519PrivateKey.generate()
    shared = ephemeral.exchange(crypto.x25519.X25519PublicKey.from_public_bytes(join._unb64(owner_seal)))
    key = crypto.HKDF(algorithm=crypto.hashes.SHA256(), length=32, salt=None, info=_INFO).derive(shared)
    nonce = secrets.token_bytes(12)
    eph = ephemeral.public_key().public_bytes(encoding=crypto.serialization.Encoding.Raw,
                                               format=crypto.serialization.PublicFormat.Raw)
    box = crypto.AESGCM(key).encrypt(nonce, json.dumps(event, separators=(",", ":")).encode("utf-8"), eph)
    return ".".join([EVENT_PREFIX, join._b64(eph), join._b64(nonce), join._b64(box)])


def _open_event(sealed: str, me: Mapping[str, Any]) -> dict[str, Any] | None:
    crypto = link._require_crypto()
    parts = sealed.split(".")
    if len(parts) != 4 or parts[0] != EVENT_PREFIX:
        return None
    try:
        eph, nonce, box = (join._unb64(part) for part in parts[1:])
        shared = me["_seal_private"].exchange(crypto.x25519.X25519PublicKey.from_public_bytes(eph))
        key = crypto.HKDF(algorithm=crypto.hashes.SHA256(), length=32, salt=None, info=_INFO).derive(shared)
        opened = json.loads(crypto.AESGCM(key).decrypt(nonce, box, eph))
    except Exception:  # noqa: BLE001 - anything that does not open is not a report
        return None
    return opened if isinstance(opened, dict) else None


# ── the member ──────────────────────────────────────────────────────────────


def shared_with_me(*, root: Path | None = None) -> list[dict[str, Any]]:
    """Owners that share with this PassBook now, and under which role."""
    rows = []
    for item in link._read_grants(root)["accepted"]:
        caveats = item.get("caveats") or {}
        if not caveats.get("role") or item.get("unlinkedAt") or item.get("expiredAt"):
            continue
        rows.append({"iss": item["iss"], "fingerprint": item.get("fingerprint", ""), "role": _one(caveats.get("role"), "read"),
                     "keys": sorted(item.get("delivered") or {}), "relay": item.get("relay", ""), "issSeal": item.get("issSeal", ""),
                     "reported": item.get("reported", ""), "reportedHashes": list(item.get("reportedHashes") or [])})
    return rows


def report(*, root: Path | None = None, opener: join.Opener | None = None, limit: int = 2000) -> dict[str, Any]:
    """Run on a MEMBER's machine, on its schedule: tell each owner how their keys were used here.

    Reads this machine's own record, keeps the rows that touch a key an owner lent, and sends each
    owner only what concerns their keys, sealed to them. Says nothing about any other key.
    """
    owners = [owner for owner in shared_with_me(root=root) if owner["relay"] and owner["issSeal"] and owner["keys"]]
    if not owners:
        return {"ok": True, "sent": 0, "owners": 0}
    import passbook_stamp
    rows = [row for row in passbook_stamp.read_stamps(limit=limit, root=root)
            if not row.get("unreadable") and row.get("op") in REPORTED_OPS and row.get("at")]
    me = link.identity(root=root)
    sent = 0
    for owner in owners:
        theirs = set(owner["keys"])
        # Where the last report ended is a time AND the rows already sent at that time: the record's
        # clock is coarse enough for two rows to share an instant, and a time alone would skip one.
        already = set(owner["reportedHashes"])
        fresh = [row for row in rows if theirs.intersection(row.get("keys") or [])
                 and (str(row["at"]) > owner["reported"]
                      or (str(row["at"]) == owner["reported"] and row.get("proofHash") not in already))]
        if not fresh:
            continue
        delivered_to, delivered = owner["reported"], [dict(at=owner["reported"], proofHash=h) for h in already]
        for start in range(0, len(fresh), BATCH):
            chunk = fresh[start:start + BATCH]
            events = [_seal_event({"at": row["at"], "op": row["op"], "granted": bool(row.get("granted")), "app": str(row.get("app") or ""),
                                   "keys": sorted(theirs.intersection(row.get("keys") or [])), "reason": str(row.get("reason") or "")[:200]},
                                  owner["issSeal"]) for row in chunk]
            try:
                status, answer = join._call(owner["relay"], "POST", "/api/passbook/team/events",
                                            {"owner": owner["iss"], "events": events}, me, opener=opener)
            except join.JoinError:
                break
            if status != 200 or not answer.get("ok"):
                break
            sent += len(chunk)
            delivered_to = str(chunk[-1]["at"])
            delivered.extend(chunk)
        if len(delivered) > len(already):
            state = link._read_grants(root)
            for item in state["accepted"]:
                if item.get("iss") == owner["iss"]:
                    item["reported"] = delivered_to
                    item["reportedHashes"] = sorted({str(row.get("proofHash") or "") for row in delivered
                                                     if str(row.get("at")) == delivered_to} - {""})
            link._write_grants(state, root)
    return {"ok": True, "sent": sent, "owners": len(owners)}
