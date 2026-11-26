# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Adding a computer to PassBook with one command, and keeping it current.

`passbook_link` is the protocol: a device identity, a pairing token, an envelope sealed to the
receiving machine and signed by the lending one. What it never had was a way to use it that a person
would choose. Both machines needed a terminal, two strings went back and forth by hand, the
fingerprint was typed twice, and the keys that arrived were a snapshot that never changed again.

This adds the missing half, and changes nothing about what is trusted:

  1. On the machine that has the keys, the owner chooses what the new machine gets (keys, groups,
     projects, umbrellas, or everything that may leave) and makes an invite.
  2. On the new machine, `passbook join <invite>`.

**The invite replaces the fingerprint comparison, it does not skip it.** An invite is
`pbj1.<id>.<secret>.<code>`. The relay sees only the id. The joining machine proves it holds the
secret with an HMAC over its pairing token, which the owner checks, so a relay (or anybody who saw
the id) cannot slip a different machine in; that is exactly what the fingerprint comparison was
for. The code is the owner's fingerprint, so the joining machine knows whose envelope to accept
without asking. The invite is a secret for its fifteen minutes: whoever has it can join. That is
the trade, said plainly, and it is the one SSH keys, runner tokens and every "join this network"
command make. It is single use and dies after one join.

**Keys stay current.** A joined machine has a mailbox on the relay. Whenever the lending machine
has its vault open, `refresh` re-seals the machine's keys if they changed (or the grant is within
ten days of its end) and drops a new envelope there. The joining machine `pull`s on a schedule.
A grant made live renews each time, so a machine whose owner is around never expires; one whose
owner stopped refreshing it runs out on the date in its last grant.

**Expiry and unlinking now take keys away on a machine that is still pulling.** When a grant has
expired, or the owner unlinked the machine, `pull` removes the keys it delivered, provided each is
still exactly what was delivered (a key the machine's own user set since is theirs and is kept).
A compromised machine can of course keep whatever it was sent; nothing can unsend a credential,
and unlinking still names the keys to rotate at the provider.

**Only keys whose reach is `tailnet` leave.** That is what the reach words say ("lendable to linked
machines"), and the picker reports the rest as staying here rather than silently dropping them.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

import passbook
import passbook_link as link

INVITE_VERSION = "pbj1"
INVITE_ID = re.compile(r"^[A-Za-z0-9_-]{22}$")
INVITE_SHAPE = re.compile(r"^pbj1\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{22})\.([A-Z2-7]{16})(?:\.([A-Za-z0-9_-]{4,200}))?$")
TIMEOUT = 20
POLL_SECONDS = 2.0
RENEW_WITHIN = timedelta(days=10)
DEFAULT_DAYS = link.DEFAULT_GRANT_DAYS
PULL_EVERY_SECONDS = 600
SCHEDULE_LABEL = "com.passbook.link-pull"
SELECTION_KINDS = ("keys", "groups", "projects", "umbrellas")
SEEN_NONCES = 200


class JoinError(link.LinkError):
    """Something about adding a machine went wrong. The message is safe to show a person.

    `code` is the relay's own word for a refusal that has a way out (`machine_limit`, `seat_limit`,
    `not_included`), so the window can put that way out beside the sentence. "" otherwise.
    """

    def __init__(self, message: str = "", code: str = "") -> None:
        super().__init__(message)
        self.code = code


# ── small pieces ────────────────────────────────────────────────────────────


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def machine_label() -> str:
    """How this machine introduces itself: its host name, never an address."""
    name = (socket.gethostname() or "").strip()
    for suffix in (".local", ".lan", ".home"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
    return re.sub(r"[\x00-\x1f]", "", name)[:60] or "A computer"


def relay_url(explicit: str = "", environ: Mapping[str, str] | None = None) -> str:
    """The relay to use: the HivemindOS one, or another only if this machine allows it."""
    import passbook_web_link as web_link
    env = os.environ if environ is None else environ
    allowed = web_link.relays(env)
    chosen = (explicit or env.get("PASSBOOK_MACHINE_RELAY", "") or allowed[0]).strip().rstrip("/")
    if chosen not in allowed:
        raise JoinError(f"{chosen} is not a relay this machine will use. "
                        "Add it to PASSBOOK_WEB_RELAYS on both machines to allow it.")
    return chosen


def _join_mac(secret: bytes, invite_id: str, pairing_token: str) -> str:
    message = f"passbook-join:v1\n{invite_id}\n{pairing_token}".encode("utf-8")
    return _b64(hmac.new(secret, message, hashlib.sha256).digest())


def _proof(me: Mapping[str, Any], method: str, path: str, body: str) -> str:
    """`X-PassBook-Proof`: this machine's signature over the request, checked by the relay."""
    seconds = str(int(time.time()))
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    message = f"passbook-relay:v1\n{method}\n{path}\n{seconds}\n{digest}".encode("utf-8")
    return f"{me['did']} {seconds} {_b64(me['_sign_private'].sign(message))}"


Opener = Callable[..., Any]


def _call(relay: str, method: str, path: str, body: Mapping[str, Any] | None, me: Mapping[str, Any],
          *, opener: Opener | None = None) -> tuple[int, dict[str, Any]]:
    text = "" if body is None else json.dumps(body, separators=(",", ":"))
    request = urllib.request.Request(relay + path, data=text.encode("utf-8") if body is not None else None,
                                     method=method, headers={
                                         "Content-Type": "application/json", "Accept": "application/json",
                                         "User-Agent": "PassBook", "X-PassBook-Proof": _proof(me, method, path, text),
                                     })
    try:
        with (opener or urllib.request.urlopen)(request, timeout=TIMEOUT) as response:
            # Room for the largest answer a relay gives: a backup of up to a megabyte, in JSON.
            return response.status, json.loads(response.read(2_500_000) or b"{}")
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read(100_000) or b"{}")
        except ValueError:
            return error.code, {}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise JoinError("The PassBook relay could not be reached. Check this machine's connection and try again.") from None


def _digest_values(values: Mapping[str, str]) -> str:
    joined = "\n".join(f"{name}={values[name]}" for name in sorted(values))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _raw_digest(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


# ── what a machine gets ─────────────────────────────────────────────────────


def normalise_selection(selection: Mapping[str, Any] | None) -> dict[str, Any]:
    """A selection as stored: lists of names under each kind, and `all`."""
    raw = dict(selection or {})
    out: dict[str, Any] = {"all": bool(raw.get("all"))}
    for kind in SELECTION_KINDS:
        items = raw.get(kind) or []
        if isinstance(items, str):
            items = [items]
        out[kind] = sorted({str(item).strip() for item in items if str(item).strip()})
    return out


def normalise_caveats(caveats: Mapping[str, Any] | None) -> dict[str, list[str]]:
    raw = dict(caveats or {})
    out: dict[str, list[str]] = {}
    for name in (*link.CAVEATS, *link.TEAM_CAVEATS):
        items = raw.get(name) or []
        if isinstance(items, str):
            # A person's name is one thing, spaces and all; hosts and commands are lists.
            items = [items] if name in link.TEAM_CAVEATS else [part for part in re.split(r"[,\s]+", items)]
        cleaned = sorted({str(item).strip().lower() if name == "hosts" else str(item).strip()
                          for item in items if str(item).strip()})
        if cleaned:
            out[name] = cleaned
    return out


def resolve_selection(selection: Mapping[str, Any], *, policy: Mapping[str, Any] | None = None,
                      names: Iterable[str] | None = None) -> dict[str, Any]:
    """Which keys a selection means right now, and which of them must stay on this machine.

    Returns `{"keys": [...], "staying": [...], "missing": [...]}`. `staying` are keys the selection
    names whose reach is not `tailnet`; `missing` are individually named keys this store lacks.
    """
    import passbook_access as access
    chosen = normalise_selection(selection)
    policy = access.read_policy() if policy is None else policy
    present = sorted(set(passbook.key_names() if names is None else names))
    wanted: set[str] = set()
    missing: list[str] = []
    if chosen["all"]:
        wanted.update(present)
    for name in chosen["keys"]:
        (wanted.add(name) if name in present else missing.append(name))
    if chosen["groups"]:
        try:
            import passbook_catalog as catalog
            arranged = catalog.groups(present, policy)
        except ImportError:
            arranged = {}
        for group in chosen["groups"]:
            wanted.update(arranged.get(group, []))
    for project in chosen["projects"]:
        for name in present:
            rule = access.project_for(name, policy)
            if rule["mode"] == "include" and project in rule["projects"]:
                wanted.add(name)
    for umbrella in chosen["umbrellas"]:
        wanted.update(name for name in access.umbrella_keys(umbrella, policy) if name in present)
    leaving = sorted(name for name in wanted if access.scope_for(name, policy)["scope"] == "tailnet")
    staying = sorted(wanted - set(leaving))
    return {"keys": leaving, "staying": staying, "missing": sorted(missing)}


def choices(*, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Everything the "what does it get" picker can offer, by name. Never a value."""
    import passbook_access as access
    policy = access.read_policy() if policy is None else policy
    present = sorted(passbook.key_names())
    try:
        import passbook_catalog as catalog
        arranged = {group: members for group, members in catalog.groups(present, policy).items()
                    if group != catalog.UNGROUPED}
    except ImportError:
        arranged = {}
    projects: dict[str, list[str]] = {}
    for name in present:
        rule = access.project_for(name, policy)
        if rule["mode"] == "include":
            for project in rule["projects"]:
                projects.setdefault(project, []).append(name)
    umbrellas = {uid: {"label": row["label"], "keys": access.umbrella_keys(uid, policy)}
                 for uid, row in access.read_umbrellas(policy).items()}
    return {
        "keys": [{"name": name, "leaves": access.scope_for(name, policy)["scope"] == "tailnet"} for name in present],
        "groups": [{"name": group, "keys": members} for group, members in sorted(arranged.items())],
        "projects": [{"name": project, "keys": sorted(members)} for project, members in sorted(projects.items())],
        "umbrellas": [{"name": uid, "label": row["label"], "keys": row["keys"]} for uid, row in sorted(umbrellas.items())],
        "caveats": list(link.CAVEATS),
        "defaultDays": DEFAULT_DAYS,
    }


def describe_selection(selection: Mapping[str, Any]) -> str:
    chosen = normalise_selection(selection)
    if chosen["all"]:
        return "everything that may leave this machine"
    parts = []
    for kind, word in (("groups", "group"), ("projects", "project"), ("umbrellas", "umbrella"), ("keys", "key")):
        items = chosen[kind]
        if items:
            parts.append(f"{word}{'s' if len(items) != 1 else ''} {', '.join(items)}")
    return "; ".join(parts) or "nothing"


# ── the lending machine ─────────────────────────────────────────────────────


def _values_for(names: list[str], workspace: str, resolve_values: Callable[[list[str]], Mapping[str, str]] | None
                ) -> dict[str, str]:
    if resolve_values is not None:
        got = dict(resolve_values(names))
    else:
        got = passbook.request(names, app="passbook-link", reason="keep a linked machine current",
                               workspace_id=workspace)
    return {name: value for name, value in got.items()
            if name in names and isinstance(value, str) and value.strip() and not value.startswith("hive-sealed:")}


def create_invite(selection: Mapping[str, Any], *, caveats: Mapping[str, Any] | None = None,
                  days: int = DEFAULT_DAYS, live: bool = True, workspace: str = "", label: str = "",
                  relay: str = "", root: Path | None = None, opener: Opener | None = None,
                  kind: str = "machine") -> dict[str, Any]:
    """Make an invite for a machine to join with `passbook join`.

    `kind` is "machine" for one of the owner's own computers and "member" for another person
    (passbook_team.py). The relay counts the two apart, and refuses a member invite it will not
    carry before any line is shown, so nobody is sent one that cannot work.

    The selection is checked now, so a person learns at once that it means no keys at all, or that
    some of what they picked stays on this machine. It is resolved again when the machine joins, and
    on every refresh after that if `live`, so a key added to a chosen group later reaches it too.
    """
    chosen = normalise_selection(selection)
    resolved = resolve_selection(chosen)
    if resolved["missing"]:
        raise JoinError(f"Not in this machine's store: {', '.join(resolved['missing'])}.")
    if not resolved["keys"]:
        if resolved["staying"]:
            raise JoinError("Everything you chose stays on this machine: its reach is not set to lendable. "
                            f"Widen one with `passbook scope set KEY --tailnet` ({', '.join(resolved['staying'][:5])}).")
        raise JoinError("Choose at least one key, group or project for the new machine.")
    relay = relay_url(relay)
    me = link.identity(root=root)
    kind = "member" if kind == "member" else "machine"
    status, answer = _call(relay, "POST", "/api/passbook/machine-invites",
                           {"label": label or machine_label(), "kind": kind}, me, opener=opener)
    if status != 200 or not answer.get("ok") or not INVITE_ID.fullmatch(str(answer.get("inviteId") or "")):
        raise JoinError(str(answer.get("error") or "The relay did not make an invite. Try again in a moment."),
                        str(answer.get("code") or ""))
    secret = secrets.token_bytes(16)
    code = me["fingerprint"].replace("-", "")
    import passbook_web_link as web_link
    suffix = "" if relay == web_link.relays()[0] else "." + _b64(relay.encode("utf-8"))
    invite = f"{INVITE_VERSION}.{answer['inviteId']}.{_b64(secret)}.{code}{suffix}"
    state = link._read_grants(root)
    pending = [item for item in state.get("invites", []) if item.get("expires", "") > link._stamp(link._now())]
    pending.append({
        "id": answer["inviteId"], "secret": _b64(secret), "relay": relay, "expires": answer.get("expiresAt", ""),
        "selection": chosen, "caveats": normalise_caveats(caveats), "days": max(1, int(days)), "live": bool(live),
        "workspace": workspace or passbook.workspace(), "created": link._stamp(link._now()),
        # A fixed grant is the keys as they are now, not whatever the selection means later.
        "names": [] if live else resolved["keys"],
        "kind": kind,
    })
    state["invites"] = pending
    link._write_grants(state, root)
    return {"ok": True, "invite": invite, "command": f"passbook join {invite}", "id": answer["inviteId"],
            "expires": answer.get("expiresAt", ""), "keys": resolved["keys"], "staying": resolved["staying"],
            "describe": describe_selection(chosen), "kind": kind}


def invites(*, root: Path | None = None) -> list[dict[str, Any]]:
    """Open invites, without their secrets."""
    now = link._stamp(link._now())
    return [{key: item.get(key) for key in ("id", "expires", "selection", "caveats", "days", "live", "created")}
            for item in link._read_grants(root).get("invites", []) if item.get("expires", "") > now]


def cancel_invite(invite_id: str, *, root: Path | None = None) -> bool:
    state = link._read_grants(root)
    before = len(state.get("invites", []))
    state["invites"] = [item for item in state.get("invites", []) if item.get("id") != invite_id]
    link._write_grants(state, root)
    return len(state["invites"]) != before


def _seal_and_record(peer_token: str, peer_fingerprint: str, names: list[str], values: Mapping[str, str], *,
                     entry: Mapping[str, Any], root: Path | None) -> dict[str, Any]:
    days = int(entry.get("days") or DEFAULT_DAYS)
    sealed = link.grant(peer_token, names, confirm_fingerprint=peer_fingerprint,
                        workspace=entry.get("workspace", ""), days=days, root=root,
                        resolve_values=lambda wanted: {name: values[name] for name in wanted},
                        caveats=entry.get("caveats") or {})
    state = link._read_grants(root)
    for item in state["issued"]:
        if item.get("aud") == sealed["did"]:
            item.update({"label": entry.get("label", ""), "relay": entry["relay"], "live": bool(entry.get("live", True)),
                         "selection": entry.get("selection", {}), "caveats": entry.get("caveats", {}),
                         "days": days, "names": entry.get("names", []), "seal": entry["seal"],
                         "kind": entry.get("kind", "machine"),
                         "digest": _digest_values(values), "sentAt": link._stamp(link._now())})
    link._write_grants(state, root)
    return sealed


def complete_invites(*, invite_id: str = "", root: Path | None = None, opener: Opener | None = None,
                     resolve_values: Callable[[list[str]], Mapping[str, str]] | None = None) -> list[dict[str, Any]]:
    """Answer any invite a machine has joined. Safe to call as often as you like.

    Returns one row per open invite: `waiting`, `joined` (with the machine's name and the keys it
    was sent), `expired`, or `failed` with a reason. A join whose proof does not match the invite's
    secret is declined, and the invite is closed, because it means somebody other than the person
    holding the invite tried to use it.
    """
    state = link._read_grants(root)
    now = link._stamp(link._now())
    rows: list[dict[str, Any]] = []
    keep: list[dict[str, Any]] = []
    me = link.identity(root=root)
    for item in state.get("invites", []):
        if invite_id and item.get("id") != invite_id:
            keep.append(item)
            continue
        if item.get("expires", "") <= now:
            rows.append({"id": item["id"], "status": "expired"})
            continue
        path = f"/api/passbook/machine-invites/{item['id']}"
        try:
            status, seen = _call(item["relay"], "GET", path, None, me, opener=opener)
        except JoinError as error:
            rows.append({"id": item["id"], "status": "waiting", "detail": str(error)})
            keep.append(item)
            continue
        if status == 404 or seen.get("status") == "expired":
            rows.append({"id": item["id"], "status": "expired"})
            continue
        if status != 200:
            # A relay that is busy or briefly wrong has not ended the invite. Calling that "expired"
            # threw away an invite somebody was in the middle of using.
            rows.append({"id": item["id"], "status": "waiting",
                         "detail": str(seen.get("error") or "The relay did not answer just now.")})
            keep.append(item)
            continue
        if seen.get("status") != "joined":
            rows.append({"id": item["id"], "status": "waiting"})
            keep.append(item)
            continue
        token, proof = str(seen.get("pairingToken") or ""), str(seen.get("proof") or "")
        expected = _join_mac(_unb64(item["secret"]), item["id"], token)
        if not hmac.compare_digest(expected, proof):
            _call(item["relay"], "POST", path + "/answer", {"declined": True}, me, opener=opener)
            rows.append({"id": item["id"], "status": "failed",
                         "detail": "A machine without this invite's secret tried to join, so it was turned away. Make a new invite."})
            continue
        peer: dict[str, Any] = {}
        try:
            peer = link.read_pairing_token(token)
            names = list(item.get("names") or []) or resolve_selection(item.get("selection", {}))["keys"]
            values = _values_for(names, item.get("workspace", ""), resolve_values)
            if not values:
                raise JoinError("None of the chosen keys could be read here. Open PassBook's vault and try again.")
            names = sorted(values)
            entry = {**item, "label": str(seen.get("label") or "A computer")[:60],
                     "seal": _b64(peer["seal_public"])}
            sealed = _seal_and_record(token, peer["fingerprint"], names, values, entry=entry, root=root)
            status, answer = _call(item["relay"], "POST", path + "/answer", {"envelope": sealed["envelope"]}, me,
                                   opener=opener)
            if status != 200 or not answer.get("ok"):
                raise JoinError(str(answer.get("error") or "The relay did not take the answer."),
                                str(answer.get("code") or ""))
        except link.LinkError as error:
            row = {"id": item["id"], "status": "failed", "detail": str(error)}
            if getattr(error, "code", ""):
                row["code"] = error.code
                # Refused by the relay's limit, after the keys were sealed and recorded as lent.
                # Nothing was delivered, so the record must not say this machine holds them.
                _forget_issued(str(peer.get("did") or ""), root)
            rows.append(row)
            keep.append(item)
            continue
        rows.append({"id": item["id"], "status": "joined", "label": entry["label"], "did": peer["did"],
                     "fingerprint": peer["fingerprint"], "keys": names, "expires": sealed["expires"],
                     "kind": item.get("kind", "machine")})
    # Re-read before writing: an invite made while this ran must survive it.
    kept = {item["id"] for item in keep}
    finished = {row["id"] for row in rows} - kept
    state = link._read_grants(root)
    state["invites"] = [item for item in state.get("invites", []) if item.get("id") not in finished]
    link._write_grants(state, root)
    return rows


def _forget_issued(did: str, root: Path | None) -> None:
    """Drop the record of a grant whose envelope the relay refused to carry. It was never delivered."""
    if not did:
        return
    state = link._read_grants(root)
    kept = [item for item in state["issued"] if not (item.get("aud") == did and not item.get("revoked") and item.get("sentAt"))]
    if len(kept) != len(state["issued"]):
        state["issued"] = kept
        link._write_grants(state, root)


def _peer_token(entry: Mapping[str, Any]) -> str:
    """A pairing token rebuilt from what this machine recorded, so a refresh can reuse `grant`."""
    payload = {"v": link.SPEC_VERSION, "did": entry["aud"], "seal": entry["seal"],
               "exp": link._stamp(link._now() + timedelta(minutes=10))}
    return link.PAIR_PREFIX + _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def refresh(*, root: Path | None = None, opener: Opener | None = None, force: bool = False,
            resolve_values: Callable[[list[str]], Mapping[str, str]] | None = None) -> dict[str, Any]:
    """Send each joined machine its keys again if they changed or its grant is nearly over.

    Never opens a vault. A machine whose keys cannot be read here (the vault is shut) is skipped and
    keeps what it last received until the next refresh that can.
    """
    sent, current, skipped, unlinked = [], [], [], []
    me = link.identity(root=root)
    soon = link._now() + RENEW_WITHIN
    for entry in list(link._read_grants(root)["issued"]):
        if entry.get("revoked") or not entry.get("relay") or not entry.get("seal"):
            continue
        label = entry.get("label") or entry["aud"]
        ends = link._parse_stamp(entry["exp"])
        renew = bool(entry.get("live", True))
        if ends <= link._now() and not renew:
            continue
        names = (resolve_selection(entry.get("selection", {}))["keys"] if entry.get("live", True)
                 else list(entry.get("names") or []))
        values = _values_for(names, entry.get("workspace", ""), resolve_values) if names else {}
        if names and not values:
            skipped.append(label)
            continue
        changed = _digest_values(values) != entry.get("digest")
        if not (force or changed or (renew and ends <= soon)):
            current.append(label)
            continue
        if not renew:
            # A fixed grant keeps its end date: a refresh carries new values, never more time.
            remaining = (ends - link._now()).days
            if remaining < 1:
                continue
            entry = {**entry, "days": remaining}
        token = _peer_token(entry)
        peer = link.read_pairing_token(token)
        try:
            if values:
                sealed = _seal_and_record(token, peer["fingerprint"], sorted(values), values,
                                          entry={**entry, "days": entry.get("days") or DEFAULT_DAYS}, root=root)
                envelope = sealed["envelope"]
            else:
                skipped.append(label)
                continue
            status, answer = _call(entry["relay"], "POST", f"/api/passbook/machines/{entry['aud']}/envelope",
                                   {"envelope": envelope}, me, opener=opener)
        except link.LinkError:
            skipped.append(label)
            continue
        if status == 410 or answer.get("unlinked"):
            state = link._read_grants(root)
            for item in state["issued"]:
                if item.get("aud") == entry["aud"]:
                    item["revoked"], item["unlinkedAt"] = True, link._stamp(link._now())
            link._write_grants(state, root)
            unlinked.append(label)
        elif status == 200:
            sent.append(label)
        else:
            skipped.append(label)
    return {"ok": True, "sent": sent, "current": current, "skipped": skipped, "unlinked": unlinked}


def unlink(did: str, *, root: Path | None = None, opener: Opener | None = None) -> dict[str, Any]:
    """Stop lending to a joined machine, and tell its mailbox so the machine drops the keys."""
    entry = next((item for item in link._read_grants(root)["issued"] if item.get("aud") == did), None)
    result = link.revoke(did, root=root)
    if entry and entry.get("relay"):
        try:
            _call(entry["relay"], "DELETE", f"/api/passbook/machines/{did}", None, link.identity(root=root), opener=opener)
            result["detail"] += (" That machine removes them itself the next time it checks in, "
                                 "unless it was changed there; rotate anything that must not outlive it.")
        except JoinError:
            result["detail"] += " The relay could not be told, so the machine keeps them until its grant ends."
    return result


# ── the joining machine ─────────────────────────────────────────────────────


def parse_invite(invite: str) -> dict[str, Any]:
    text = "".join(str(invite).split())
    text = text.removeprefix("passbookjoin")
    match = INVITE_SHAPE.fullmatch(text)
    if not match:
        raise JoinError("That is not a PassBook invite. Copy the whole `passbook join pbj1.…` line again.")
    invite_id, secret, code, relay = match.groups()
    relay = relay_url(_unb64(relay).decode("utf-8") if relay else "")
    fingerprint = "-".join(code[index:index + 4] for index in range(0, len(code), 4))
    return {"id": invite_id, "secret": _unb64(secret), "fingerprint": fingerprint, "relay": relay}


def _stored_raw(workspace: str = "") -> dict[str, str]:
    try:
        return passbook.parse_env_text(passbook.target_path(workspace).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError):
        return {}


Writer = Callable[[Mapping[str, str], bool], Mapping[str, Any]]
Remover = Callable[[list[str]], Any]


def _default_writer(values: Mapping[str, str], overwrite: bool) -> Mapping[str, Any]:
    return passbook.set_values(values, overwrite=overwrite, exact=True)


def _default_remover(names: list[str]) -> Any:
    return passbook.remove_values(names)


def _apply_caveats(names: Iterable[str], caveats: Mapping[str, Any]) -> None:
    caveats = normalise_caveats(caveats)
    if not caveats:
        return
    import passbook_access as access
    policy = access.read_policy()
    use_only = "use" in (caveats.get("role") or [])
    for name in names:
        if caveats.get("hosts") or caveats.get("commands"):
            access.set_guard(name, policy, commands=caveats.get("commands") or None,
                             destinations=caveats.get("hosts") or None, replace=True)
        elif use_only:
            # Shared "to use": a guard with nothing in it. The key goes to commands this machine's
            # broker starts and is never printed or revealed here. That keeps it off this person's
            # screen and out of their agent's transcript. It does not stop somebody who sets out to
            # take it, and the owner's side says so (passbook_team.py).
            access.set_guard(name, policy)
        if caveats.get("apps"):
            access.set_audience(name, "include", caveats["apps"], policy)
    access.write_policy(policy)


def _land(body: Mapping[str, Any], values: Mapping[str, str], link_row: Mapping[str, Any], *,
          write: Writer, remove: Remover, root: Path | None) -> dict[str, Any]:
    """Write an envelope's keys, drop the ones it no longer carries, and record what was delivered."""
    delivered: dict[str, str] = dict(link_row.get("delivered") or {})
    raw = _stored_raw()
    ours = {name for name, digest in delivered.items() if name in raw and _raw_digest(raw[name]) == digest}
    theirs = {name for name in values if name in raw and name not in delivered}
    changed_here = {name for name in delivered if name in raw and name not in ours}
    writable = {name: value for name, value in values.items() if name not in theirs and name not in changed_here}
    result = dict(write(writable, True)) if writable else {"added": [], "updated": [], "kept": []}
    dropped = sorted(name for name in ours if name not in values)
    if dropped:
        remove(dropped)
    raw = _stored_raw()
    delivered = {name: _raw_digest(raw[name]) for name in writable if name in raw}
    caveats = {}
    for capability in body.get("att", []):
        caveats.update({name: capability.get("nb", {}).get(name) for name in (*link.CAVEATS, *link.TEAM_CAVEATS)
                        if capability.get("nb", {}).get(name)})
    _apply_caveats(writable, caveats)
    state = link._read_grants(root)
    previous = next((item for item in state["accepted"] if item.get("iss") == body["iss"]), {})
    # Every envelope this issuer sent that was taken, so a relay cannot hand an old one back.
    nonces = [*list(previous.get("nonces") or [])[-(SEEN_NONCES - 1):], body["nonce"]]
    state["accepted"] = [item for item in state["accepted"] if item.get("iss") != body["iss"]]
    state["accepted"].append({"nonces": nonces,
        "iss": body["iss"], "nonce": body["nonce"], "nbf": body["nbf"], "exp": body["exp"], "keys": sorted(writable),
        "at": link._stamp(link._now()), "fingerprint": link_row["fingerprint"], "relay": link_row["relay"],
        "label": link_row.get("label", ""), "delivered": delivered, "caveats": caveats,
        "pulledAt": link._stamp(link._now()),
        # The lending machine's sealing key, from the signed envelope. A member seals its reports
        # of key use to it (passbook_team.py).
        "issSeal": link_row.get("issSeal") or previous.get("issSeal", ""),
        "reported": previous.get("reported", ""), "reportedHashes": previous.get("reportedHashes", []),
    })
    link._write_grants(state, root)
    link._record("link", sorted(writable), granted=True, reason=f"joined from {link_row['fingerprint']}",
                 root=root, workspace=passbook.workspace())
    return {"keys": sorted(writable), "added": list(result.get("added", [])), "updated": list(result.get("updated", [])),
            "kept": sorted(theirs | changed_here), "removed": dropped, "expires": body["exp"]}


def join(invite: str, *, label: str = "", root: Path | None = None, opener: Opener | None = None,
         wait_seconds: float = 900, poll_seconds: float = POLL_SECONDS, write: Writer | None = None,
         remove: Remover | None = None, on_wait: Callable[[], None] | None = None,
         sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    """Run on the NEW machine. Joins the invite and stores the keys it is sent."""
    parsed = parse_invite(invite)
    me = link.identity(root=root)
    if me["fingerprint"] == parsed["fingerprint"]:
        raise JoinError("That invite was made on this machine. Run `passbook join` on the machine you are adding.")
    pairing = link.pairing_token(root=root)
    path = f"/api/passbook/machine-invites/{parsed['id']}"
    status, answer = _call(parsed["relay"], "POST", path + "/join", {
        "pairingToken": pairing["token"], "proof": _join_mac(parsed["secret"], parsed["id"], pairing["token"]),
        "label": label or machine_label(),
    }, me, opener=opener)
    if status != 200 or not answer.get("ok"):
        raise JoinError(str(answer.get("error") or "That invite could not be joined. Make a new one."))
    deadline = time.monotonic() + wait_seconds
    while True:
        status, answer = _call(parsed["relay"], "GET", path + "/result", None, me, opener=opener)
        state = answer.get("status")
        if status == 200 and state == "answered" and answer.get("envelope"):
            break
        if state == "declined":
            raise JoinError("The other machine turned this join away. Make a new invite there.")
        if state == "expired" or status == 404 or time.monotonic() >= deadline:
            raise JoinError("The invite ran out before the other machine answered. "
                            "Make a new invite there and keep PassBook open on it while this machine joins.")
        if on_wait:
            on_wait()
        sleep(poll_seconds)
    body, values = link._open_accepted(answer["envelope"], confirm_fingerprint=parsed["fingerprint"], root=root)
    row = {"fingerprint": parsed["fingerprint"], "relay": parsed["relay"], "label": "", "delivered": {},
           "issSeal": _issuer_seal(answer["envelope"])}
    state = link._read_grants(root)
    known = next((item for item in state["accepted"] if item.get("iss") == body["iss"]), None)
    if known:
        row["delivered"] = known.get("delivered") or {}
    landed = _land(body, values, row, write=write or _default_writer, remove=remove or _default_remover, root=root)
    return {"ok": True, "from": parsed["fingerprint"], **landed}


def pull(*, root: Path | None = None, opener: Opener | None = None, write: Writer | None = None,
         remove: Remover | None = None) -> dict[str, Any]:
    """Run on a JOINED machine, on its schedule: collect fresh keys, and drop expired or unlinked ones."""
    write, remove = write or _default_writer, remove or _default_remover
    me = link.identity(root=root)
    rows: list[dict[str, Any]] = []
    for item in list(link._read_grants(root)["accepted"]):
        if not item.get("relay") or item.get("unlinkedAt") or item.get("expiredAt"):
            continue
        label = item.get("fingerprint", "")
        try:
            status, answer = _call(item["relay"], "GET",
                                   f"/api/passbook/machines/{me['did']}/envelope?issuer={item['iss']}", None, me,
                                   opener=opener)
        except JoinError as error:
            rows.append({"from": label, "status": "unreachable", "detail": str(error)})
            status, answer = 0, {}
        if status == 200 and answer.get("unlinked"):
            removed = _drop_delivered(item, remove, root=root, mark="unlinkedAt")
            rows.append({"from": label, "status": "unlinked", "removed": removed})
            continue
        envelope = answer.get("envelope") if status == 200 else None
        # The usual answer: the envelope this machine already took, because nothing changed since.
        if envelope and _envelope_nonce(envelope) in {item.get("nonce"), *(item.get("nonces") or [])} - {None, ""}:
            envelope = None
        if envelope:
            try:
                body, values = link._open_accepted(envelope, confirm_fingerprint=item["fingerprint"], root=root)
            except link.LinkError as error:
                rows.append({"from": label, "status": "refused", "detail": str(error)})
                body = None
            if body is not None:
                older = link._parse_stamp(body["nbf"]) < link._parse_stamp(item.get("nbf") or body["nbf"])
                if body["iss"] != item["iss"] or older or body["nonce"] in (item.get("nonces") or []):
                    rows.append({"from": label, "status": "refused", "detail": "An older or foreign envelope was ignored."})
                else:
                    landed = _land(body, values, {**item, "issSeal": _issuer_seal(envelope) or item.get("issSeal", "")},
                                   write=write, remove=remove, root=root)
                    rows.append({"from": label, "status": "updated", **landed})
                    continue
        if item.get("exp") and link._parse_stamp(item["exp"]) <= link._now():
            removed = _drop_delivered(item, remove, root=root, mark="expiredAt")
            rows.append({"from": label, "status": "expired", "removed": removed})
            continue
        _touch(item["iss"], root=root)
        if not any(row["from"] == label for row in rows):
            rows.append({"from": label, "status": "current", "removed": []})
    return {"ok": True, "links": rows}


def _issuer_seal(envelope: str) -> str:
    """The sealing key the issuer put in its signed envelope. Read only after the envelope verified."""
    try:
        outer = json.loads(_unb64(envelope[len(link.ENVELOPE_PREFIX):]))
        seal = str(outer["iss_seal"])
        return seal if len(_unb64(seal)) == 32 else ""
    except (ValueError, KeyError, TypeError):
        return ""


def _envelope_nonce(envelope: str) -> str:
    try:
        outer = json.loads(_unb64(envelope[len(link.ENVELOPE_PREFIX):]))
        return str(outer["grant"]["nonce"])
    except (ValueError, KeyError, TypeError):
        return ""


def _touch(iss: str, *, root: Path | None) -> None:
    state = link._read_grants(root)
    for item in state["accepted"]:
        if item.get("iss") == iss:
            item["pulledAt"] = link._stamp(link._now())
    link._write_grants(state, root)


def _drop_delivered(item: Mapping[str, Any], remove: Remover, *, root: Path | None, mark: str) -> list[str]:
    raw = _stored_raw()
    unchanged = sorted(name for name, digest in (item.get("delivered") or {}).items()
                       if name in raw and _raw_digest(raw[name]) == digest)
    if unchanged:
        remove(unchanged)
    state = link._read_grants(root)
    for entry in state["accepted"]:
        if entry.get("iss") == item["iss"]:
            entry[mark] = link._stamp(link._now())
            entry["delivered"] = {}
    link._write_grants(state, root)
    link._record("unlink", unchanged, granted=True, reason=f"{mark[:-2]} from {item.get('fingerprint', '')}",
                 root=root, workspace=passbook.workspace())
    return unchanged


# ── the joining machine's schedule ──────────────────────────────────────────


def _pull_command() -> list[str]:
    return [sys.executable, str(Path(__file__).with_name("passbook_cli.py").resolve()), "link", "pull", "--quiet"]


def schedule_plan(*, root: Path | None = None) -> dict[str, Any]:
    """Where the every-ten-minutes `passbook link pull` goes on this platform, and what it says."""
    import plistlib
    store = str(Path(root if root is not None else passbook.root()).expanduser().resolve())
    command = _pull_command()
    system = sys.platform
    home = Path.home()
    if system == "darwin":
        path = home / "Library" / "LaunchAgents" / f"{SCHEDULE_LABEL}.plist"
        content = plistlib.dumps({"Label": SCHEDULE_LABEL, "ProgramArguments": command,
                                  "EnvironmentVariables": {"HIVE_HOME": store}, "StartInterval": PULL_EVERY_SECONDS,
                                  "RunAtLoad": True, "ProcessType": "Background"})
        return {"platform": "darwin", "path": path, "content": content, "extra": []}
    if system.startswith("linux"):
        config = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config") / "systemd" / "user"
        quoted = " ".join(json.dumps(part) for part in command)
        service = (f"[Unit]\nDescription=PassBook: collect keys lent to this machine\n\n[Service]\nType=oneshot\n"
                   f"Environment=HIVE_HOME={json.dumps(store)}\nExecStart={quoted}\nUMask=0077\n").encode()
        timer = (f"[Unit]\nDescription=PassBook: collect keys lent to this machine\n\n[Timer]\nOnBootSec=1min\n"
                 f"OnUnitActiveSec={PULL_EVERY_SECONDS}s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n").encode()
        return {"platform": "linux", "path": config / f"{SCHEDULE_LABEL}.timer", "content": timer,
                "extra": [(config / f"{SCHEDULE_LABEL}.service", service)]}
    if system == "win32":
        return {"platform": "win32", "path": None, "content": b"", "extra": [],
                "task": ["schtasks", "/Create", "/F", "/SC", "MINUTE", "/MO", str(PULL_EVERY_SECONDS // 60),
                         "/TN", SCHEDULE_LABEL, "/TR", subprocess.list2cmdline(command)]}
    return {"platform": system, "path": None, "content": b"", "extra": []}


def schedule(*, install: bool = True, root: Path | None = None) -> dict[str, Any]:
    """Install (or remove) the schedule that keeps this machine's borrowed keys current."""
    plan = schedule_plan(root=root)
    manual = " ".join(_pull_command())
    if plan["platform"] == "darwin":
        target = plan["path"]
        domain = f"gui/{os.getuid()}"
        subprocess.run(["launchctl", "bootout", domain, str(target)], capture_output=True, check=False)
        if not install:
            target.unlink(missing_ok=True)
            return {"ok": True, "installed": False, "where": str(target)}
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(plan["content"])
        loaded = subprocess.run(["launchctl", "bootstrap", domain, str(target)], capture_output=True, check=False)
        return {"ok": loaded.returncode == 0, "installed": True, "where": str(target),
                "detail": "" if loaded.returncode == 0 else f"Saved, but launchd did not start it. Run: {manual}"}
    if plan["platform"] == "linux":
        systemctl = shutil.which("systemctl")
        if not install:
            if systemctl:
                subprocess.run([systemctl, "--user", "disable", "--now", f"{SCHEDULE_LABEL}.timer"], capture_output=True, check=False)
            for path in [plan["path"], *(item[0] for item in plan["extra"])]:
                path.unlink(missing_ok=True)
            return {"ok": True, "installed": False, "where": str(plan["path"])}
        if not systemctl:
            return {"ok": False, "installed": False,
                    "detail": f"This machine has no systemd. Run this every ten minutes yourself: {manual}"}
        plan["path"].parent.mkdir(parents=True, exist_ok=True)
        for path, content in [(plan["path"], plan["content"]), *plan["extra"]]:
            path.write_bytes(content)
        subprocess.run([systemctl, "--user", "daemon-reload"], capture_output=True, check=False)
        started = subprocess.run([systemctl, "--user", "enable", "--now", f"{SCHEDULE_LABEL}.timer"], capture_output=True, check=False)
        detail = "" if started.returncode == 0 else f"Saved, but systemd did not start it. Run this every ten minutes yourself: {manual}"
        if started.returncode == 0 and not os.environ.get("XDG_RUNTIME_DIR"):
            detail = "It runs while you are signed in. For a server, also run: loginctl enable-linger"
        return {"ok": started.returncode == 0, "installed": True, "where": str(plan["path"]), "detail": detail}
    if plan["platform"] == "win32":
        if not install:
            subprocess.run(["schtasks", "/Delete", "/F", "/TN", SCHEDULE_LABEL], capture_output=True, check=False)
            return {"ok": True, "installed": False, "where": SCHEDULE_LABEL}
        made = subprocess.run(plan["task"], capture_output=True, check=False)
        return {"ok": made.returncode == 0, "installed": made.returncode == 0, "where": SCHEDULE_LABEL,
                "detail": "" if made.returncode == 0 else f"Run this every ten minutes yourself: {manual}"}
    return {"ok": False, "installed": False, "detail": f"Run this every ten minutes yourself: {manual}"}


def scheduled() -> bool:
    plan = schedule_plan()
    if plan["platform"] == "win32":
        return subprocess.run(["schtasks", "/Query", "/TN", SCHEDULE_LABEL], capture_output=True, check=False).returncode == 0
    return bool(plan["path"] and Path(plan["path"]).exists())


__all__ = ["JoinError", "cancel_invite", "choices", "complete_invites", "create_invite", "invites", "join",
           "parse_invite", "pull", "refresh", "resolve_selection", "schedule", "scheduled", "unlink"]
