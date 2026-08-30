# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""How PassBook decides whether a credential may be read, right now.

Split out of the broker on purpose: the decision is pure logic over two small
files, so it can be reasoned about and tested without a daemon running, and the
broker is left holding only the things that genuinely need a live process.

## The modes

Every key, for every app, resolves to one of four:

  always   hand it over, no interruption
  ask      hold the request and ask the owner; a granted answer can be
           remembered for a while
  window   hand it over inside a schedule, refuse outside it
  never    refuse

Most specific wins: a key's own mode, then the app's default, then the machine
default. A machine that has never configured any of this sits at `always`, which
is what it did before these modes existed.

## Unlocks

`ask` is the mode people mean when they say "check with me", and answering it
forty times an hour is how a security feature gets turned off. So an **unlock**
is a time-boxed decision: approve once, for an hour, and everything the unlock
covers stops asking until it expires. That is deliberately the same shape as
the door on a building — held open for a stated period, by someone who said so,
with a record of who and when — rather than a checkbox that stays ticked.

Unlocks are files, not memory, so restarting the broker does not silently revoke
one the owner is relying on, and expiry is checked on read rather than on a
timer, so a clock change or a sleeping laptop cannot leave one open forever.
"""

from __future__ import annotations

import json
import os
import re
import secrets
from datetime import datetime, time as clock, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping

import passbook

__all__ = [
    "DEFAULT_SCOPE",
    "SCOPES",
    "may_change_scope",
    "scope_allows",
    "scope_for",
    "set_scope",
    "AUDIENCE_MODES",
    "audience_allows",
    "audience_for",
    "key_entry",
    "set_audience",
    "REACHES",
    "add_umbrella_projects",
    "create_umbrella",
    "delete_umbrella",
    "listed_umbrellas",
    "put_under_umbrella",
    "read_umbrellas",
    "remove_umbrella_projects",
    "set_umbrella_listed",
    "set_umbrella_projects",
    "set_umbrella_reach",
    "set_umbrella_tags",
    "take_from_umbrella",
    "umbrella_conflicts",
    "umbrella_for_key",
    "umbrella_id",
    "umbrella_keys",
    "umbrella_record",
    "GRANT_MODES",
    "POLICY_FILENAME",
    "SESSIONS_FILENAME",
    "ask_timeout",
    "close_session",
    "decide_key",
    "describe_duration",
    "describe_window",
    "mode_for",
    "policy_path",
    "session_covers",
    "sessions_path",
    "open_session",
    "parse_duration",
    "read_policy",
    "requires_passkey",
    "sessions",
    "upgrade_policy",
    "within_window",
    "write_policy",
]

POLICY_FILENAME = "passbook-policy.json"
SESSIONS_FILENAME = "passbook-sessions.json"
POLICY_VERSION = 3

GRANT_MODES = ("always", "ask", "window", "never")
DEFAULT_MODE = "always"

# Presets a person actually reaches for. Custom durations are parsed too; these
# exist so a UI has something to put on buttons.
DURATION_PRESETS = ("15m", "1h", "4h", "8h", "24h")
MAX_SESSION_SECONDS = 7 * 24 * 3600

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_DURATION = re.compile(r"^\s*(\d+)\s*([smhd])?\s*$", re.IGNORECASE)
_CLOCK = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


def policy_path(root: Path | None = None) -> Path:
    return (Path(root) if root is not None else passbook.root()) / POLICY_FILENAME


def sessions_path(root: Path | None = None) -> Path:
    return (Path(root) if root is not None else passbook.root()) / SESSIONS_FILENAME


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _stamp(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _parse_stamp(text: str) -> datetime:
    return datetime.fromisoformat(str(text).replace("Z", "+00:00"))


def _write_private(path: Path, payload: Mapping[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
    os.chmod(path, 0o600)
    return path


# ── durations ──────────────────────────────────────────────────────────────


def parse_duration(text: str) -> int:
    """`30m`, `2h`, `1d`, or a bare number of seconds. Raises on nonsense.

    Capped at a week. An unlock that outlives the reason for it is just the
    `always` mode with extra steps and a worse audit trail.
    """
    match = _DURATION.match(str(text))
    if not match:
        raise ValueError(f"{text!r} is not a duration — try 30m, 2h or 1d")
    amount = int(match.group(1))
    unit = (match.group(2) or "s").lower()
    seconds = amount * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    if seconds <= 0:
        raise ValueError("A duration has to be longer than nothing")
    if seconds > MAX_SESSION_SECONDS:
        raise ValueError("An unlock cannot last longer than 7 days")
    return seconds


def describe_duration(seconds: int) -> str:
    """Plain words for a countdown, so a UI never has to render '3540 seconds'."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        hours, minutes = divmod(seconds // 60, 60)
        return f"{hours}h" if not minutes else f"{hours}h {minutes}m"
    return f"{seconds // 86400}d"


# ── policy ─────────────────────────────────────────────────────────────────


def upgrade_policy(loaded: Mapping[str, Any]) -> dict[str, Any]:
    """Read any policy this product has ever written, as the current shape.

    Version 1 had two machine-wide modes and a flat key list per app. Rather
    than migrate the file on disk — which would break a machine that still runs
    an older PassBook against the same store — it is translated on read.
    """
    if not isinstance(loaded, dict):
        return {"version": POLICY_VERSION, "default": {"mode": DEFAULT_MODE},
                "apps": {}, "keys": {}, "groups": {}}

    legacy = str(loaded.get("mode") or "")
    if legacy in {"audit", "deny"} or int(loaded.get("version") or 1) < POLICY_VERSION:
        apps: dict[str, Any] = {}
        for app, entry in (loaded.get("apps") or {}).items():
            if not isinstance(entry, dict):
                continue
            keys = entry.get("keys")
            if isinstance(keys, dict):
                apps[app] = entry
                continue
            apps[app] = {
                "default": {"mode": "never" if legacy == "deny" else DEFAULT_MODE},
                "keys": {str(key): {"mode": "always"} for key in (keys or [])},
            }
        return {
            "version": POLICY_VERSION,
            # `audit` granted everything; `deny` granted only what was listed.
            "default": {"mode": "never" if legacy == "deny" else DEFAULT_MODE},
            "apps": apps,
            "keys": loaded.get("keys") if isinstance(loaded.get("keys"), dict) else {},
            "groups": loaded.get("groups") if isinstance(loaded.get("groups"), dict) else {},
        }

    current = {
        "version": POLICY_VERSION,
        "default": loaded.get("default") if isinstance(loaded.get("default"), dict) else {"mode": DEFAULT_MODE},
        "apps": loaded.get("apps") if isinstance(loaded.get("apps"), dict) else {},
        "keys": loaded.get("keys") if isinstance(loaded.get("keys"), dict) else {},
        "groups": loaded.get("groups") if isinstance(loaded.get("groups"), dict) else {},
    }
    # Anything a newer PassBook wrote is carried through untouched, so an older
    # one reading and rewriting the same store does not quietly delete it. The
    # write side does the same; forward compatibility only works on both.
    for section, value in loaded.items():
        current.setdefault(str(section), value)
    return current


def read_policy(root: Path | None = None) -> dict[str, Any]:
    """The policy, or a permissive default. A broken policy never refuses.

    A parse error that silently denied everything would take the machine down
    and look like a credential fault the whole time.
    """
    try:
        return upgrade_policy(json.loads(policy_path(root).read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {"version": POLICY_VERSION, "default": {"mode": DEFAULT_MODE},
                "apps": {}, "keys": {}, "groups": {}}


def write_policy(policy: Mapping[str, Any], root: Path | None = None) -> Path:
    """Persist a policy. Every section, or a caller's edit vanishes silently.

    This listed its sections literally and so dropped `keys` and `groups` the
    moment they existed: `agents set` printed the new audience, wrote a file
    without it, and the next read said "every agent" again.
    """
    written = {
        "version": POLICY_VERSION,
        "default": policy.get("default") or {"mode": DEFAULT_MODE},
        "apps": policy.get("apps") or {},
        "keys": policy.get("keys") or {},
        "groups": policy.get("groups") or {},
    }
    # Anything a newer PassBook added and this one does not know about is kept
    # rather than silently deleted by an older machine sharing the same store.
    for section, value in policy.items():
        written.setdefault(str(section), value)
    return _write_private(policy_path(root), written)


def mode_for(app: str, key: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """The rule that applies to one key for one app. Most specific wins."""
    apps = policy.get("apps")
    if not isinstance(apps, dict):
        apps = {}
    entry = apps.get(str(app))
    if not isinstance(entry, dict):
        entry = apps.get("*") if isinstance(apps.get("*"), dict) else {}
    # Shape, not just syntax. A hand-edited or older-format `keys` can be a list
    # rather than a mapping, and reaching for `.get` on it raised inside the
    # broker's request handler — where the cost was not a bad answer but no
    # answer at all.
    keys = entry.get("keys")
    if not isinstance(keys, dict):
        keys = {}
    for candidate in (str(key), "*"):
        rule = keys.get(candidate)
        if isinstance(rule, dict) and rule.get("mode") in GRANT_MODES:
            return rule
    for source in (entry.get("default"), policy.get("default")):
        if isinstance(source, dict) and source.get("mode") in GRANT_MODES:
            return source
    return {"mode": DEFAULT_MODE}


# ── how far a key reaches ──────────────────────────────────────────────────
#
# A workspace never sees a sibling's keys, which is the right default and is
# occasionally the wrong one: an OpenAI key is usually meant for everything on
# the machine, while a client's credential is meant for exactly one workspace.
# So a key carries a **scope**:
#
#   workspace   the workspace that owns it, and nobody else (the default)
#   machine     every workspace on this machine
#   tailnet     as above, and eligible to be lent to a linked machine
#
# `tailnet` is a permission, not a sync. PassBook lends keys by explicit
# envelope (`passbook link`); widening a scope makes a key eligible for that and
# does not move it anywhere by itself. Saying otherwise would promise a
# replication this project does not do.
#
# ## Ownership
#
# Widening a scope hands a credential to workspaces that did not have it, so the
# workspace it came from keeps that decision. Anyone else can see the scope and
# read the key; only the owner can change how far it reaches. Otherwise sharing
# a key with a workspace would hand that workspace the power to share it onward,
# which is not sharing — it is giving it away.

SCOPES = ("workspace", "machine", "tailnet")
# The widest reach, because that is what the standard already promises: one
# store per machine, shared by every app that opts in, and lendable to a linked
# machine on purpose. A key narrows when somebody narrows it, and until then it
# behaves the way a store with no workspaces configured always has.
DEFAULT_SCOPE = "tailnet"


def scope_for(key: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """A key's reach and who decides it. Unreadable entries read as the default.

    The default is the widest reach. A store with no workspaces configured has
    always been one file shared by every app on the machine, and linking exists
    so a key can be lent onward deliberately; starting narrow would quietly
    change what an existing store means. A key narrows when somebody narrows it.
    """
    entry = key_entry(key, policy)
    raw = str(entry.get("scope", "") or "").strip().lower()
    return {
        "scope": raw if raw in SCOPES else DEFAULT_SCOPE,
        "owner": str(entry.get("owner_workspace", "") or ""),
        "explicit": raw in SCOPES,
    }


def scope_allows(workspace: str, key: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """May a process acting for this workspace read this key at all?"""
    rule = scope_for(key, policy)
    here = str(workspace or "")
    if rule["scope"] in {"machine", "tailnet"}:
        return {"allowed": True, "why": f"scoped to the whole {rule['scope']}"}
    owner = rule["owner"]
    if not owner or not here or here == owner:
        return {"allowed": True, "why": "this workspace owns it"}
    return {"allowed": False,
            "why": f"scoped to the {owner} workspace"}


def may_change_scope(workspace: str, key: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """Only the workspace a key came from decides how far it reaches."""
    rule = scope_for(key, policy)
    owner, here = rule["owner"], str(workspace or "")
    if not owner:
        return {"allowed": True, "why": "no workspace has claimed this key yet"}
    if here == owner:
        return {"allowed": True, "why": "this workspace owns it"}
    return {"allowed": False,
            "why": f"only the {owner} workspace can change this key's scope"}


def set_scope(key: str, scope: str, policy: MutableMapping[str, Any], *,
              workspace: str = "") -> dict[str, Any]:
    """Set a key's reach, in place. Refuses unless this workspace owns it."""
    wanted = str(scope).strip().lower()
    if wanted not in SCOPES:
        raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
    verdict = may_change_scope(workspace, key, policy)
    if not verdict["allowed"]:
        raise PermissionError(verdict["why"])
    keys = policy.setdefault("keys", {})
    entry = keys.setdefault(str(key), {})
    entry["scope"] = wanted
    # The first workspace to scope a key claims it. A machine with no workspaces
    # configured records no owner, so nothing is locked to a name that does not
    # exist yet and any workspace created later can still take it.
    if workspace:
        entry.setdefault("owner_workspace", str(workspace))
    return scope_for(key, policy)


# ── who a key is for ───────────────────────────────────────────────────────
#
# The modes above answer "how is this app handled". That is the right question
# when you are configuring one app, and the wrong one when you are looking at
# one credential and asking who can see it — which is the question people
# actually ask about a production database password.
#
# So a key carries its own audience, in one of three shapes:
#
#   all                every agent, which is the default and what a machine
#                      that has never configured this does today
#   include [...]      only these, and nothing else
#   exclude [...]      everyone except these
#
# An audience is a hard bound, checked before any mode. A key that excludes an
# agent is not "ask" for that agent — it is no, and no amount of approving
# prompts changes it. That is what makes it safe to hand someone the shape of
# their whole store and let them exclude the three keys that matter.

AUDIENCE_MODES = ("all", "include", "exclude")


def key_entry(key: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """Everything the policy records about one key. Never a value."""
    keys = policy.get("keys")
    if not isinstance(keys, dict):
        return {}
    entry = keys.get(str(key))
    return entry if isinstance(entry, dict) else {}


def audience_for(key: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """A key's audience, normalised. Anything unreadable degrades to `all`.

    Degrading open rather than shut is deliberate: a corrupt or hand-edited
    entry must not silently cut every agent off from a credential, because the
    failure would look like an outage somewhere else entirely.
    """
    raw = key_entry(key, policy).get("agents", "all")
    if isinstance(raw, str):
        return {"mode": "all", "agents": []} if raw.strip().lower() in {"", "all", "*"} else {
            "mode": "include", "agents": [raw.strip()]}
    if isinstance(raw, list):
        return {"mode": "include", "agents": sorted({str(a).strip() for a in raw if str(a).strip()})}
    if isinstance(raw, dict):
        for mode in ("include", "exclude"):
            listed = raw.get(mode)
            if isinstance(listed, list):
                names = sorted({str(a).strip() for a in listed if str(a).strip()})
                if names:
                    return {"mode": mode, "agents": names}
    return {"mode": "all", "agents": []}


def audience_allows(app: str, key: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """May this agent see this key at all, before any mode is considered?"""
    rule = audience_for(key, policy)
    name = str(app).strip()
    if rule["mode"] == "all":
        return {"allowed": True, "why": "every agent"}
    if rule["mode"] == "include":
        if name in rule["agents"]:
            return {"allowed": True, "why": f"{name} is on this key's list"}
        return {"allowed": False,
                "why": f"this key is limited to {', '.join(rule['agents'])}"}
    if name in rule["agents"]:
        return {"allowed": False, "why": f"{name} is excluded from this key"}
    return {"allowed": True, "why": "not excluded"}


# ── confirmations for changes ──────────────────────────────────────────────
#
# Everything else in this file is about READS. These are about WRITES: whether
# adding, changing or removing a key should stop and ask the person first.
#
# Off by default, all three, because a machine where every `passbook add` waits
# on a dialog is one where people stop using `passbook add`. Turned on, they
# make the store's contents something that cannot change quietly — which is a
# different property from its values being unreadable, and the one that catches
# an agent helpfully "fixing" a credential.

CONFIRM_OPS = ("add", "modify", "delete")


def confirmations(policy: Mapping[str, Any]) -> dict[str, bool]:
    """Which changes need a person to say yes. Unreadable entries read as off.

    Degrading OFF here, where audiences degrade OPEN, is the same instinct
    pointed the same way: neither should turn a corrupt policy file into a
    machine that has locked its owner out of their own store.
    """
    raw = policy.get("confirm")
    if not isinstance(raw, dict):
        return {op: False for op in CONFIRM_OPS}
    return {op: bool(raw.get(op, False)) for op in CONFIRM_OPS}


def set_confirmation(op: str, required: bool, policy: MutableMapping[str, Any]) -> dict[str, bool]:
    """Turn one confirmation on or off."""
    op = str(op).strip().lower()
    if op not in CONFIRM_OPS:
        raise ValueError(f"confirmation must be one of {', '.join(CONFIRM_OPS)}")
    current = confirmations(policy)
    current[op] = bool(required)
    policy["confirm"] = current
    return current


def needs_confirmation(op: str, policy: Mapping[str, Any]) -> bool:
    return confirmations(policy).get(str(op).strip().lower(), False)


# ── umbrellas ──────────────────────────────────────────────────────────────
#
# An umbrella covers projects and holds keys, so one credential serves several
# checkouts without going machine-wide.
#
#     ai apps (umbrella, tags: llm, media)
#       ├── ami          (project)
#       ├── hivemindos   (project)
#       └── ansem        (project)
#
# It is deliberately NOT called a group. `passbook_catalog` already has groups:
# families inferred from a key's own name, so a store of three hundred keys can
# be read. Those must never gate anything — every key on a machine falls into
# one, so gating on inference would put the whole store behind rules nobody
# wrote. Two things that decide such different questions cannot share a noun; a
# command whose meaning depends on invisible state is one a person stops
# reading. A key's group arranges a listing. A key's umbrella bounds a read.
#
# ## Where this sits, and what it is not
#
# There are two axes and it is worth being exact, because they look alike from
# a distance and an owner choosing between them by feel will get it wrong:
#
#   * a WORKSPACE decides which store a key lives in — a separate file, one per
#     process, `scope` bounds by it.
#   * an UMBRELLA decides which projects may read a key inside whatever store it
#     is already in. It moves nothing.
#
# So they compose rather than compete: a key can be workspace-scoped AND under
# an umbrella, and both must say yes. What they must never do is disagree
# silently — an umbrella that names projects a key cannot reach anyway reads as
# a grant and behaves as a refusal. `umbrella_conflicts` exists to say so out
# loud rather than leave somebody debugging a credential that was never coming.
#
# ## Reach and visibility are two switches, not one
#
# `open` used to mean both "every project may use it" and "agents may see it",
# which made the useful middle unreachable: an umbrella an agent can SEE but may
# not use, so it learns "there is a media umbrella and it is not for me" instead
# of learning nothing. They are separate now. `open` and `close` remain as the
# two common corners.
#
# Closed is the default and holds from the moment the umbrella exists, not from
# the moment somebody finishes filling it in — that window is exactly when a
# person is most likely to be interrupted.
#
# Umbrellas do not nest. A project may sit under several and then sees the union.

REACHES = ("members", "everyone")
DEFAULT_REACH = "members"

_UMBRELLA_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def umbrella_id(label: str) -> str:
    """The id a label is filed under: lowercased, spaces to hyphens.

    So `passbook umbrella new "ai apps"` and `passbook umbrella open ai-apps`
    are the same umbrella. The label is kept verbatim for display.
    """
    handle = "-".join(str(label).strip().lower().split())
    handle = re.sub(r"[^a-z0-9._-]", "-", handle).strip("-")
    handle = re.sub(r"-{2,}", "-", handle)
    if not _UMBRELLA_ID.match(handle):
        raise ValueError(f"{label!r} is not a usable umbrella name")
    return handle


def read_umbrellas(policy: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Every umbrella, normalised. Never raises on a damaged entry."""
    raw = policy.get("umbrellas")
    if not isinstance(raw, dict):
        return {}
    found: dict[str, dict[str, Any]] = {}
    for uid, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        try:
            handle = umbrella_id(str(uid))
        except ValueError:
            continue
        projects, tags = entry.get("projects"), entry.get("tags")
        reach = str(entry.get("reach", "") or "").strip().lower()
        found[handle] = {
            "id": handle,
            "label": str(entry.get("label") or uid),
            # Anything unreadable is the CLOSED corner. Degrading open would
            # hand an umbrella's keys to every project on the machine the first
            # time something writes this file wrongly.
            "reach": reach if reach in REACHES else DEFAULT_REACH,
            "listed": entry.get("listed") is True,
            "projects": sorted({str(x).strip() for x in projects if str(x).strip()})
            if isinstance(projects, list) else [],
            "tags": sorted({str(x).strip() for x in tags if str(x).strip()})
            if isinstance(tags, list) else [],
            "note": str(entry.get("note") or ""),
        }
    return found


def umbrella_record(umbrella: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """One umbrella, or `{}` when no such umbrella was ever created."""
    try:
        handle = umbrella_id(umbrella)
    except ValueError:
        return {}
    return read_umbrellas(policy).get(handle, {})


def umbrella_for_key(key: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """The umbrella a key was put under, or `{}`.

    Only an explicit `umbrella` on the key counts. A key's display GROUP is not
    consulted here and must not be: that is the inference this whole design
    keeps away from the decision.
    """
    named = key_entry(key, policy).get("umbrella")
    if not isinstance(named, str) or not named.strip():
        return {}
    return umbrella_record(named, policy)


def umbrella_keys(umbrella: str, policy: Mapping[str, Any]) -> list[str]:
    """Which keys are under an umbrella, by name."""
    try:
        handle = umbrella_id(umbrella)
    except ValueError:
        return []
    keys = policy.get("keys")
    if not isinstance(keys, dict):
        return []
    found = []
    for name, entry in keys.items():
        if not isinstance(entry, dict):
            continue
        named = entry.get("umbrella")
        if isinstance(named, str) and named.strip():
            try:
                if umbrella_id(named) == handle:
                    found.append(str(name))
            except ValueError:
                continue
    return sorted(found)


def create_umbrella(label: str, policy: MutableMapping[str, Any], *,
                    tags: Iterable[str] = (), note: str = "",
                    reach: str = DEFAULT_REACH, listed: bool = False) -> dict[str, Any]:
    """Create an umbrella. Closed and unlisted unless asked otherwise."""
    handle = umbrella_id(label)
    wanted = str(reach).strip().lower()
    if wanted not in REACHES:
        raise ValueError(f"reach must be one of {', '.join(REACHES)}")
    umbrellas = policy.setdefault("umbrellas", {})
    entry = umbrellas.setdefault(handle, {})
    entry.setdefault("label", str(label).strip())
    entry.setdefault("projects", [])
    entry["reach"] = wanted
    entry["listed"] = bool(listed) or entry.get("listed") is True
    named = sorted({str(t).strip() for t in tags if str(t).strip()})
    if named:
        entry["tags"] = sorted(set(entry.get("tags") or []) | set(named))
    if note:
        entry["note"] = str(note).strip()
    return read_umbrellas(policy)[handle]


def delete_umbrella(umbrella: str, policy: MutableMapping[str, Any]) -> bool:
    """Remove an umbrella, and take its keys out from under it."""
    handle = umbrella_id(umbrella)
    umbrellas = policy.get("umbrellas")
    if not isinstance(umbrellas, dict) or handle not in umbrellas:
        return False
    for key in umbrella_keys(handle, policy):
        policy["keys"][key].pop("umbrella", None)
    del umbrellas[handle]
    return True


def _require(umbrella: str, policy: Mapping[str, Any]) -> str:
    handle = umbrella_id(umbrella)
    if not umbrella_record(handle, policy):
        raise ValueError(f"there is no umbrella called {umbrella!r}")
    return handle


def set_umbrella_projects(umbrella: str, projects: Iterable[str],
                          policy: MutableMapping[str, Any]) -> dict[str, Any]:
    handle = _require(umbrella, policy)
    policy["umbrellas"][handle]["projects"] = sorted(
        {str(p).strip() for p in projects if str(p).strip()})
    return read_umbrellas(policy)[handle]


def add_umbrella_projects(umbrella: str, projects: Iterable[str],
                          policy: MutableMapping[str, Any]) -> dict[str, Any]:
    existing = umbrella_record(umbrella, policy)
    if not existing:
        raise ValueError(f"there is no umbrella called {umbrella!r}")
    return set_umbrella_projects(umbrella, [*existing["projects"], *projects], policy)


def remove_umbrella_projects(umbrella: str, projects: Iterable[str],
                             policy: MutableMapping[str, Any]) -> dict[str, Any]:
    existing = umbrella_record(umbrella, policy)
    if not existing:
        raise ValueError(f"there is no umbrella called {umbrella!r}")
    dropping = {str(p).strip() for p in projects if str(p).strip()}
    return set_umbrella_projects(
        umbrella, [p for p in existing["projects"] if p not in dropping], policy)


def put_under_umbrella(umbrella: str, keys: Iterable[str],
                       policy: MutableMapping[str, Any]) -> dict[str, Any]:
    """Put keys under an umbrella. This is an access change, not an arrangement."""
    handle = _require(umbrella, policy)
    held = policy.setdefault("keys", {})
    for key in keys:
        held.setdefault(str(key), {})["umbrella"] = handle
    return read_umbrellas(policy)[handle]


def take_from_umbrella(keys: Iterable[str], policy: MutableMapping[str, Any]) -> list[str]:
    """Take keys out from under whatever umbrella they were under."""
    held = policy.get("keys")
    if not isinstance(held, dict):
        return []
    freed = []
    for key in keys:
        entry = held.get(str(key))
        if isinstance(entry, dict) and entry.pop("umbrella", None) is not None:
            freed.append(str(key))
    return sorted(freed)


def set_umbrella_reach(umbrella: str, reach: str,
                       policy: MutableMapping[str, Any]) -> dict[str, Any]:
    """Who may USE it: its own projects, or every project."""
    handle = _require(umbrella, policy)
    wanted = str(reach).strip().lower()
    if wanted not in REACHES:
        raise ValueError(f"reach must be one of {', '.join(REACHES)}")
    policy["umbrellas"][handle]["reach"] = wanted
    return read_umbrellas(policy)[handle]


def set_umbrella_listed(umbrella: str, listed: bool,
                        policy: MutableMapping[str, Any]) -> dict[str, Any]:
    """Whether agents are told this umbrella exists. Independent of reach."""
    handle = _require(umbrella, policy)
    policy["umbrellas"][handle]["listed"] = bool(listed)
    return read_umbrellas(policy)[handle]


def set_umbrella_tags(umbrella: str, tags: Iterable[str], policy: MutableMapping[str, Any], *,
                      note: str | None = None) -> dict[str, Any]:
    """What an agent reads to judge whether an umbrella is meant for its task."""
    handle = _require(umbrella, policy)
    policy["umbrellas"][handle]["tags"] = sorted(
        {str(t).strip() for t in tags if str(t).strip()})
    if note is not None:
        policy["umbrellas"][handle]["note"] = str(note).strip()
    return read_umbrellas(policy)[handle]


def listed_umbrellas(policy: Mapping[str, Any], *, project: str = "") -> list[dict[str, Any]]:
    """The umbrellas an agent may be told about: name, tags, note, and whether
    it may actually use them. Never keys.

    An unlisted umbrella is not advertised. Its keys still appear in a listing
    under their own names — hiding a NAME would make a refusal look like a
    missing credential — but which projects share it is not an outsider's
    business.
    """
    here = str(project).strip()
    return [
        {"name": record["label"], "id": record["id"], "tags": record["tags"],
         "note": record["note"],
         # Answered for the CALLER, not in the abstract. An umbrella reachable
         # by everyone is usable; so is one this caller's project sits under.
         # Reporting reach alone told a member it could not use the very
         # umbrella that was granting it keys.
         "usable_here": record["reach"] == "everyone" or (bool(here) and here in record["projects"])}
        for record in sorted(read_umbrellas(policy).values(), key=lambda r: r["id"])
        if record["listed"]
    ]


def umbrella_conflicts(umbrella: str, policy: Mapping[str, Any], *,
                       workspace: str = "") -> list[dict[str, str]]:
    """Where this umbrella promises something another bound already refuses.

    Two bounds on one key are fine and are the point — they compose, and both
    must say yes. What is not fine is a rule that READS like a grant and
    BEHAVES like a refusal, which is what an umbrella covering a project does
    when the key it covers is scoped to a workspace, or fenced by a per-key
    rule of its own. Nothing here changes a decision; it exists so the owner is
    told at the moment they write the rule rather than by an outage later.
    """
    record = umbrella_record(umbrella, policy)
    if not record:
        return []
    found: list[dict[str, str]] = []
    for key in umbrella_keys(record["id"], policy):
        entry = key_entry(key, policy)
        if "projects" in entry and str(entry.get("projects")).strip().lower() not in {"all", "*"}:
            rule = project_for(key, policy)
            found.append({
                "key": key,
                "why": f"{key} has its own project rule ({rule['mode']}: "
                       f"{', '.join(rule['projects']) or 'none'}), which outranks this umbrella",
            })
        reach = scope_for(key, policy)
        if reach["scope"] == "workspace" and reach.get("owner") and workspace                 and reach["owner"] != workspace:
            found.append({
                "key": key,
                "why": f"{key} is scoped to the {reach['owner']} workspace, so this "
                       f"umbrella cannot reach it from {workspace}",
            })
    return found


# ── guards ─────────────────────────────────────────────────────────────────
#
# Every bound above answers "may this caller HOLD this key". A guard answers a
# later question: given that something may use it, where may it go? Two lists,
# because there are exactly two ways a value leaves the broker — a command it is
# injected into, and a host it is sent to.
#
# These are read at use time by `passbook_grant`, which owns the matching. This
# section owns storage, so that every section of the policy file is written in
# one place and `write_policy` stays the only thing that knows the shape.


def read_guards(policy: Mapping[str, Any]) -> dict[str, Any]:
    guards = policy.get("guards")
    return dict(guards) if isinstance(guards, Mapping) else {}


def set_guard(key: str, policy: MutableMapping[str, Any], *,
              commands: Iterable[str] | None = None,
              destinations: Iterable[str] | None = None,
              replace: bool = False) -> dict[str, Any]:
    """Bind a key to the commands that may receive it and the hosts it may reach.

    Additive by default. A guard is written one line at a time — `--to` today,
    another host next week — and a call that quietly dropped what came before
    would turn every addition into a silent narrowing that only shows up when
    something stops working.
    """
    name = str(key).strip()
    if not name:
        raise ValueError("which key?")
    guards = read_guards(policy)
    rule = dict(guards.get(name) or {}) if not replace else {}

    if commands is not None:
        existing = [] if replace else list(rule.get("commands") or [])
        rule["commands"] = sorted({*existing, *(str(c).strip() for c in commands if str(c).strip())})
    if destinations is not None:
        existing = [] if replace else list(rule.get("destinations") or [])
        rule["destinations"] = sorted({
            *existing,
            *(str(d).strip().lower().lstrip("*") for d in destinations if str(d).strip())})

    guards[name] = rule
    policy["guards"] = guards
    return rule


def clear_guard(key: str, policy: MutableMapping[str, Any]) -> bool:
    """Unbind a key entirely. Returns whether there was anything to remove."""
    guards = read_guards(policy)
    if str(key).strip() not in guards:
        return False
    guards.pop(str(key).strip())
    policy["guards"] = guards
    return True


# ── projects ───────────────────────────────────────────────────────────────
#
# A third bound, beside scope (which workspaces) and audience (which agents):
# which PROJECTS a key is for. The same three modes, because they are the same
# question asked about a different noun, and a second vocabulary for `include`
# would be a second thing to learn.
#
# A project is a claim the caller makes, exactly like an agent name — usually
# the basename of its git root. It decides policy and fills the record; it is
# not a password, and this file does not pretend otherwise. What it buys is
# real all the same: a key scoped to one project is not handed to an agent
# running in a different checkout, so a prompt injection in one repository
# cannot spend another repository's credentials.

PROJECT_MODES = ("all", "include", "exclude")


def project_for(key: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """A key's projects, normalised. Anything unreadable degrades to `all`.

    Open rather than shut, for the reason `audience_for` degrades open: a
    corrupt entry must not cut every project off from a credential, because the
    failure would look like an outage somewhere else entirely.
    """
    entry = key_entry(key, policy)
    raw = entry.get("projects", "all")
    explicit = "projects" in entry
    if isinstance(raw, str) and raw.strip().lower() not in {"", "all", "*"}:
        return {"mode": "include", "projects": [raw.strip()]}
    if isinstance(raw, list):
        return {"mode": "include",
                "projects": sorted({str(a).strip() for a in raw if str(a).strip()})}
    if isinstance(raw, dict):
        for mode in ("include", "exclude"):
            listed = raw.get(mode)
            if isinstance(listed, list):
                names = sorted({str(a).strip() for a in listed if str(a).strip()})
                if names:
                    return {"mode": mode, "projects": names}
    # A rule written on the key itself is somebody's decision about that key and
    # outranks the group it happens to sit in — the same instinct that lets an
    # explicit group beat an inferred one. Only when the key says nothing does
    # its group get to speak.
    if not explicit or str(raw).strip().lower() in {"", "all", "*"}:
        held = umbrella_for_key(key, policy)
        if held and held["reach"] != "everyone":
            return {"mode": "include", "projects": list(held["projects"]),
                    "umbrella": held["label"]}
    return {"mode": "all", "projects": []}


def project_allows(project: str, key: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """May a caller working in this project see this key?"""
    rule = project_for(key, policy)
    name = str(project).strip()
    if rule["mode"] == "all":
        return {"allowed": True, "why": "every project"}
    # A closed group with nothing in it yet. Closed means closed from the moment
    # it exists, so this is readable by nobody — and the reason has to name the
    # group, or it presents as a key that has gone missing.
    if rule["mode"] == "include" and not rule["projects"]:
        held = rule.get("umbrella")
        return {"allowed": False,
                "why": (f"the {held} umbrella is closed and covers no projects yet"
                        if held else "this key is limited to projects, and none are listed")}
    if rule.get("umbrella"):
        covers = ", ".join(rule["projects"])
        if name and name in rule["projects"]:
            return {"allowed": True, "why": f"{name} is under the {rule['umbrella']} umbrella"}
        if not name:
            return {"allowed": False,
                    "why": f"this key is under the {rule['umbrella']} umbrella ({covers}), "
                           "and this caller named no project"}
        return {"allowed": False,
                "why": f"this key is under the {rule['umbrella']} umbrella, which covers {covers}"}
    if not name:
        # An `include` list is a statement that this key belongs to named
        # projects. A caller that names none is not one of them.
        if rule["mode"] == "include":
            return {"allowed": False,
                    "why": f"this key is limited to {', '.join(rule['projects'])}, "
                           "and this caller named no project"}
        return {"allowed": True, "why": "no project named, and none is excluded"}
    if rule["mode"] == "include":
        if name in rule["projects"]:
            return {"allowed": True, "why": f"{name} is on this key's list"}
        return {"allowed": False,
                "why": f"this key is limited to {', '.join(rule['projects'])}"}
    if name in rule["projects"]:
        return {"allowed": False, "why": f"{name} is excluded from this key"}
    return {"allowed": True, "why": "not excluded"}


def set_projects(key: str, mode: str, projects: Iterable[str],
                 policy: MutableMapping[str, Any]) -> dict[str, Any]:
    """Set which projects a key is for. Returns the normalised rule."""
    mode = str(mode).strip().lower()
    if mode not in PROJECT_MODES:
        raise ValueError(f"projects must be one of {', '.join(PROJECT_MODES)}")
    names = sorted({str(a).strip() for a in projects if str(a).strip()})
    if mode != "all" and not names:
        raise ValueError(f"`{mode}` needs at least one project name")
    keys = policy.setdefault("keys", {})
    entry = keys.setdefault(str(key), {})
    entry["projects"] = "all" if mode == "all" else {mode: names}
    return project_for(key, policy)


def projects_seen(policy: Mapping[str, Any]) -> list[str]:
    """Every project name any key mentions, so a picker has something to show."""
    names: set[str] = set()
    for entry in (policy.get("keys") or {}).values():
        raw = entry.get("projects") if isinstance(entry, dict) else None
        if isinstance(raw, dict):
            for listed in raw.values():
                if isinstance(listed, list):
                    names.update(str(a).strip() for a in listed if str(a).strip())
        elif isinstance(raw, list):
            names.update(str(a).strip() for a in raw if str(a).strip())
        elif isinstance(raw, str) and raw.strip().lower() not in {"", "all", "*"}:
            names.add(raw.strip())
    return sorted(names)


def set_audience(key: str, mode: str, agents: Iterable[str], policy: MutableMapping[str, Any]) -> dict[str, Any]:
    """Set a key's audience in place. Returns the normalised rule."""
    mode = str(mode).strip().lower()
    if mode not in AUDIENCE_MODES:
        raise ValueError(f"audience must be one of {', '.join(AUDIENCE_MODES)}")
    names = sorted({str(a).strip() for a in agents if str(a).strip()})
    if mode != "all" and not names:
        raise ValueError(f"`{mode}` needs at least one agent name")
    keys = policy.setdefault("keys", {})
    entry = keys.setdefault(str(key), {})
    entry["agents"] = "all" if mode == "all" else {mode: names}
    return audience_for(key, policy)


# ── time windows ───────────────────────────────────────────────────────────


def within_window(rule: Mapping[str, Any], moment: datetime | None = None) -> bool:
    """Is now inside this rule's schedule?

    Local time, because a person setting "office hours" means the hours on the
    clock in front of them. A window with no bounds is open, not shut — the
    failure mode of an unparseable schedule should be a working machine.
    """
    window = rule.get("window")
    if not isinstance(window, dict):
        return True
    local = (moment or _now()).astimezone()

    days = window.get("days")
    if isinstance(days, (list, tuple)) and days:
        if DAYS[local.weekday()] not in {str(day).strip().lower()[:3] for day in days}:
            return False

    start, end = _clock_bound(window.get("from")), _clock_bound(window.get("to"))
    if start is None or end is None:
        return True
    current = local.time().replace(second=0, microsecond=0)
    if start <= end:
        return start <= current <= end
    # An overnight window such as 22:00–06:00 wraps midnight.
    return current >= start or current <= end


def _clock_bound(text: Any) -> clock | None:
    match = _CLOCK.match(str(text or ""))
    if not match:
        return None
    return clock(int(match.group(1)), int(match.group(2)))


def describe_window(rule: Mapping[str, Any]) -> str:
    window = rule.get("window")
    if not isinstance(window, dict):
        return "any time"
    days = window.get("days") or []
    when = f"{window.get('from', '00:00')}–{window.get('to', '23:59')}"
    return f"{', '.join(days)} {when}".strip() if days else when


# ── unlocks ────────────────────────────────────────────────────────────────


def _read_sessions(root: Path | None = None) -> list[dict[str, Any]]:
    try:
        loaded = json.loads(sessions_path(root).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    found = loaded.get("sessions") if isinstance(loaded, dict) else loaded
    return [item for item in found if isinstance(item, dict)] if isinstance(found, list) else []


def sessions(*, root: Path | None = None, include_expired: bool = False) -> list[dict[str, Any]]:
    """Unlocks, newest last, expiry evaluated now rather than on a timer.

    Checking on read is what makes a slept laptop or a changed clock safe: there
    is no countdown to miss, only a timestamp that either has passed or has not.
    """
    now = _now()
    out = []
    for item in _read_sessions(root):
        try:
            expires = _parse_stamp(item["expires"])
        except (KeyError, ValueError):
            continue
        remaining = int((expires - now).total_seconds())
        if remaining <= 0 and not include_expired:
            continue
        out.append({**item, "remaining_seconds": max(0, remaining), "active": remaining > 0})
    return out


def open_session(
    *,
    duration: str | int,
    keys: Iterable[str] = (),
    app: str = "",
    reason: str = "",
    approved_by: str = "owner",
    root: Path | None = None,
) -> dict[str, Any]:
    """Hold the door open for a stated period. Returns the unlock, no values.

    Naming keys or an app narrows it; naming neither covers everything, which is
    the "open full access for an hour" case and is recorded as exactly that so
    it is legible later rather than looking like ordinary use.
    """
    seconds = duration if isinstance(duration, int) else parse_duration(duration)
    if isinstance(duration, int) and not 0 < seconds <= MAX_SESSION_SECONDS:
        raise ValueError("An unlock cannot last longer than 7 days")
    started = _now()
    record = {
        "id": secrets.token_hex(6),
        "started": _stamp(started),
        "expires": _stamp(started + timedelta(seconds=seconds)),
        "duration_seconds": seconds,
        "keys": sorted({str(key).strip() for key in keys if str(key).strip()}),
        "app": str(app).strip(),
        "reason": str(reason)[:200],
        "approved_by": str(approved_by)[:64],
    }
    live = [item for item in _read_sessions(root)
            if _safe_future(item.get("expires"), started)]
    _write_private(sessions_path(root), {"version": POLICY_VERSION, "sessions": [*live, record]})
    return {**record, "remaining_seconds": seconds, "active": True}


def _safe_future(stamp: Any, now: datetime) -> bool:
    try:
        return _parse_stamp(stamp) > now
    except (TypeError, ValueError):
        return False


def close_session(session_id: str = "", *, root: Path | None = None) -> dict[str, Any]:
    """End one unlock, or every unlock when given no id."""
    target = str(session_id).strip()
    now = _now()
    live = [item for item in _read_sessions(root) if _safe_future(item.get("expires"), now)]
    kept = [item for item in live if target and item.get("id") != target]
    closed = len(live) - len(kept)
    _write_private(sessions_path(root), {"version": POLICY_VERSION, "sessions": kept})
    return {"ok": closed > 0, "closed": closed, "remaining": len(kept)}


def session_covers(app: str, key: str, *, root: Path | None = None) -> dict[str, Any] | None:
    """The unlock that covers this key for this app, if any is open."""
    for item in sessions(root=root):
        if item.get("app") and item["app"] != str(app):
            continue
        named = item.get("keys") or []
        if named and str(key) not in named:
            continue
        return item
    return None


# ── the decision ───────────────────────────────────────────────────────────


def ask_timeout(rule: Mapping[str, Any], fallback: float = 60.0) -> float:
    """How long THIS key waits for a person, in seconds.

    Sixty seconds is right for someone at the keyboard and wrong for an agent
    running at three in the morning — so the answer belongs to the key, not to
    the product. A rule may say `{"mode": "ask", "timeout": "10s"}`; a key an
    unattended job uses should fail fast rather than hang, and one a person
    reaches for should wait long enough that stepping away is survivable.
    """
    given = rule.get("timeout")
    if given in (None, ""):
        return fallback
    try:
        return float(parse_duration(str(given)))
    except (ValueError, TypeError):
        return fallback


def requires_passkey(rule: Mapping[str, Any]) -> bool:
    """Whether releasing this key needs the passkey, when one is enrolled.

    Default true, deliberately. If it were opt-in nobody would turn it on, and a
    passkey that guards the session but not the release of a credential is
    decoration. The repetition people fear is absorbed by unlocks — approve once
    with the passkey, hold it open for an hour — rather than by weakening the
    default. A rule may still say `{"require_passkey": false}` where the friction
    genuinely is not worth it.
    """
    value = rule.get("require_passkey")
    return True if value is None else bool(value)


def decide_key(app: str, key: str, policy: Mapping[str, Any], *, root: Path | None = None,
               workspace: str | None = None, project: str | None = None) -> dict[str, Any]:
    """What to do about one key, right now: grant, refuse, or ask.

    Returns an outcome and the reason for it, because "denied" with no cause is
    the thing that makes people disable a policy rather than fix it.
    """
    # Scope first: a key that does not reach this workspace is not this
    # workspace's to read, whatever its audience or mode says.
    if workspace is None:
        try:
            import passbook

            workspace = passbook.workspace()
        except Exception:  # noqa: BLE001 — no workspace configured is the common case
            workspace = ""
    reach = scope_allows(workspace, key, policy)
    if not reach["allowed"]:
        return {"outcome": "refuse", "mode": "never", "why": reach["why"], "scope": True}

    # Then the project, for the same reason and in the same way: a key that is
    # not this project's is not this project's whoever is asking for it.
    if project is None:
        try:
            import passbook

            project = passbook.project()
        except Exception:  # noqa: BLE001 — no project is the common case
            project = ""
    belongs = project_allows(project, key, policy)
    if not belongs["allowed"]:
        return {"outcome": "refuse", "mode": "never", "why": belongs["why"], "project": True}

    # The audience is a bound, not a preference: if this key is not for this
    # agent, no mode and no unlock can produce a grant.
    audience = audience_allows(app, key, policy)
    if not audience["allowed"]:
        return {"outcome": "refuse", "mode": "never", "why": audience["why"], "audience": True}

    rule = mode_for(app, key, policy)
    mode = rule.get("mode", DEFAULT_MODE)

    if mode == "always":
        return {"outcome": "grant", "mode": mode, "why": "always allowed"}
    if mode == "never":
        return {"outcome": "refuse", "mode": mode, "why": "never allowed for this app"}

    unlock = session_covers(app, key, root=root)
    if unlock:
        return {"outcome": "grant", "mode": mode, "why": f"unlocked for {describe_duration(unlock['remaining_seconds'])} more",
                "session": unlock["id"]}

    if mode == "window":
        if within_window(rule):
            return {"outcome": "grant", "mode": mode, "why": f"inside {describe_window(rule)}"}
        return {"outcome": "refuse", "mode": mode, "why": f"outside {describe_window(rule)}"}

    return {"outcome": "ask", "mode": mode, "why": "needs approval",
            "timeout": ask_timeout(rule), "require_passkey": requires_passkey(rule)}

# ── approved agents ────────────────────────────────────────────────────────
#
# `always` for everything is the setting people actually run, because `ask` for
# everything asks forty times a day and gets switched off within a week. The
# useful middle is neither: a default of `ask` with a named set of agents that
# do not have to. An automation that runs at 3am keeps working; a coding agent
# that has never asked for anything before has to check in.
#
# This is ORGANISATION, not authentication, and the difference has to stay
# visible or somebody will lean on it. The name a caller gives is a claim — the
# same claim `caller()` documents — so an unapproved agent can call itself an
# approved one. What the list buys is real and worth having: an accident is
# contained, an unfamiliar caller is visible, and the blast radius of a tool
# nobody meant to grant is one prompt instead of the whole store. What it does
# not buy is a boundary against something choosing to lie.


def approved_agents(policy: Mapping[str, Any]) -> list[str]:
    """Apps with an explicit `always`, ignoring the machine-wide default.

    An app's mode lives at `apps[name]["default"]["mode"]`, which is where
    `mode_for` looks and where `passbook policy --app` writes it. The first
    version of this read `apps[name]["mode"]` — one level up, a place nothing
    consults — so approving an agent wrote a key the decision point ignored and
    the whole list was decoration. It looked right in a live test only because
    an earlier `passbook policy` call had written the real one.
    """
    apps = policy.get("apps")
    if not isinstance(apps, Mapping):
        return []
    found = []
    for name, entry in apps.items():
        if name == "*" or not isinstance(entry, Mapping):
            continue
        rule = entry.get("default")
        if isinstance(rule, Mapping) and str(rule.get("mode", "")).lower() == "always":
            found.append(str(name))
    return sorted(found)


def approve_agent(name: str, policy: MutableMapping[str, Any]) -> dict[str, Any]:
    """Let this agent through without asking."""
    who = str(name).strip()
    if not who or who == "*":
        raise ValueError("name an agent; '*' is the default, not an agent")
    apps = policy.setdefault("apps", {})
    entry = apps.setdefault(who, {})
    entry["default"] = {"mode": "always"}
    return entry


def unapprove_agent(name: str, policy: MutableMapping[str, Any]) -> bool:
    """Drop the override so this agent falls back to the default.

    The rule is removed rather than set to `ask`, so that changing the default
    later moves this agent with it. An agent pinned to `ask` would sit there
    asking on a machine somebody had deliberately opened up, and nobody would
    remember why.

    Per-key rules the owner set separately are left alone: this undoes an
    approval, and quietly discarding unrelated policy would be a different and
    much less welcome operation.
    """
    who = str(name).strip()
    apps = policy.get("apps")
    if not isinstance(apps, MutableMapping) or who not in apps:
        return False
    entry = apps[who]
    if not isinstance(entry, MutableMapping) or "default" not in entry:
        return False
    entry.pop("default")
    if not entry:
        apps.pop(who)
    return True


def default_mode(policy: Mapping[str, Any]) -> str:
    """What an agent with no rule of its own gets.

    Reads the `*` app entry first, because that is where `mode_for` looks before
    it falls back to the machine default.
    """
    apps = policy.get("apps")
    if isinstance(apps, Mapping):
        entry = apps.get("*")
        if isinstance(entry, Mapping):
            rule = entry.get("default")
            if isinstance(rule, Mapping) and rule.get("mode") in GRANT_MODES:
                return str(rule["mode"])
    fallback = policy.get("default")
    if isinstance(fallback, Mapping) and fallback.get("mode") in GRANT_MODES:
        return str(fallback["mode"])
    return DEFAULT_MODE


def set_default_mode(mode: str, policy: MutableMapping[str, Any]) -> str:
    """Set what unapproved agents get. Written where `mode_for` reads it."""
    wanted = str(mode).strip().lower()
    if wanted not in GRANT_MODES:
        raise ValueError(f"mode must be one of {', '.join(sorted(GRANT_MODES))}")
    apps = policy.setdefault("apps", {})
    entry = apps.setdefault("*", {})
    entry["default"] = {"mode": wanted}
    return wanted


def known_agents(policy: Mapping[str, Any], *, seen: Iterable[str] = (),
                 installed: Iterable[Mapping[str, Any]] = (),
                 peers: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Every agent this machine can name, and what each one gets.

    Three sources, because each knows something the others do not. `installed`
    is which agent runtimes are on the disk — the ones that could ask tomorrow.
    `seen` is which names have actually asked, from the ledger, which is the
    only one that reflects reality rather than intent. `peers` is other machines
    in the fleet, where a name means somebody else's agent may reach this store.

    Kept pure so the sources can be gathered by whoever has them, and so this
    works identically on a machine with no fleet and no runtimes installed.
    """
    approved = set(approved_agents(policy))
    default = default_mode(policy)
    where: dict[str, set[str]] = {}

    for entry in installed:
        name = str(entry.get("id") or "").strip()
        if name:
            where.setdefault(name, set()).add("installed")
    for name in seen:
        name = str(name).strip()
        if name:
            where.setdefault(name, set()).add("has asked")
    for name in peers:
        name = str(name).strip()
        if name:
            where.setdefault(name, set()).add("fleet")
    for name in approved:
        where.setdefault(name, set()).add("approved")

    return [
        {
            "name": name,
            "approved": name in approved,
            "mode": "always" if name in approved else default,
            "where": sorted(places),
        }
        for name, places in sorted(where.items())
    ]
