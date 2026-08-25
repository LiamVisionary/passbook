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
from typing import Any, Iterable, Mapping

import passbook

__all__ = [
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
POLICY_VERSION = 2

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
        return {"version": POLICY_VERSION, "default": {"mode": DEFAULT_MODE}, "apps": {}}

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
        }

    return {
        "version": POLICY_VERSION,
        "default": loaded.get("default") if isinstance(loaded.get("default"), dict) else {"mode": DEFAULT_MODE},
        "apps": loaded.get("apps") if isinstance(loaded.get("apps"), dict) else {},
    }


def read_policy(root: Path | None = None) -> dict[str, Any]:
    """The policy, or a permissive default. A broken policy never refuses.

    A parse error that silently denied everything would take the machine down
    and look like a credential fault the whole time.
    """
    try:
        return upgrade_policy(json.loads(policy_path(root).read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {"version": POLICY_VERSION, "default": {"mode": DEFAULT_MODE}, "apps": {}}


def write_policy(policy: Mapping[str, Any], root: Path | None = None) -> Path:
    return _write_private(policy_path(root), {
        "version": POLICY_VERSION,
        "default": policy.get("default") or {"mode": DEFAULT_MODE},
        "apps": policy.get("apps") or {},
    })


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


def decide_key(app: str, key: str, policy: Mapping[str, Any], *, root: Path | None = None) -> dict[str, Any]:
    """What to do about one key, right now: grant, refuse, or ask.

    Returns an outcome and the reason for it, because "denied" with no cause is
    the thing that makes people disable a policy rather than fix it.
    """
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
