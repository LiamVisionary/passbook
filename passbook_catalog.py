# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Making a large store legible: groups, and who gets what.

Optional companion to `passbook_access.py`. Nothing here decides anything — it
reads the same policy and answers the questions a person asks when they are
looking at a store rather than configuring one app:

  * what is in here, arranged so I can read it
  * which agents can see this key
  * which keys can this agent see

## Why groups are inferred rather than demanded

A real store has a few hundred keys, and any scheme that requires tagging each
one by hand is a scheme that never gets finished — so the store stays a flat
list forever and nobody ever looks at it.

So a group is *derived* from the key's own name by default, and only overridden
when someone disagrees. `OPENAI_API_KEY`, `OPENAI_ORG_ID` and `OPENAI_BASE_URL`
are already telling you they belong together; the naming convention people
already follow is the organisation, and this just reads it.

An explicit group always wins, because the inference is a convenience and not a
claim to be right.

## The matrix

`matrix()` is the view that makes an audience decision reviewable: every key
against every agent that has ever asked for one, with the outcome and the reason
in each cell. It is the difference between "I set some policies" and "I can see
that the trading key is visible to four agents, two of which I forgot about".
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping

import passbook_access as access

__all__ = [
    "UNGROUPED",
    "agents_seen",
    "group_of",
    "groups",
    "infer_group",
    "matrix",
    "organise",
    "set_group",
    "suggest_groups",
]

UNGROUPED = "Ungrouped"

# Suffixes that describe what a value *is* rather than what it belongs to.
# Stripping them turns OPENAI_API_KEY and OPENAI_BASE_URL into one family
# instead of two.
_ROLE_SUFFIXES = (
    "API_KEY", "SECRET_KEY", "ACCESS_KEY", "PRIVATE_KEY", "PUBLIC_KEY",
    "CLIENT_SECRET", "CLIENT_ID", "ACCOUNT_ID", "PROJECT_ID", "ZONE_ID",
    "BASE_URL", "ENDPOINT", "WEBHOOK_URL", "REFRESH_TOKEN", "ACCESS_TOKEN",
    "API_TOKEN", "AUTH_TOKEN", "PASSWORD", "USERNAME", "TOKEN", "SECRET",
    "KEY", "URL", "HOST", "PORT", "REGION", "MODEL", "ID",
)

# Prefixes that say how a value is *delivered* rather than whose it is.
_NOISE_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_",
                   "EXPO_PUBLIC_", "GATSBY_", "NUXT_PUBLIC_", "HIVE_", "HIVEMINDOS_")


def infer_group(name: str) -> str:
    """The family a key name is already announcing it belongs to.

    Never guesses beyond the name: a key with nothing to strip is its own
    family, which reads better than forcing it into a bucket it does not fit.
    """
    text = str(name).strip().upper()
    if not text:
        return UNGROUPED
    for prefix in _NOISE_PREFIXES:
        if text.startswith(prefix) and len(text) > len(prefix):
            text = text[len(prefix):]
            break
    for suffix in _ROLE_SUFFIXES:
        if text.endswith("_" + suffix) and len(text) > len(suffix) + 1:
            return text[: -(len(suffix) + 1)].strip("_").title().replace("_", " ") or UNGROUPED
    head = re.split(r"_", text)[0]
    return head.title() if head else UNGROUPED


def group_of(name: str, policy: Mapping[str, Any]) -> str:
    """A key's group: what someone set, else what its name implies."""
    explicit = access.key_entry(name, policy).get("group")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    return infer_group(name)


def set_group(name: str, group: str, policy: MutableMapping[str, Any]) -> str:
    """Pin a key to a group, in place. An empty group returns it to inference."""
    keys = policy.setdefault("keys", {})
    entry = keys.setdefault(str(name), {})
    label = str(group).strip()
    if label:
        entry["group"] = label
    else:
        entry.pop("group", None)
    return group_of(name, policy)


def groups(names: Iterable[str], policy: Mapping[str, Any], *, minimum: int = 2) -> dict[str, list[str]]:
    """Every key, arranged. Group names sorted, `Ungrouped` last.

    A group of one is not a group. Inferring per-key families over a real store
    produced 179 groups for 279 keys — four fifths of them singletons — which is
    a flat list wearing a costume. So an *inferred* family only becomes a group
    once `minimum` keys share it, and the leftovers collect under `Ungrouped`
    where they are honestly one undifferentiated pile.

    A group somebody set by hand is always kept, however few keys are in it:
    they said so, and the point of an override is that it overrides.
    """
    pinned: dict[str, list[str]] = {}
    guessed: dict[str, list[str]] = {}
    for name in names:
        explicit = access.key_entry(name, policy).get("group")
        target = pinned if isinstance(explicit, str) and explicit.strip() else guessed
        target.setdefault(group_of(name, policy), []).append(str(name))

    out: dict[str, list[str]] = {group: list(members) for group, members in pinned.items()}
    for group, members in guessed.items():
        destination = group if len(members) >= minimum or group in out else UNGROUPED
        out.setdefault(destination, []).extend(members)

    for members in out.values():
        members.sort()
    ordered = sorted(out, key=lambda g: (g == UNGROUPED, g.lower()))
    return {group: out[group] for group in ordered}


def suggest_groups(names: Iterable[str], *, minimum: int = 2) -> dict[str, list[str]]:
    """Groups worth creating, from names alone. Singletons are not worth it."""
    inferred: dict[str, list[str]] = {}
    for name in names:
        inferred.setdefault(infer_group(name), []).append(str(name))
    counts = Counter({group: len(members) for group, members in inferred.items()})
    return {group: sorted(inferred[group]) for group, count in counts.most_common()
            if count >= minimum and group != UNGROUPED}


def agents_seen(*, root: Path | None = None, policy: Mapping[str, Any] | None = None) -> list[str]:
    """Every agent this machine knows about — configured, or seen asking.

    Reading the ledger matters as much as reading the policy: the agents worth
    reviewing are usually the ones nobody configured, which is exactly why they
    are absent from the policy and present in the record.
    """
    found: set[str] = set()
    policy = access.read_policy(root) if policy is None else policy
    for app in (policy.get("apps") or {}):
        if str(app) not in {"", "*"}:
            found.add(str(app))
    for key_rule in (policy.get("keys") or {}).values():
        if isinstance(key_rule, dict):
            rule = key_rule.get("agents")
            if isinstance(rule, dict):
                for listed in rule.values():
                    if isinstance(listed, list):
                        found.update(str(a) for a in listed if str(a).strip())
    try:
        import passbook_stamp

        for row in passbook_stamp.read_stamps(limit=2000, root=root):
            app = str(row.get("app") or "").strip()
            if app and app != "unknown":
                found.add(app)
    except Exception:  # noqa: BLE001 — no ledger yet is not an error
        pass
    return sorted(found)


def matrix(
    names: Iterable[str],
    agents: Iterable[str],
    policy: Mapping[str, Any],
    *,
    root: Path | None = None,
) -> dict[str, Any]:
    """Every key against every agent, with the outcome and why.

    Values never appear here, and the reason travels with the outcome, because
    a grid of green and red with no explanation is a grid people stop reading.
    """
    keys = sorted({str(n) for n in names})
    who = sorted({str(a) for a in agents if str(a).strip()})
    rows = []
    for key in keys:
        audience = access.audience_for(key, policy)
        cells = {}
        for agent in who:
            verdict = access.decide_key(agent, key, policy, root=root)
            cells[agent] = {
                "outcome": verdict["outcome"],
                "why": verdict["why"],
                "by_audience": bool(verdict.get("audience")),
            }
        rows.append({
            "key": key,
            "group": group_of(key, policy),
            "audience": audience,
            "agents": cells,
            "granted_to": sorted(a for a, c in cells.items() if c["outcome"] == "grant"),
        })
    return {"agents": who, "keys": keys, "rows": rows,
            "groups": groups(keys, policy)}
