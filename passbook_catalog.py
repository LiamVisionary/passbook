# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Making a large store legible: groups, and who gets what.

Optional companion to `passbook_access.py`. Nothing here decides anything — it
reads the same policy and answers the questions a person asks when they are
looking at a store rather than configuring one app:

  * what is in here, arranged so I can read it
  * which apps can see this key
  * which keys can this app see

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

## Apps, not agents

The thing that asks for a credential is whatever declared a name: a background
daemon, a command line, a project's build, or an agent connected over MCP. The
ledger field is `app`, the policy section is `apps`, and this module's job is to
report them honestly.

The surfaces used to call the whole set "agents", which read as a claim about
what they were, and on a real machine four of the eight names were LaunchAgents
and CLIs. The internal identifiers below still say `agent` because the policy
rule that narrows a key is `audience`/`agents` in the on-disk schema and
renaming that would rewrite everyone's policy file; every string a person reads
says *app*. Keep it that way.

## The matrix

`matrix()` is the view that makes an audience decision reviewable: every key
against every app that has ever asked for one, with the outcome and the reason
in each cell. It is the difference between "I set some policies" and "I can see
that the trading key is visible to four apps, two of which I forgot about".
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping

import passbook_access as access

__all__ = [
    "UNGROUPED",
    "effective_groups",
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

# Words that describe what a value *is* rather than whose it is. A key whose
# first word is one of these is naming a role, not a vendor, so it has no family.
_ROLE_WORDS = frozenset({
    "API", "SECRET", "ACCESS", "PRIVATE", "PUBLIC", "CLIENT", "AUTH", "TOKEN",
    "KEY", "PASSWORD", "USERNAME", "URL", "HOST", "PORT", "REGION", "MODEL",
    "ID", "ENDPOINT", "WEBHOOK", "BASE", "DEFAULT", "ENABLE", "ENABLED", "DISABLE",
})

# Prefixes that say how a value is *delivered* rather than whose it is.
_NOISE_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_",
                   "EXPO_PUBLIC_", "GATSBY_", "NUXT_PUBLIC_", "HIVE_", "HIVEMINDOS_")


# How a vendor writes its own name.
#
# `title()` gets most of them right and a handful conspicuously wrong, and it
# is the wrong ones that end up on screen: "Openai", "Github", "Aws". A group
# heading is the largest text on a page of a few hundred keys, so it is worth
# the table. Anything absent still falls through to `title()`, which is right
# for the long tail.
_VENDOR_CASING = {
    "AWS": "AWS", "GCP": "GCP", "S3": "S3", "SQS": "SQS", "SNS": "SNS",
    "GITHUB": "GitHub", "GITLAB": "GitLab", "BITBUCKET": "Bitbucket",
    "OPENAI": "OpenAI", "XAI": "xAI", "HUGGINGFACE": "HuggingFace",
    "ELEVENLABS": "ElevenLabs", "RUNPOD": "RunPod", "POSTHOG": "PostHog",
    "SENDGRID": "SendGrid", "MAILGUN": "Mailgun", "PAGERDUTY": "PagerDuty",
    "DIGITALOCEAN": "DigitalOcean", "MONGODB": "MongoDB", "POSTGRESQL": "PostgreSQL",
    "MYSQL": "MySQL", "SQLITE": "SQLite", "DYNAMODB": "DynamoDB",
    "OAUTH": "OAuth", "SMTP": "SMTP", "IMAP": "IMAP", "JWT": "JWT",
    "NPM": "NPM", "PYPI": "PyPI", "MCP": "MCP", "LLM": "LLM", "AI": "AI",
    "IOS": "iOS", "MACOS": "macOS", "TLS": "TLS", "SSH": "SSH", "GPG": "GPG",
}


def infer_group(name: str) -> str:
    """The family a key name is already announcing it belongs to.

    The vendor is the first word, once any delivery prefix is off the front.
    Nothing cleverer: an earlier version stripped role suffixes too, so
    STRIPE_SECRET_KEY became "Stripe" while STRIPE_WEBHOOK_SECRET became
    "Stripe Webhook" and the two keys for one vendor landed in different groups.
    Splitting a family is a worse failure than a group being a little coarse,
    because a coarse group is still one place to look.
    """
    text = str(name).strip().upper()
    if not text:
        return UNGROUPED
    for prefix in _NOISE_PREFIXES:
        if text.startswith(prefix) and len(text) > len(prefix):
            text = text[len(prefix):]
            break
    head = text.split("_", 1)[0]
    # A name that is nothing but a role — API_KEY, TOKEN — names no family.
    if not head or head in _ROLE_WORDS:
        return UNGROUPED
    return _VENDOR_CASING.get(head, head.title())


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


def effective_groups(names: Iterable[str], policy: Mapping[str, Any], *, minimum: int = 2) -> dict[str, str]:
    """Key -> the group it is actually filed under. One answer, everywhere.

    `group_of` returns the family a name implies, which is not the same thing:
    a family of one collapses into `Ungrouped` when the store is arranged. Two
    surfaces asking different functions therefore disagreed — the key list filed
    ADMIN_TOKEN under Ungrouped while the access matrix tagged it "Admin".
    """
    filed: dict[str, str] = {}
    for group, members in groups(names, policy, minimum=minimum).items():
        for member in members:
            filed[member] = group
    return filed


def suggest_groups(names: Iterable[str], *, minimum: int = 2) -> dict[str, list[str]]:
    """Groups worth creating, from names alone. Singletons are not worth it."""
    inferred: dict[str, list[str]] = {}
    for name in names:
        inferred.setdefault(infer_group(name), []).append(str(name))
    counts = Counter({group: len(members) for group, members in inferred.items()})
    return {group: sorted(inferred[group]) for group, count in counts.most_common()
            if count >= minimum and group != UNGROUPED}


# PassBook's own commands, and the hive-env wrappers that are the same store
# under older names. They appear in the RECORD, because the record must show
# every read — but the Apps page is for deciding which apps may read which
# keys, and PassBook reading its own store is not a decision to make.
#
# `passbook-run` asking for a credential is you running PassBook. Offering to
# restrict it is offering to restrict yourself, and a picker full of your own
# tooling buries the four callers that a decision could sensibly be made about.
FIRST_PARTY_PREFIXES = ("passbook", "hive-env-")
FIRST_PARTY = frozenset({"passbook"})


def is_first_party(app: str) -> bool:
    name = str(app).strip().lower()
    return name in FIRST_PARTY or name.startswith(FIRST_PARTY_PREFIXES)


def agents_seen(*, root: Path | None = None, policy: Mapping[str, Any] | None = None,
                include_tooling: bool = False) -> list[str]:
    """Every app this machine knows about — configured, or seen asking.

    Reading the ledger matters as much as reading the policy: the apps worth
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
    if not include_tooling:
        # An app explicitly named in a policy stays visible whatever it is
        # called: somebody wrote that rule deliberately and hiding the subject
        # of it would make the rule unexplainable.
        configured = {str(a) for a in (policy.get("apps") or {})}
        for key_rule in (policy.get("keys") or {}).values():
            if isinstance(key_rule, dict) and isinstance(key_rule.get("agents"), dict):
                for listed in key_rule["agents"].values():
                    if isinstance(listed, list):
                        configured.update(str(a) for a in listed)
        found = {app for app in found
                 if not is_first_party(app) or app in configured}
    return sorted(found)


def agent_activity(*, root: Path | None = None, limit: int = 4000) -> dict[str, int]:
    """How many times each caller has asked, from the record.

    A name alone cannot be judged. `fleet-health-watchdog` at 468 asks and
    `probe` at 1 are both "something that asked this machine for a credential",
    and only one of them is a thing to make a decision about. Showing the count
    is better than guessing which names are noise and hiding them: the store's
    own history says which is which, and a one-off from a test still deserves
    to be seen rather than quietly filtered.
    """
    counts: Counter[str] = Counter()
    try:
        import passbook_stamp

        for row in passbook_stamp.read_stamps(limit=limit, root=root):
            app = str(row.get("app") or "").strip()
            if app and app != "unknown":
                counts[app] += 1
    except Exception:  # noqa: BLE001 — no ledger yet is not an error
        return {}
    return dict(counts)


def matrix(
    names: Iterable[str],
    agents: Iterable[str],
    policy: Mapping[str, Any],
    *,
    root: Path | None = None,
) -> dict[str, Any]:
    """Every key against every app, with the outcome and why.

    Values never appear here, and the reason travels with the outcome, because
    a grid of green and red with no explanation is a grid people stop reading.
    """
    keys = sorted({str(n) for n in names})
    who = sorted({str(a) for a in agents if str(a).strip()})
    filed = effective_groups(keys, policy)
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
            "group": filed.get(key, UNGROUPED),
            "audience": audience,
            "agents": cells,
            "granted_to": sorted(a for a, c in cells.items() if c["outcome"] == "grant"),
        })
    return {"agents": who, "keys": keys, "rows": rows,
            "groups": groups(keys, policy)}
