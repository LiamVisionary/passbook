# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Which provider account each key belongs to: the sign-in email, how that account signs in, and its name.

Liam, 2026-11-24, during a key rotation: signing in to the wrong account cost time twice. DeepInfra's key
belongs to an account that signs in with GitHub, so a Google sign-in with the same address made an empty new
account; DashScope's key belongs to an Alibaba Cloud account that signs in with Google under another address,
and the first address made another empty one. "Keep track of email accounts, as automatically as possible,
with fallback to optionally entering it on your own."

So beside each key PassBook keeps who owns it:

- **Found** where the provider will say. A provider whose API reports the owner to the key itself (DeepInfra's
  `/v1/me`, Vultr's `/v2/account`, ...) is asked by `passbook account lookup`, through the same path `passbook
  run` and `passbook balances` open keys by, and again whenever `balances` or `rotate` already holds the key.
  The catalog of who can be asked is `passbook_balances.OWNERS`, beside the balance readers.
- **Entered** where it will not (DashScope, Groq, DeepSeek...): `passbook account set KEY --email ... --via
  google`, the key's page in the window, or an agent through the MCP server's `record_account`.

Each field remembers where it came from, so a lookup that learns the email never wipes the sign-in method
somebody typed (almost no API reports that), and an entry outlives a rotation because it is kept by key name.
A found entry also keeps an opaque fingerprint of the key it was read with, so a replaced key is asked again.

An email is personal data. The record is a file beside the store, readable by its owner only, on this
machine only: it is not a store key, so sync never carries it, and it is never part of a URL, a log line, a
receipt or anything a provider or an alert is sent. A lookup sends a provider nothing but the key, to the
provider's own canonical address, and keeps only the fields named here, never the answer itself (some of those
answers echo the key).
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

FILE = "accounts.json"
VERSION = 1

#: How an account signs in. The ids are what `--via` takes; the words are what a person reads.
VIA = {
    "google": "Google",
    "github": "GitHub",
    "microsoft": "Microsoft",
    "apple": "Apple",
    "gitlab": "GitLab",
    "password": "email and password",
    "email-link": "a link sent by email",
    "sso": "single sign-on",
    "other": "another way",
}
#: The fields of an entry. `account` is the account, organization or team name where the provider has one.
FIELDS = ("email", "via", "account", "note")
BY_HAND = "by hand"

EMAIL = re.compile(r"^[^@\s\x00-\x1f\x7f]{1,64}@[^@\s\x00-\x1f\x7f]{1,190}\.[^@\s\x00-\x1f\x7f.]{2,63}$")
LINE = re.compile(r"^[^\x00-\x1f\x7f]{1,200}$")
KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class AccountError(ValueError):
    """Something about an entry is wrong. The message is for a person."""


# ── the record ──────────────────────────────────────────────────────────────


def path(root: Path | None = None) -> Path:
    if root is None:
        import passbook

        root = passbook.root()
    return Path(root) / FILE


def read(root: Path | None = None) -> dict[str, dict]:
    """Every key's entry, by key name. A missing or damaged file reads as no entries."""
    try:
        data = json.loads(path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    accounts = data.get("accounts") if isinstance(data, dict) else None
    if not isinstance(accounts, dict):
        return {}
    return {name: _clean(entry) for name, entry in accounts.items()
            if isinstance(name, str) and KEY.match(name) and isinstance(entry, dict) and _clean(entry)}


def _clean(entry: Mapping[str, Any]) -> dict:
    kept = {field: entry[field] for field in FIELDS if isinstance(entry.get(field), str) and entry[field]}
    if not kept:
        return {}
    sources = entry.get("from") if isinstance(entry.get("from"), dict) else {}
    kept["from"] = {field: str(sources.get(field) or BY_HAND) for field in FIELDS if field in kept}
    for extra in ("updatedAt", "found"):
        if entry.get(extra):
            kept[extra] = entry[extra]
    return kept


def write(records: Mapping[str, Mapping[str, Any]], root: Path | None = None) -> None:
    """Owner-only, replaced in one step, so a reader never sees half a file."""
    target = path(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    clean = {name: _clean(entry) for name, entry in sorted(records.items()) if _clean(entry)}
    temporary = target.with_suffix(".tmp")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump({"version": VERSION, "accounts": clean}, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, target)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


def get(key: str, root: Path | None = None) -> dict | None:
    return read(root).get(key)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _via(value: str) -> str:
    word = str(value or "").strip().lower().replace("_", "-").replace(" ", "-")
    aliases = {"gh": "github", "google-account": "google", "email": "password", "email-and-password": "password",
               "magic-link": "email-link", "saml": "sso", "okta": "sso"}
    word = aliases.get(word, word)
    if word not in VIA:
        raise AccountError(f"Sign-in method {value!r} is not one PassBook knows. Use one of: {', '.join(VIA)}.")
    return word


def validate(field: str, value: str) -> str:
    """The value as kept, or AccountError. An empty value means "clear this field"."""
    value = str(value or "").strip()
    if not value:
        return ""
    if field == "email":
        value = value.lower() if value.count("@") == 1 else value
        if not EMAIL.match(value):
            raise AccountError(f"{value!r} does not look like an email address.")
        return value
    if field == "via":
        return _via(value)
    if not LINE.match(value):
        raise AccountError(f"The {field} is one line of at most 200 characters.")
    return value


def set_fields(key: str, fields: Mapping[str, str | None], *, source: str = BY_HAND,
               root: Path | None = None) -> dict:
    """Change some fields of KEY's entry and keep the rest. None leaves a field; "" clears it.

    Returns the entry as kept (empty when every field is now clear, which removes it)."""
    if not KEY.match(str(key or "")):
        raise AccountError(f"{key!r} is not a key name.")
    unknown = set(fields) - set(FIELDS)
    if unknown:
        raise AccountError(f"Unknown field: {', '.join(sorted(unknown))}.")
    checked = {field: validate(field, value) for field, value in fields.items() if value is not None}
    if not checked:
        raise AccountError("Say what to keep: --email, --via, --account or --note.")
    records = read(root)
    entry = dict(records.get(key) or {})
    sources = dict(entry.get("from") or {})
    for field, value in checked.items():
        if value:
            entry[field], sources[field] = value, source
        else:
            entry.pop(field, None)
            sources.pop(field, None)
    entry["from"], entry["updatedAt"] = sources, _now()
    if _clean(entry):
        records[key] = entry
    else:
        records.pop(key, None)
    write(records, root)
    return _clean(entry)


def forget(key: str, root: Path | None = None) -> bool:
    records = read(root)
    if key not in records:
        return False
    records.pop(key)
    write(records, root)
    return True


def rename(old: str, new: str, root: Path | None = None) -> None:
    """Carry an entry to a key's new name, when a key is renamed."""
    records = read(root)
    if old in records and new not in records and KEY.match(new):
        records[new] = records.pop(old)
        write(records, root)


# ── saying it ───────────────────────────────────────────────────────────────


def describe(entry: Mapping[str, Any] | None) -> str:
    """One line: "you@example.com, signs in with Google · Alibaba Cloud international · Singapore region"."""
    if not entry:
        return ""
    first = entry.get("email") or ""
    if entry.get("via"):
        how = f"signs in with {VIA.get(entry['via'], entry['via'])}"
        first = f"{first}, {how}" if first else how[:1].upper() + how[1:]
    parts = [part for part in (first, entry.get("account"), entry.get("note")) if part]
    return " · ".join(parts)


def sources(entry: Mapping[str, Any] | None) -> str:
    """Where the entry came from, said once: "found by DeepInfra's API", "entered by hand", or both."""
    if not entry:
        return ""
    said = list(dict.fromkeys((entry.get("from") or {}).values()))
    words = [("entered by hand" if item == BY_HAND else f"found by {item}" if item.endswith("'s API")
              else f"recorded by {item.removeprefix('mcp:')}") for item in said]
    return "; ".join(words)


def public(entry: Mapping[str, Any] | None) -> dict | None:
    """What a surface shows: the fields, where each came from, a line, and when it was last confirmed."""
    if not entry:
        return None
    found = entry.get("found") if isinstance(entry.get("found"), dict) else {}
    return {**{field: entry.get(field) for field in FIELDS if entry.get(field)},
            "viaLabel": VIA.get(entry.get("via") or "", None) if entry.get("via") else None,
            "from": dict(entry.get("from") or {}), "line": describe(entry), "said": sources(entry),
            "updatedAt": entry.get("updatedAt"), "foundAt": found.get("at"), "foundBy": found.get("provider")}


# ── asking the provider ─────────────────────────────────────────────────────


def apply_found(key: str, found: Mapping[str, Any], *, provider: str, label: str, mark: str,
                root: Path | None = None) -> tuple[dict, list[str]]:
    """Keep what a provider said about KEY's owner. Returns the entry, and the fields it CHANGED from an
    earlier, different value (a key that moved to another account, or a typo entered by hand)."""
    records = read(root)
    entry = dict(records.get(key) or {})
    sources = dict(entry.get("from") or {})
    changed = []
    for field in ("email", "via", "account"):
        value = found.get(field)
        try:
            value = validate(field, value) if value else ""
        except AccountError:
            value = ""
        if not value:
            continue
        if entry.get(field) and entry[field] != value:
            changed.append(field)
        entry[field], sources[field] = value, label
    entry["from"] = sources
    entry["found"] = {"provider": provider, "fingerprint": mark, "at": _now()}
    entry["updatedAt"] = _now()
    records[key] = entry
    write(records, root)
    return _clean(entry), changed


def lookup(values: Mapping[str, str], names: Iterable[str], *, root: Path | None = None, fresh: bool = False,
           fetch: Callable[[str, str], tuple[int, Any]] | None = None) -> list[dict]:
    """Ask each key's provider who owns it, for the keys whose provider will say.

    `values` are the opened keys (as `passbook balances` opens them). A key already asked with this very value
    is not asked again unless `fresh`. Each result is {"key", "provider", "status", "account", "changed"}:
    status is found, kept (asked before with this value), no-api, locked, rejected, not-allowed, error or
    unsaid."""
    import passbook_balances as balances

    if root is None:
        import passbook

        root = passbook.root()
    fetch = fetch or balances.fetch_owner
    salt = balances.salt_for(root)
    results = []
    for name in dict.fromkeys(names):
        entry = balances.owner_provider(name)
        result: dict[str, Any] = {"key": name, "provider": (entry or {}).get("id"), "providerName": (entry or {}).get("name"),
                                  "status": "no-api", "account": None, "changed": []}
        results.append(result)
        if not entry:
            result["account"] = get(name, root)
            continue
        value = str(values.get(name) or "")
        if not value or value.startswith("hive-sealed:"):
            result["status"], result["account"] = "locked", get(name, root)
            continue
        mark = balances.fingerprint(salt, f"{entry['id']}#owner", value)
        kept = get(name, root)
        if not fresh and kept and (kept.get("found") or {}).get("fingerprint") == mark:
            result["status"], result["account"] = "kept", kept
            continue
        try:
            status, payload = fetch(entry["owner"], value)
        except Exception:  # noqa: BLE001 — offline, a timeout, a refused redirect: nothing is assumed
            result["status"], result["account"] = "error", kept
            continue
        if status in (401, 403):
            # 401: the key itself was refused. 403: the key works but may not read who owns it (a Cloudflare
            # token without User Details, a fal key without billing read): nothing is wrong with the key.
            result["status"], result["account"] = ("rejected" if status == 401 else "not-allowed"), kept
            result["httpStatus"] = status
            continue
        found = balances.parse_owner(entry["owner"], payload) if status == 200 else None
        if not found:
            result["status"], result["account"] = ("unsaid" if status == 200 else "error"), kept
            if status != 200:
                result["httpStatus"] = status
            continue
        account, changed = apply_found(name, found, provider=entry["id"], label=f"{entry['name']}'s API",
                                       mark=mark, root=root)
        result.update(status="found", account=account, changed=changed)
    return results


def wanted(held: Iterable[str], *, only: Iterable[str] = ()) -> list[str]:
    """The held keys a lookup would open: the ones named, else every one whose provider says who owns it."""
    import passbook_balances as balances

    held = list(held)
    asked = [name for name in only if name]
    if asked:
        return [name for name in dict.fromkeys(asked) if name in set(held)]
    return [name for name in held if balances.owner_provider(name)]


def summary(names: Iterable[str], root: Path | None = None, records: Mapping[str, dict] | None = None) -> dict | None:
    """The account of the first of these keys that has one: what a balance row, one account of several
    keys, shows."""
    records = read(root) if records is None else records
    for name in names:
        if records.get(name):
            return {**(public(records[name]) or {}), "key": name}
    return None


def since(entry: Mapping[str, Any] | None) -> float | None:
    """Seconds since the entry was last confirmed by its provider, or None when it never was."""
    found = (entry or {}).get("found") or {}
    try:
        return time.time() - datetime.fromisoformat(str(found.get("at")).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None
