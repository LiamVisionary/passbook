# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Sign-ins, not just keys — OAuth grants that stay alive.

Optional companion to `passbook.py`. A store already holds things like

    OPENAI_OAUTH_ACCESS_TOKEN
    OPENAI_OAUTH_REFRESH_TOKEN
    OPENAI_OAUTH_EXPIRES_AT

and treats them as three unrelated strings. It cannot tell you the grant
expired, and it cannot do anything about it. So the access token an app reads
is dead an hour after somebody last opened the thing that refreshes it, and the
failure surfaces as a puzzling 401 somewhere else entirely.

This module makes a **grant** a thing PassBook understands: which keys hold it,
when it expires, and how to renew it. The broker then refreshes on read, which
is the whole point — the broker runs whether or not the app that created the
grant is running.

## What is and is not stored here

The grant's *description* lives in `passbook-oauth.json`: a label, the token
endpoint, the client id, which key names hold what. None of that is secret and
all of it is worth reading.

The **tokens live in the store**, under ordinary key names, so they are sealed,
policy-checked and recorded exactly like every other credential. There is no
second vault and no second set of rules.

## Providers are configuration

No vendor's client id ships in this file. Some CLIs authenticate with their own
registered client, and a grant that impersonates one is a matter between you and
that vendor's terms — not something a library should decide for you by baking it
in. `PROVIDERS` therefore holds only services where you register your own
client, and anything else is described when you add it.

## Refreshing is a `refresh_token` grant, and nothing more

Every provider here does the same thing: POST `grant_type=refresh_token` to a
token endpoint and get a new access token back. What varies is a URL, a client
id, a scope and four key names. That is a table, so this is a table.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

__all__ = [
    "GRANTS_FILENAME",
    "PROVIDERS",
    "GrantError",
    "NotConnected",
    "RefreshFailed",
    "add_grant",
    "authorize_url",
    "complete_login",
    "describe",
    "exchange_refresh",
    "grant_keys",
    "grants",
    "needs_refresh",
    "read_grants",
    "remove_grant",
    "status",
    "token_values",
]

GRANTS_FILENAME = "passbook-oauth.json"
GRANTS_VERSION = 1

# Refresh this long before the token actually dies, so a request that takes a
# moment does not arrive with an expired token.
EXPIRY_SLACK_SECONDS = 120
HTTP_TIMEOUT = 30


class GrantError(RuntimeError):
    """Anything this module refuses to do."""


class NotConnected(GrantError):
    """The grant exists but has never been completed, or was disconnected."""


class RefreshFailed(GrantError):
    """The provider refused to renew the grant. Usually means: sign in again."""


# ── providers ──────────────────────────────────────────────────────────────
#
# Only services where YOU register the client. Everything else is described at
# `add_grant` time — see the module docstring for why.

PROVIDERS: dict[str, dict[str, Any]] = {
    "google": {
        "label": "Google",
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "scope": "openid email profile",
        "extra_authorize": {"access_type": "offline", "prompt": "consent"},
    },
    "github": {
        "label": "GitHub",
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "scope": "read:user",
    },
    "microsoft": {
        "label": "Microsoft",
        "authorize_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "scope": "openid profile email offline_access",
    },
    "custom": {
        "label": "Custom",
        "authorize_url": "",
        "token_url": "",
        "scope": "",
    },
}


# ── the grant file ─────────────────────────────────────────────────────────


def grants_path(root: Path | None = None) -> Path:
    if root is not None:
        return Path(root) / GRANTS_FILENAME
    import passbook

    return passbook.root() / GRANTS_FILENAME


def read_grants(*, root: Path | None = None) -> dict[str, Any]:
    try:
        loaded = json.loads(grants_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": GRANTS_VERSION, "grants": []}
    if not isinstance(loaded, dict):
        return {"version": GRANTS_VERSION, "grants": []}
    loaded.setdefault("version", GRANTS_VERSION)
    if not isinstance(loaded.get("grants"), list):
        loaded["grants"] = []
    return loaded


def _write(payload: Mapping[str, Any], *, root: Path | None = None) -> Path:
    path = grants_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp{os.getpid()}")
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(handle, (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    finally:
        os.close(handle)
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover
        pass
    return path


def _slug(text: str) -> str:
    cleaned = "".join(c if c.isalnum() else "_" for c in str(text).strip().upper())
    return "_".join(part for part in cleaned.split("_") if part)


def grant_keys(grant: Mapping[str, Any]) -> dict[str, str]:
    """Which store key holds which part of this grant."""
    prefix = str(grant.get("key_prefix") or "").strip()
    if not prefix:
        raise GrantError("This grant has no key prefix")
    named = grant.get("keys")
    if isinstance(named, dict) and named:
        return {role: str(name) for role, name in named.items() if str(name).strip()}
    return {
        "access_token": f"{prefix}_ACCESS_TOKEN",
        "refresh_token": f"{prefix}_REFRESH_TOKEN",
        "expires_at": f"{prefix}_EXPIRES_AT",
        "account": f"{prefix}_ACCOUNT",
    }


def grants(*, root: Path | None = None) -> list[dict[str, Any]]:
    """Every grant, described. Key NAMES and endpoints — never a token."""
    out = []
    for grant in read_grants(root=root).get("grants", []):
        if not isinstance(grant, dict):
            continue
        out.append({
            "id": grant.get("id", ""),
            "provider": grant.get("provider", ""),
            "label": grant.get("label", ""),
            "account": grant.get("account", ""),
            "key_prefix": grant.get("key_prefix", ""),
            "keys": grant_keys(grant) if grant.get("key_prefix") else {},
            "token_url": grant.get("token_url", ""),
            "scope": grant.get("scope", ""),
            "created_at": grant.get("created_at", ""),
            "connected_at": grant.get("connected_at", ""),
        })
    return out


def find_grant(grant_id: str, *, root: Path | None = None) -> dict[str, Any]:
    wanted = str(grant_id).strip()
    for grant in read_grants(root=root).get("grants", []):
        if isinstance(grant, dict) and (grant.get("id") == wanted or grant.get("label") == wanted):
            return grant
    raise GrantError(f"No such sign-in: {grant_id}")


def add_grant(
    provider: str,
    label: str = "",
    *,
    client_id: str = "",
    client_secret: str = "",
    authorize_url: str = "",
    token_url: str = "",
    scope: str = "",
    key_prefix: str = "",
    redirect_port: int = 0,
    root: Path | None = None,
) -> dict[str, Any]:
    """Describe a sign-in. Does not connect it — `authorize_url` does that."""
    known = PROVIDERS.get(str(provider).strip().lower())
    if known is None:
        raise GrantError(f"Unknown provider {provider!r}. Known: {', '.join(sorted(PROVIDERS))}")
    name = str(label).strip() or str(provider).strip().lower()
    prefix = _slug(key_prefix or f"{provider}_{name}" if label else f"{provider}") or _slug(provider)

    resolved_token = str(token_url or known["token_url"]).strip()
    resolved_authorize = str(authorize_url or known["authorize_url"]).strip()
    if not resolved_token or not resolved_authorize:
        raise GrantError("A custom provider needs both --authorize-url and --token-url")
    if not client_id:
        raise GrantError("A sign-in needs a client id — register one with the provider")

    vault = read_grants(root=root)
    identifier = f"{str(provider).strip().lower()}:{name}"
    if any(isinstance(g, dict) and g.get("id") == identifier for g in vault["grants"]):
        raise GrantError(f"{identifier} already exists")

    grant = {
        "id": identifier,
        "provider": str(provider).strip().lower(),
        "label": name,
        "client_id": client_id,
        # A confidential client's secret is a credential, so it goes in the
        # store like every other one rather than into this readable file.
        "client_secret_key": f"{prefix}_CLIENT_SECRET" if client_secret else "",
        "authorize_url": resolved_authorize,
        "token_url": resolved_token,
        "scope": str(scope or known["scope"]).strip(),
        "extra_authorize": known.get("extra_authorize", {}),
        "key_prefix": prefix,
        "redirect_port": int(redirect_port or 0),
        "created_at": _now_iso(),
        "connected_at": "",
    }
    vault["grants"].append(grant)
    _write(vault, root=root)
    if client_secret:
        import passbook

        passbook.set_values({grant["client_secret_key"]: client_secret}, overwrite=True)
    return {"id": identifier, "key_prefix": prefix, "keys": grant_keys(grant)}


def remove_grant(grant_id: str, *, forget_tokens: bool = True, root: Path | None = None) -> dict[str, Any]:
    """Forget a sign-in, and by default the tokens with it."""
    vault = read_grants(root=root)
    grant = find_grant(grant_id, root=root)
    vault["grants"] = [g for g in vault["grants"] if g.get("id") != grant["id"]]
    _write(vault, root=root)
    removed: list[str] = []
    if forget_tokens:
        import passbook

        names = list(grant_keys(grant).values())
        if grant.get("client_secret_key"):
            names.append(grant["client_secret_key"])
        try:
            passbook.remove_values(names)
            removed = names
        except Exception:  # noqa: BLE001 — forgetting the grant is the point
            pass
    return {"removed": grant["id"], "forgot": sorted(removed)}


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ── connecting: PKCE ───────────────────────────────────────────────────────


def _verifier() -> str:
    return base64.urlsafe_b64encode(os.urandom(64)).decode("ascii").rstrip("=")


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def authorize_url(
    grant_id: str, *, redirect_uri: str, root: Path | None = None,
) -> dict[str, str]:
    """Where to send the browser, plus the PKCE verifier to hold onto.

    The verifier never leaves this process — that is what PKCE is for. It is
    returned to the caller rather than written down, so an interrupted login
    leaves nothing behind.
    """
    grant = find_grant(grant_id, root=root)
    verifier = _verifier()
    state = secrets.token_urlsafe(24)
    query = {
        "response_type": "code",
        "client_id": grant["client_id"],
        "redirect_uri": redirect_uri,
        "scope": grant.get("scope", ""),
        "state": state,
        "code_challenge": _challenge(verifier),
        "code_challenge_method": "S256",
    }
    query.update(grant.get("extra_authorize") or {})
    return {
        "url": f"{grant['authorize_url']}?{urllib.parse.urlencode(query)}",
        "verifier": verifier,
        "state": state,
    }


def _post_form(url: str, form: Mapping[str, str], *, opener: Callable[..., Any] | None = None) -> dict[str, Any]:
    body = urllib.parse.urlencode({k: v for k, v in form.items() if v}).encode("ascii")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"})
    send = opener or urllib.request.urlopen
    try:
        with send(request, timeout=HTTP_TIMEOUT) as response:
            raw = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:200] if hasattr(error, "read") else ""
        raise RefreshFailed(f"the provider returned {error.code}: {detail}") from error
    except (urllib.error.URLError, OSError) as error:
        raise RefreshFailed(f"could not reach the provider: {error}") from error
    try:
        parsed = json.loads(raw)
    except ValueError:
        # GitHub answers form-encoded unless asked otherwise, and asking is not
        # always honoured. Accept both rather than failing on a working reply.
        parsed = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
    if not isinstance(parsed, dict) or parsed.get("error"):
        raise RefreshFailed(str(parsed.get("error_description") or parsed.get("error") or "no token returned"))
    return parsed


def _client_secret(grant: Mapping[str, Any]) -> str:
    key = str(grant.get("client_secret_key") or "")
    if not key:
        return ""
    import passbook

    return passbook.request([key], app="passbook-oauth", reason="client secret").get(key, "")


def complete_login(
    grant_id: str, *, code: str, verifier: str, redirect_uri: str,
    root: Path | None = None, opener: Callable[..., Any] | None = None,
) -> dict[str, str]:
    """Trade the authorization code for tokens, and store them."""
    grant = find_grant(grant_id, root=root)
    tokens = _post_form(grant["token_url"], {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": grant["client_id"],
        "client_secret": _client_secret(grant),
        "code_verifier": verifier,
    }, opener=opener)
    written = _persist(grant, tokens, root=root)
    vault = read_grants(root=root)
    for entry in vault["grants"]:
        if entry.get("id") == grant["id"]:
            entry["connected_at"] = _now_iso()
    _write(vault, root=root)
    return written


def exchange_refresh(
    grant: Mapping[str, Any], refresh_token: str, *,
    root: Path | None = None, opener: Callable[..., Any] | None = None,
) -> dict[str, str]:
    """Renew a grant. Returns the values to store; does not store them."""
    if not refresh_token:
        raise NotConnected("this sign-in has no refresh token")
    tokens = _post_form(grant["token_url"], {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": grant.get("client_id", ""),
        "client_secret": _client_secret(grant),
        "scope": grant.get("scope", ""),
    }, opener=opener)
    return _token_values(grant, tokens, previous_refresh=refresh_token)


def _token_values(
    grant: Mapping[str, Any], tokens: Mapping[str, Any], *, previous_refresh: str = "",
) -> dict[str, str]:
    keys = grant_keys(grant)
    access = str(tokens.get("access_token") or "")
    if not access:
        raise RefreshFailed("the provider returned no access token")
    values = {keys["access_token"]: access}
    # Rotating providers issue a new refresh token; non-rotating ones omit it,
    # and overwriting with an empty string would disconnect the grant silently.
    rotated = str(tokens.get("refresh_token") or "")
    if rotated or previous_refresh:
        values[keys["refresh_token"]] = rotated or previous_refresh
    lifetime = tokens.get("expires_in")
    if lifetime:
        try:
            values[keys["expires_at"]] = str(int(time.time()) + int(lifetime))
        except (TypeError, ValueError):
            pass
    for field in ("account_id", "id_token"):
        if tokens.get(field) and "account" in keys and field == "account_id":
            values[keys["account"]] = str(tokens[field])
    return values


def _persist(grant: Mapping[str, Any], tokens: Mapping[str, Any], *, root: Path | None = None) -> dict[str, str]:
    import passbook

    values = _token_values(grant, tokens)
    passbook.set_values(values, overwrite=True)
    return {name: "stored" for name in values}


# ── reading a grant's state ────────────────────────────────────────────────


def token_values(grant: Mapping[str, Any], *, app: str = "passbook-oauth") -> dict[str, str]:
    """This grant's stored values, through the normal door."""
    import passbook

    return passbook.request(list(grant_keys(grant).values()), app=app,
                            reason=f"sign-in {grant.get('id', '')}")


def needs_refresh(grant: Mapping[str, Any], values: Mapping[str, str], *,
                  slack: int = EXPIRY_SLACK_SECONDS, now: float | None = None) -> bool:
    """Is the access token missing, or close enough to expiry to renew?

    A grant with no recorded expiry is treated as needing a refresh only when it
    has no access token at all — some providers do not say, and refreshing on
    every read would rate-limit an honest caller.
    """
    keys = grant_keys(grant)
    access = values.get(keys["access_token"], "")
    if not access:
        return True
    raw = values.get(keys["expires_at"], "")
    if not raw:
        return False
    try:
        expires_at = float(raw)
    except (TypeError, ValueError):
        return False
    return (now if now is not None else time.time()) >= expires_at - slack


def status(grant: Mapping[str, Any], values: Mapping[str, str], *, now: float | None = None) -> dict[str, Any]:
    """Connected, expiring, expired or never connected. Never a token."""
    keys = grant_keys(grant)
    has_access = bool(values.get(keys["access_token"]))
    has_refresh = bool(values.get(keys["refresh_token"]))
    raw = values.get(keys["expires_at"], "")
    moment = now if now is not None else time.time()
    try:
        expires_at = float(raw) if raw else 0.0
    except (TypeError, ValueError):
        expires_at = 0.0
    remaining = int(expires_at - moment) if expires_at else 0

    if not has_refresh and not has_access:
        state, detail = "disconnected", "Never connected, or signed out."
    elif not has_refresh:
        state, detail = "no-refresh", "Connected, but with no refresh token — it will die and stay dead."
    elif expires_at and remaining <= 0:
        state, detail = "expired", "Expired. The next read renews it."
    elif expires_at and remaining <= EXPIRY_SLACK_SECONDS:
        state, detail = "expiring", "About to expire. The next read renews it."
    else:
        state, detail = "connected", ("Connected." if not expires_at
                                      else f"Connected, {_describe(remaining)} left.")
    return {
        "id": grant.get("id", ""), "provider": grant.get("provider", ""),
        "label": grant.get("label", ""), "state": state, "detail": detail,
        "expires_in": max(0, remaining), "has_refresh": has_refresh,
        "keys": keys,
    }


def _describe(seconds: int) -> str:
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{round(seconds / 60)} min"
    if seconds < 172800:
        return f"{round(seconds / 3600)}h"
    return f"{round(seconds / 86400)} days"


def describe(*, root: Path | None = None, app: str = "passbook-oauth") -> list[dict[str, Any]]:
    """Every sign-in and its state, for a status surface. Never a token."""
    out = []
    for grant in read_grants(root=root).get("grants", []):
        if not isinstance(grant, dict) or not grant.get("key_prefix"):
            continue
        try:
            values = token_values(grant, app=app)
        except Exception:  # noqa: BLE001 — a locked store means "cannot tell"
            values = {}
        out.append(status(grant, values))
    return out
