# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Linking a browser to a PassBook workspace.

HivemindOS on the web (hivemindos.app) is a browser, not a machine PassBook can see. It links the
way any second device does (`passbook_link`): it makes a device identity, publishes a pairing token,
and receives envelopes sealed to it after a person approves. Two things differ, and only two:

**Transport.** A web page and this app cannot pass strings to each other, so a relay carries them.
The page registers its pairing token there and opens `passbook://link?request=<id>&relay=<origin>`.
This module reads the token from the relay, and after approval posts the sealed envelope back. The
relay sees a public token and an envelope it cannot open; that is the whole of what it learns. Only
relays on an allowlist are ever contacted, so a link cannot send an envelope anywhere else.

**Scope and time.** A browser links to a whole workspace, not a list of keys, and it stays current:
`sync` re-seals the workspace's keys to every linked browser whenever this machine has the workspace
open, so a key added or changed here reaches the browser on its next visit. The grant inside each
envelope still expires (30 days) and a browser that stops being refreshed stops receiving anything.

Approval is the owner's, in PassBook, with the same factor that opens the workspace (password, or a
workspace already opened with a passkey or Touch ID). The owner also confirms that the code the
browser shows matches the one here: that is the fingerprint check the link protocol requires, and a
swapped pairing token cannot survive it.

What it cannot do, as with every link: unlinking stops the next envelope, not the last one. A browser
that was linked has seen the keys it was sent; rotate at the provider anything that must not outlive it.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

import passbook
import passbook_link as link
import passbook_vault as vault
from passbook_managed_store import ManagedError

DEFAULT_RELAYS = ("https://hivemindos-paid-agent-gateway.hivemindos.workers.dev",)
REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{22}$")
GRANT_DAYS = 30
TIMEOUT = 20
KIND = "weblink"


def relays(environ: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """Relays this machine will talk to. Extra ones only by explicit configuration."""
    env = os.environ if environ is None else environ
    extra = [item.strip().rstrip("/") for item in str(env.get("PASSBOOK_WEB_RELAYS", "")).split(",") if item.strip()]
    return tuple(dict.fromkeys([*DEFAULT_RELAYS, *extra]))


def relay_origin(url: str, environ: Mapping[str, str] | None = None) -> str:
    try:
        parsed = urllib.parse.urlsplit(str(url).strip())
    except ValueError:
        raise ManagedError("This link does not come from HivemindOS.", "relay-refused") from None
    origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment or origin not in relays(environ):
        raise ManagedError("This link does not come from HivemindOS.", "relay-refused")
    return origin


def parse_link(url: str) -> tuple[str, str]:
    """`passbook://link?request=<id>&relay=<origin>` -> (id, relay). Anything else is refused."""
    text = str(url).strip()
    prefix = "passbook://link?"
    if not text.startswith(prefix):
        raise ManagedError("That is not a HivemindOS link.", "request-not-found")
    query = urllib.parse.parse_qs(text[len(prefix):], strict_parsing=True, max_num_fields=2)
    request_id = (query.get("request") or [""])[0]
    relay = (query.get("relay") or [""])[0]
    if not REQUEST_ID.fullmatch(request_id) or set(query) != {"request", "relay"}:
        raise ManagedError("That is not a HivemindOS link.", "request-not-found")
    return request_id, relay_origin(relay)


def _http(method: str, url: str, body: Mapping[str, Any] | None = None, *,
          opener: Callable[..., Any] | None = None) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json", "Accept": "application/json", "User-Agent": "PassBook",
    })
    try:
        with (opener or urllib.request.urlopen)(request, timeout=TIMEOUT) as response:
            return response.status, json.loads(response.read(1_000_000) or b"{}")
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read(100_000) or b"{}")
        except ValueError:
            return error.code, {}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise ManagedError("HivemindOS could not be reached. Check your connection and try again.", "relay-unavailable") from None


def _read_request(request_id: str, relay: str, opener=None) -> dict[str, Any]:
    status, answer = _http("GET", f"{relay}/api/passbook/link-requests/{request_id}", opener=opener)
    if status != 200 or not answer.get("ok"):
        raise ManagedError("This link request has expired. Start again from HivemindOS.", "request-expired")
    try:
        peer = link.read_pairing_token(answer["pairingToken"])
    except (link.LinkError, KeyError):
        raise ManagedError("This link request is damaged. Start again from HivemindOS.", "request-expired") from None
    return {"peer": peer, "token": answer["pairingToken"], "site": str(answer.get("site") or "hivemindos.app")[:120],
            "label": str(answer.get("label") or "HivemindOS on the web")[:60]}


def inspect(request_id: str, relay: str, root: Path, *, opener=None) -> dict[str, Any]:
    """What the owner is being asked to approve: who, the code to match, and where it can land."""
    from passbook_integrations import _workspace_rows
    relay = relay_origin(relay)
    if not REQUEST_ID.fullmatch(str(request_id)):
        raise ManagedError("That is not a HivemindOS link.", "request-not-found")
    seen = _read_request(request_id, relay, opener)
    return {"ok": True, "request": {"id": request_id, "relay": relay, "site": seen["site"], "label": seen["label"],
                                    "code": seen["peer"]["fingerprint"], "expires": seen["peer"]["expires"]},
            "workspaces": _workspace_rows(root)}


def _workspace_values(root: Path, workspace: str, dek: bytes | None, profile: str) -> dict[str, str]:
    from passbook_integrations import workspace_path
    path = workspace_path(root, workspace)
    try:
        raw = passbook.parse_env_text(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raw = {}
    opened = vault.unseal_mapping(raw, dek, profile_id=profile)
    # A value another machine sealed for its own store is not a credential here.
    return {key: value for key, value in opened.items() if value and not str(value).startswith("hive-sealed:")}


def _seal(peer: Mapping[str, Any], values: Mapping[str, str], workspace: str, root: Path) -> dict[str, Any]:
    token = link.PAIR_PREFIX + link._b64(json.dumps({
        "v": link.SPEC_VERSION, "did": peer["did"], "seal": link._b64(peer["seal_public"]),
        "exp": link._stamp(link._now() + timedelta(minutes=10)),
    }, separators=(",", ":")).encode("utf-8"))
    return link.grant(token, sorted(values), confirm_fingerprint=peer["fingerprint"], workspace=workspace,
                      days=GRANT_DAYS, root=root, resolve_values=lambda names: {name: values[name] for name in names})


def decide(body: Mapping[str, Any], root: Path, tx: Any, *, opener=None) -> dict[str, Any]:
    """The owner's answer, from the PassBook window (or `passbook link web`)."""
    from passbook_integrations import _password_key, _workspace_rows
    request_id = str(body.get("requestId") or "")
    relay = relay_origin(str(body.get("relay") or ""))
    if not REQUEST_ID.fullmatch(request_id):
        raise ManagedError("That is not a HivemindOS link.", "request-not-found")
    if body.get("decision") == "deny":
        _http("POST", f"{relay}/api/passbook/link-requests/{request_id}/answer", {"declined": True}, opener=opener)
        return {"ok": True, "decision": "deny"}
    if body.get("decision") != "allow":
        raise ManagedError("Review and approve this link to continue.", "consent-required")
    seen = _read_request(request_id, relay, opener)
    peer = seen["peer"]
    # The code on both screens is the fingerprint check; the window sends back what the owner matched.
    confirmed = "".join(str(body.get("code") or "").split()).upper().replace("-", "")
    if confirmed != peer["fingerprint"].replace("-", ""):
        raise ManagedError("The codes do not match. Do not link this browser.", "code-mismatch")
    workspace = str(body.get("workspace") or "")
    if workspace not in {row["id"] for row in _workspace_rows(root)}:
        raise ManagedError("Choose one of your workspaces.", "workspace-required")
    dek, profile = _password_key(root, workspace, body.get("password"))
    values = _workspace_values(root, workspace, dek, profile)
    if not values:
        raise ManagedError("This workspace has no keys to share yet.", "workspace-empty")
    try:
        sealed = _seal(peer, values, workspace, root)
    except link.LinkError as exc:
        raise ManagedError(str(exc), "link-failed") from None
    status, answer = _http("POST", f"{relay}/api/passbook/link-requests/{request_id}/answer",
                           {"envelope": sealed["envelope"]}, opener=opener)
    if status != 200 or not answer.get("ok"):
        raise ManagedError(str(answer.get("error") or "HivemindOS did not accept the link. Start again from HivemindOS."), "relay-refused")
    record = {"did": peer["did"], "seal": link._b64(peer["seal_public"]), "fingerprint": peer["fingerprint"],
              "relay": relay, "workspace": workspace, "site": seen["site"], "label": seen["label"],
              "linkedAt": link._stamp(link._now()), "syncedAt": link._stamp(link._now()), "revokedAt": None,
              "keys": len(values)}
    tx.put(KIND, peer["did"], record)
    return {"ok": True, "decision": "allow", "linked": _public(record), "issuerFingerprint": sealed["issuer_fingerprint"]}


def _public(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record.get(key) for key in ("did", "fingerprint", "workspace", "site", "label", "linkedAt", "syncedAt", "revokedAt", "keys")}


def linked(tx: Any) -> list[dict[str, Any]]:
    return [_public(row) for row in tx.all(KIND)]


def revoke(did: str, tx: Any) -> dict[str, Any]:
    row = tx.get(KIND, did)
    if not row:
        raise ManagedError("That browser is not linked.", "not-linked")
    row["revokedAt"] = link._stamp(link._now())
    tx.put(KIND, did, row)
    return {"ok": True, "detail": f"{row['label']} will receive nothing further. Keys it already received stay with it; "
                                  "rotate at the provider anything that must not."}


def sync(root: Path, tx: Any, held_dek: Callable[[str], tuple[bytes | None, str]], *, opener=None) -> dict[str, Any]:
    """Re-seal each linked browser's workspace while it is open here, so the browser stays current.

    A workspace that is locked on this machine is skipped, not forced open: sync never asks for a
    factor. The browser simply keeps what it last received until the owner opens PassBook again.
    """
    done, skipped, unlinked = [], [], []
    for row in tx.all(KIND):
        if row.get("revokedAt"):
            continue
        dek, profile = held_dek(row["workspace"])
        values = _workspace_values(root, row["workspace"], dek, profile)
        if dek is None and any(vault.is_sealed(v) for v in _raw_values(root, row["workspace"]).values()):
            skipped.append(row["label"])
            continue
        if not values:
            skipped.append(row["label"])
            continue
        peer = {"did": row["did"], "seal_public": link._unb64(row["seal"]), "fingerprint": row["fingerprint"]}
        try:
            sealed = _seal(peer, values, row["workspace"], root)
            status, answer = _http("POST", f"{row['relay']}/api/passbook/devices/{row['did']}/envelope",
                                   {"envelope": sealed["envelope"]}, opener=opener)
        except (ManagedError, link.LinkError):
            skipped.append(row["label"])
            continue
        if status == 410 or answer.get("unlinked"):
            # The browser was unlinked from HivemindOS: stop sealing to it here too.
            row["revokedAt"] = link._stamp(link._now())
            tx.put(KIND, row["did"], row)
            unlinked.append(row["label"])
        elif status == 200:
            row["syncedAt"] = link._stamp(link._now())
            row["keys"] = len(values)
            tx.put(KIND, row["did"], row)
            done.append(row["label"])
        else:
            skipped.append(row["label"])
    return {"ok": True, "synced": done, "skipped": skipped, "unlinked": unlinked}


def _raw_values(root: Path, workspace: str) -> dict[str, str]:
    from passbook_integrations import workspace_path
    try:
        return passbook.parse_env_text(workspace_path(root, workspace).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
