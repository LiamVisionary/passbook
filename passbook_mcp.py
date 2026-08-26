# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""PassBook as an MCP server — how an agent finds out it has credentials.

Optional companion to `passbook.py`. Run it as `passbook mcp`, point any MCP
client at it, and the agent learns three things the moment it connects: which
credentials this machine holds, which of them it is allowed to read, and how to
ask for one.

## Why MCP and not something new

An agent already knows how to speak MCP. The Agent Client Protocol, which sits
between editors and agents, reuses MCP's JSON representations and passes MCP
servers through to the agent — so one MCP server reaches both without inventing
a second thing for anyone to implement. There is nothing PassBook-shaped to
learn: it is a tool list and a resource, like everything else the agent has.

## The identity problem, stated honestly

The agent's name arrives in `initialize` as `clientInfo.name`, and that is a
**claim**. Nothing in the protocol proves it, and a process that wanted to read
another agent's keys could simply say it was that agent. This is the same limit
the broker has, for the same reason, and it is why the name is used for policy
and the ledger rather than treated as authentication.

What it does buy is real, and it is the common case rather than the adversarial
one: an agent asks for the three keys it needs instead of helping itself to the
environment, the owner can see which agent asked for what, and a key that is
none of an agent's business can be marked so.

## Values

`list_credentials` returns NAMES, never values — the same rule every other
status surface in this project follows. Exactly one tool returns a value,
`get_credential`, one key at a time, by name, through the broker, recorded.
That is so "can this leak?" stays answerable by reading the tool list.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

import passbook

__all__ = ["PROTOCOL_VERSION", "SERVER_NAME", "handle", "serve"]

SERVER_NAME = "passbook"
SERVER_VERSION = "1.0.0"
# Echoed back when the client asks for something we know; otherwise we answer
# with ours and let the client decide, which is what the spec asks for.
PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

CATALOG_URI = "passbook://credentials"


def _access():
    try:
        import passbook_access

        return passbook_access
    except ImportError:
        return None


def _catalog_module():
    try:
        import passbook_catalog

        return passbook_catalog
    except ImportError:
        return None


# ── the tools ──────────────────────────────────────────────────────────────


TOOLS = [
    {
        "name": "list_credentials",
        "title": "List available credentials",
        "description": (
            "Every credential this machine holds, by NAME, grouped, with whether "
            "you are allowed to read each one. Never returns values. Call this "
            "first: it tells you what exists without spending an approval."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "group": {"type": "string", "description": "Only this group."},
                "search": {"type": "string", "description": "Case-insensitive substring of the name."},
            },
        },
    },
    {
        "name": "get_credential",
        "title": "Read one credential",
        "description": (
            "The value of ONE credential, by name. Goes through the broker, so it "
            "is checked against this machine's policy and recorded. May be refused, "
            "or may wait while the owner is asked. Ask only for what you need — "
            "each call leaves a receipt with your name on it."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "The credential's name, e.g. OPENAI_API_KEY."},
                "reason": {"type": "string", "description": "Why you need it. Shown to the owner and recorded."},
            },
            "required": ["name"],
        },
    },
    {
        "name": "check_credentials",
        "title": "Check credentials exist",
        "description": (
            "Whether named credentials are set, without reading them. Use this to "
            "decide whether a task is possible before asking for anything."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "names": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["names"],
        },
    },
    {
        "name": "vault_status",
        "title": "Is the store unlocked",
        "description": (
            "Whether this machine's credential store is encrypted and whether it "
            "is currently unlocked. If it is locked, no credential can be read "
            "until the owner signs in — tell them rather than retrying."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _client_name(state: Mapping[str, Any]) -> str:
    return str(state.get("client") or "mcp-client")


def _visible(agent: str, names: list[str], policy: Mapping[str, Any], root: Path | None):
    access = _access()
    catalog = _catalog_module()
    out = []
    for name in names:
        entry: dict[str, Any] = {"name": name}
        if catalog is not None:
            entry["group"] = catalog.group_of(name, policy)
        if access is not None:
            verdict = access.decide_key(agent, name, policy, root=root)
            entry["access"] = verdict["outcome"]
            entry["why"] = verdict["why"]
        else:
            entry["access"] = "grant"
        out.append(entry)
    return out


def _record(agent: str, name: str, *, granted: bool, reason: str, root: Path | None) -> None:
    """Stamp a read. The broker stamps its own, so this covers the case where
    there is no broker — which is exactly when nothing else would."""
    try:
        import passbook_broker
        import passbook_stamp

        if passbook_broker.running(root=root):
            return  # already recorded on the far side; one event, one row
        passbook_stamp.stamp(op="read", keys=[name], app=agent,
                             granted=granted, reason=reason, root=root)
    except Exception:  # noqa: BLE001 — a receipt must never fail the call
        pass


def _tool_list_credentials(arguments: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any]:
    root = state.get("root")
    access = _access()
    catalog = _catalog_module()
    policy = access.read_policy(root) if access else {}
    names = passbook.key_names()

    search = str(arguments.get("search") or "").strip().lower()
    if search:
        names = [n for n in names if search in n.lower()]
    wanted_group = str(arguments.get("group") or "").strip()
    if wanted_group and catalog is not None:
        names = [n for n in names if catalog.group_of(n, policy).lower() == wanted_group.lower()]

    agent = _client_name(state)
    entries = _visible(agent, names, policy, root)
    readable = [e["name"] for e in entries if e.get("access") == "grant"]
    payload = {
        "agent": agent,
        "total": len(entries),
        "readable_now": len(readable),
        "credentials": entries,
    }
    if catalog is not None:
        payload["groups"] = catalog.groups(names, policy)
    return payload


def _tool_get_credential(arguments: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any]:
    name = str(arguments.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")
    agent = _client_name(state)
    reason = str(arguments.get("reason") or "")[:200] or "requested over MCP"
    root = state.get("root")
    access = _access()

    # Decide here, before asking. `passbook.request()` routes through the broker
    # when one is running and falls back to reading the file when one is not —
    # which is right for a plaintext store on a machine with no daemon, and
    # wrong here, because it would hand this agent a key the owner marked as
    # none of its business. An audience is a bound, so it is enforced at every
    # door rather than at the one that happens to be open.
    if access is not None:
        policy = access.read_policy(root)
        verdict = access.decide_key(agent, name, policy, root=root)
        if verdict["outcome"] == "refuse":
            _record(agent, name, granted=False, reason=verdict["why"], root=root)
            return {"name": name, "value": None, "refused": True, "why": verdict["why"]}

    granted = passbook.request([name], app=agent, reason=reason)
    if name in granted:
        _record(agent, name, granted=True, reason=reason, root=root)
        return {"name": name, "value": granted[name]}

    if name not in passbook.key_names():
        why = "this machine does not hold that credential"
    else:
        why = "the store is locked; the owner needs to sign in"
    _record(agent, name, granted=False, reason=why, root=root)
    return {"name": name, "value": None, "refused": True, "why": why}


def _tool_check_credentials(arguments: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any]:
    wanted = [str(n).strip() for n in (arguments.get("names") or []) if str(n).strip()]
    held = set(passbook.key_names())
    return {"present": sorted(n for n in wanted if n in held),
            "missing": sorted(n for n in wanted if n not in held)}


def _tool_vault_status(arguments: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any]:
    try:
        import passbook_broker

        live = passbook_broker.vault_status(root=state.get("root"))
    except Exception:  # noqa: BLE001 — no broker is a normal machine
        live = {}
    try:
        import passbook_vault

        shape = passbook_vault.status(root=state.get("root"))
    except Exception:  # noqa: BLE001
        shape = {}
    encrypted = bool(shape.get("sealed"))
    unlocked = bool(live.get("unlocked")) or not encrypted
    return {
        "encrypted": encrypted,
        "unlocked": unlocked,
        "detail": shape.get("detail", "The store is not encrypted."),
        "advice": ("Credentials are readable." if unlocked
                   else "The store is locked. Ask the owner to run `passbook signin`; "
                        "retrying will not help."),
    }


HANDLERS: dict[str, Callable[[Mapping[str, Any], Mapping[str, Any]], dict[str, Any]]] = {
    "list_credentials": _tool_list_credentials,
    "get_credential": _tool_get_credential,
    "check_credentials": _tool_check_credentials,
    "vault_status": _tool_vault_status,
}


# ── protocol ───────────────────────────────────────────────────────────────


def _result(request_id: Any, payload: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _content(payload: Any) -> dict[str, Any]:
    text = json.dumps(payload, indent=2, sort_keys=True)
    return {"content": [{"type": "text", "text": text}], "structuredContent": payload}


def handle(message: Mapping[str, Any], state: dict[str, Any]) -> dict[str, Any] | None:
    """One JSON-RPC message in, at most one out. None means a notification."""
    method = str(message.get("method") or "")
    request_id = message.get("id")
    params = message.get("params") if isinstance(message.get("params"), dict) else {}

    if method == "initialize":
        client = params.get("clientInfo") if isinstance(params.get("clientInfo"), dict) else {}
        # A claim, not a credential. Recorded as such; see the module docstring.
        state["client"] = str(client.get("name") or "").strip() or "mcp-client"
        asked = str(params.get("protocolVersion") or "")
        return _result(request_id, {
            "protocolVersion": asked if asked in SUPPORTED_VERSIONS else PROTOCOL_VERSION,
            "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "This machine shares one credential store between its apps, and you "
                "can read from it. Call `list_credentials` to see what exists — names "
                "and groups only, no values, no approval spent. Call `get_credential` "
                "for one value when you actually need it; it is checked against the "
                "owner's policy and leaves a receipt naming you. Never ask for "
                "everything, and never print a value into your reply or into a file."
            ),
        })

    if method in {"notifications/initialized", "notifications/cancelled", "initialized"}:
        return None

    if method == "ping":
        return _result(request_id, {})

    if method == "tools/list":
        return _result(request_id, {"tools": TOOLS})

    if method == "tools/call":
        name = str(params.get("name") or "")
        handler = HANDLERS.get(name)
        if handler is None:
            return _error(request_id, -32602, f"no such tool: {name}")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        try:
            return _result(request_id, _content(handler(arguments, state)))
        except Exception as error:  # noqa: BLE001 — a tool error is data, not a crash
            return _result(request_id, {
                "content": [{"type": "text", "text": str(error)}], "isError": True})

    if method == "resources/list":
        return _result(request_id, {"resources": [{
            "uri": CATALOG_URI,
            "name": "Credential catalogue",
            "description": "Names and groups of every credential this machine holds, "
                           "and whether you may read each. Never values.",
            "mimeType": "application/json",
        }]})

    if method == "resources/read":
        if str(params.get("uri") or "") != CATALOG_URI:
            return _error(request_id, -32602, f"no such resource: {params.get('uri')}")
        payload = _tool_list_credentials({}, state)
        return _result(request_id, {"contents": [{
            "uri": CATALOG_URI, "mimeType": "application/json",
            "text": json.dumps(payload, indent=2, sort_keys=True)}]})

    if request_id is None:
        return None
    return _error(request_id, -32601, f"unknown method: {method}")


def serve(*, root: Path | None = None, stdin=None, stdout=None) -> int:
    """Speak MCP over stdio until the client hangs up."""
    source = sys.stdin if stdin is None else stdin
    sink = sys.stdout if stdout is None else stdout
    state: dict[str, Any] = {"root": root}

    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            sink.write(json.dumps(_error(None, -32700, "invalid JSON")) + "\n")
            sink.flush()
            continue
        reply = handle(message, state)
        if reply is not None:
            sink.write(json.dumps(reply) + "\n")
            sink.flush()
    return 0
