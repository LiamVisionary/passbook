# SPDX-License-Identifier: Apache-2.0
"""MCP adapter for a host that authenticates agents and handles owner approvals.

The host supplies its agent endpoint and a scoped bearer capability. Neither a
vault password nor the installation signing key belongs in this process.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping


def configured() -> bool:
    return bool(os.environ.get("PASSBOOK_AGENT_URL") and os.environ.get("PASSBOOK_AGENT_TOKEN"))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def call(action: str, body: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not configured():
        return {"ok": False, "state": "reconnecting", "error": "Connect this agent in its host app to use keys."}
    base = os.environ["PASSBOOK_AGENT_URL"].rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    if (parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment
            or not parsed.hostname or (parsed.scheme != "https" and not (
                parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}))):
        return {"ok": False, "error": "This agent's key connection address is not secure."}
    if action not in {"use", "requests"}:
        return {"ok": False, "error": "This key connection action is not supported."}
    payload = json.dumps(body, allow_nan=False, separators=(",", ":")).encode() if body is not None else None
    if payload is not None and len(payload) > 48_000:
        return {"ok": False, "error": "The key operation is too large."}
    header = os.environ.get("PASSBOOK_AGENT_HEADER", "Authorization")
    token = os.environ["PASSBOOK_AGENT_TOKEN"]
    if not re.fullmatch(r"[A-Za-z0-9-]{1,80}", header) or any(ord(c) < 32 for c in token):
        return {"ok": False, "error": "This agent's connection identity is invalid."}
    request = urllib.request.Request(base + "/" + action, data=payload,
        headers={header: "Bearer " + token if header.lower() == "authorization" else token, "Content-Type": "application/json"},
        method="POST" if payload is not None else "GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        try:
            response = opener.open(request, timeout=35)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(1_048_577)
            if len(raw) > 1_048_576:
                raise ValueError()
            reply = json.loads(raw)
            if not isinstance(reply, dict):
                raise ValueError()
            return reply
    except (OSError, ValueError):
        return {"ok": False, "state": "reconnecting", "error": "This key operation could not be confirmed. Resume with the same idempotency key."}


def use(arguments: Mapping[str, Any], _state=None) -> dict[str, Any]:
    body = {key: value for key, value in arguments.items() if key != "waitSeconds"}
    if not isinstance(body.get("idempotencyKey"), str) or not body["idempotencyKey"]:
        return {"ok": False, "error": "Choose an idempotency key and reuse it when resuming this operation."}
    try:
        wait = min(30, max(0, int(arguments.get("waitSeconds", 20))))
    except (ValueError, TypeError):
        wait = 20
    deadline = time.monotonic() + wait
    reply = call("use", body)
    while (reply.get("state") in {"absent", "locked", "awaiting-approval"}
           and reply.get("request", {}).get("status") == "pending" and time.monotonic() < deadline):
        time.sleep(min(2, max(0, deadline - time.monotonic())))
        reply = call("use", body)
    return reply


def status(_arguments=None, _state=None) -> dict[str, Any]:
    return call("requests")


TOOLS = [
    {"name": "credential_use", "description": "Use named keys through a verified host connection. Approval appears in the host app; never ask for a secret in chat. Resume with the same idempotencyKey until resolved.",
     "inputSchema": {"type": "object", "additionalProperties": False,
                     "required": ["keys", "operation", "destination", "account", "taskId", "reason", "idempotencyKey"],
                     "properties": {
                         "keys": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 32},
                         **{key: {"type": "string"} for key in ("operation", "destination", "account", "taskId", "reason", "idempotencyKey")},
                         "parameters": {"type": "object", "description": "HTTPS method, headers with {{KEY_NAME}} templates, and request body."},
                         "waitSeconds": {"type": "integer", "minimum": 0, "maximum": 30}}}},
    {"name": "credential_status", "description": "Check this verified agent's pending key requests. Never returns values.",
     "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}}},
]
