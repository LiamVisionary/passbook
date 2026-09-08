# SPDX-License-Identifier: Apache-2.0
"""Credential use under verified installations; no agent-facing plaintext path."""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any, Mapping

import passbook
import passbook_access as access
import passbook_grant as grant_tools
import passbook_vault as vault
from passbook_managed_store import ManagedError, Store, Transaction, canonical, identifier, now_ms
from passbook_integrations import (_password_key, _public_request, _ready, env_for, require_request,
                                   stamp, text, workspace_path, record, PENDING_MS)

KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def keys_of(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ManagedError("Choose the keys needed for this operation.")
    if any(not isinstance(key, str) or not KEY.fullmatch(key) for key in value):
        raise ManagedError("A key name is invalid.")
    return sorted(set(value))


def _raw(root: Path, workspace: str) -> dict[str, str]:
    path = workspace_path(root, workspace)
    try:
        return passbook.parse_env_text(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def _values(root: Path, workspace: str, keys: list[str], broker: Any) -> dict[str, str]:
    # Managed bindings never inherit a daemon's ambient environment or another
    # workspace's keys. Existing standalone inheritance remains separate.
    raw = _raw(root, workspace)
    dek, profile = broker._held_dek(workspace)
    values: dict[str, str] = {}
    for key in keys:
        value = raw.get(key)
        if not value:
            continue
        if vault.is_sealed(value):
            if dek is not None:
                try:
                    values[key] = vault.unseal_value(key, value, dek, profile_id=profile)
                except vault.VaultError:
                    pass
        elif not value.startswith("hive-sealed:"):
            values[key] = value
    return values


def _policy_denials(root: Path, binding: Mapping[str, Any], body: Mapping[str, Any], keys: list[str], broker: Any) -> list[str]:
    policy = broker.read_policy(root)
    denied = []
    for key in keys:
        # An owner-created managed grant may answer ask, but cannot override an
        # explicit never, project, audience, workspace, or host restriction.
        verdict = access.decide_key(str(body.get("agentId") or binding["app"]), key, policy,
                                    root=root, workspace=binding["workspace"], project=str(body.get("project") or ""))
        if verdict["outcome"] == "refuse":
            denied.append(key)
        destination = str(body.get("destination") or "")
        if destination and grant_tools.destinations_for(key, policy):
            if not grant_tools.host_allowed(key, destination, policy)["allowed"]:
                denied.append(key)
    return sorted(set(denied))


def _normalize(body: Mapping[str, Any], binding: Mapping[str, Any]) -> dict[str, Any]:
    agent = text(body.get("agentId"), limit=128, required=True)
    keys = keys_of(body.get("keys"))
    operation = text(body.get("operation"), limit=100, required=True)
    destination = text(body.get("destination"), limit=2048, required=True)
    parsed = urllib.parse.urlsplit(destination)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or "{{" in destination or "\\" in destination):
        raise ManagedError("Choose a secure connection destination.", "invalid-destination")
    parameters = body.get("parameters", {})
    if not isinstance(parameters, dict):
        raise ManagedError("The operation parameters are invalid.")
    url = parameters.get("url", destination)
    if url != destination:
        raise ManagedError("The requested destination changed.", "destination-mismatch")
    method = text(parameters.get("method", "GET"), limit=10).upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
        raise ManagedError("This connection operation is not supported.")
    headers = parameters.get("headers", {})
    if not isinstance(headers, dict) or len(headers) > 32:
        raise ManagedError("The request headers are invalid.")
    for key, value in headers.items():
        if (not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,80}", key)
                or not isinstance(value, str) or any(ord(c) < 32 for c in value)
                or key.lower() in {"host", "connection", "content-length", "proxy-authorization", "cookie"}):
            raise ManagedError("The request headers are invalid.")
    params = {"url": destination, "method": method, "headers": headers}
    if "body" in parameters:
        params["body"] = parameters["body"]
    encoded = canonical(params)
    placeholders = grant_tools.placeholders(encoded)
    if not set(placeholders).issubset(set(keys)):
        raise ManagedError("The operation asks for a key that was not listed.")
    if not placeholders:
        # A convenient safe default for the ordinary single bearer-key case.
        # Multi-key/auth schemes must supply their exact header templates.
        if len(keys) != 1 or any(key.lower() == "authorization" for key in headers):
            raise ManagedError("Choose how this connection uses the selected keys.")
        params["headers"] = {**headers, "Authorization": "Bearer {{" + keys[0] + "}}"}
    # Never put credentials into a URL or arbitrary request body; managed
    # connectors substitute only explicitly named authentication headers.
    if grant_tools.placeholders(canonical(params.get("body"))):
        raise ManagedError("Keys can only be supplied through this connection's authentication headers.")
    if set(grant_tools.placeholders(*params["headers"].values())) != set(keys):
        raise ManagedError("Every requested key must be used by this connection.")
    task = text(body.get("taskId"), limit=200)
    project = text(body.get("project"), limit=128)
    account = text(body.get("account"), limit=200)
    idem = text(body.get("idempotencyKey"), limit=200, required=True)
    # Include HTTP method in the permission operation even if a caller reuses a
    # friendly label. A read grant must never authorize a DELETE at the same URL.
    op = operation if operation.startswith(method + " ") else method + " " + operation
    permission = {"agentId": agent, "workspace": binding["workspace"], "project": project, "keys": keys,
                  "operation": op, "destination": destination, "account": account}
    fingerprint = hashlib.sha256(canonical({**permission, "parameters": params}).encode()).hexdigest()
    digest = hashlib.sha256(canonical({**permission, "taskId": task, "parameters": params}).encode()).hexdigest()
    return {**permission, "installationId": binding["installationId"], "parameters": params,
            "taskId": task, "idempotencyKey": idem, "fingerprint": fingerprint, "digest": digest,
            "agentName": text(body.get("agentName") or agent, limit=100),
            "workspaceName": binding["name"], "deviceName": text(body.get("deviceName"), limit=100),
            "reason": text(body.get("reason"), limit=500)}


def _covering_grant(tx: Transaction, request: Mapping[str, Any]) -> dict[str, Any] | None:
    for grant in tx.all("grant"):
        if grant.get("revokedAt") or (grant.get("expiresMs") and grant["expiresMs"] <= now_ms()):
            continue
        if any(grant.get(key) != request.get(key) for key in ("installationId", "agentId", "workspace", "operation", "destination", "account", "project")):
            continue
        if grant["scope"] != "all-keys" and not set(request["keys"]).issubset(grant["keys"]):
            continue
        if grant["scope"] == "task" and (not request["taskId"] or grant["taskId"] != request["taskId"]):
            continue
        if grant["scope"] == "once" and (grant.get("usedAt") or grant["fingerprint"] != request["fingerprint"]):
            continue
        return grant
    return None


def _request(body: Mapping[str, Any], root: Path, tx: Transaction, binding: Mapping[str, Any], broker: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = _normalize(body, binding)
    candidate["workspaceName"] = passbook.workspace_label(binding["workspace"], env_for(root))
    denied = _policy_denials(root, binding, candidate, candidate["keys"], broker)
    if denied:
        raise ManagedError("This operation is restricted by your key permissions.", "policy-denied")
    raw = _raw(root, binding["workspace"])
    missing = [key for key in candidate["keys"] if not raw.get(key)]
    alias_id = hashlib.sha256(canonical([candidate["installationId"], candidate["agentId"],
                                        candidate["idempotencyKey"]]).encode()).hexdigest()
    alias = tx.get("request-key", alias_id)
    if alias:
        if alias["digest"] != candidate["digest"]:
            raise ManagedError("This retry changed the requested operation.", "idempotency-conflict")
        row = tx.get("request", alias["requestId"])
        if row:
            row["missingKeys"] = missing
            tx.put("request", row["id"], row)
            return row, candidate
    # Agent-local idempotency namespace prevents one agent from learning or
    # taking over another agent's operation by guessing its retry key.
    for row in tx.all("request"):
        if all(row.get(key) == candidate[key] for key in ("installationId", "agentId", "idempotencyKey")):
            if row["digest"] != candidate["digest"]:
                raise ManagedError("This retry changed the requested operation.", "idempotency-conflict")
            row["missingKeys"] = missing
            tx.put("request", row["id"], row)
            return row, candidate
    # Concurrent retries from the same task collapse only when the complete
    # operation matches. A larger permission never joins a smaller request.
    for row in tx.all("request"):
        if (row["installationId"] == candidate["installationId"] and row["digest"] == candidate["digest"]
                and row["status"] == "pending" and row["expiresMs"] > now_ms()):
            tx.put("request-key", alias_id, {"requestId": row["id"], "digest": candidate["digest"]})
            return row, candidate
    expires = now_ms() + PENDING_MS
    if sum(row["status"] == "pending" and row["agentId"] == candidate["agentId"]
           and row["installationId"] == candidate["installationId"] and row["expiresMs"] > now_ms()
           for row in tx.all("request")) >= 50:
        raise ManagedError("This agent already has many pending key requests. Resolve them before asking for more.", "request-limit")
    row = {**candidate, "id": identifier(), "status": "pending", "createdAt": stamp(),
           "expiresAt": stamp(expires), "expiresMs": expires, "missingKeys": missing}
    cover = _covering_grant(tx, row)
    if cover:
        row.update({"status": "approved", "grantId": cover["id"]})
    tx.put("request", row["id"], row)
    tx.put("request-key", alias_id, {"requestId": row["id"], "digest": candidate["digest"]})
    record(root, binding, "ask", row["keys"], request_id=row["id"], agent_id=row["agentId"])
    return row, {**candidate, "_created": True}


def _supply(body: Mapping[str, Any], root: Path, tx: Transaction, binding: Mapping[str, Any]) -> dict[str, Any]:
    row = require_request(tx, binding, body.get("requestId")) if body.get("requestId") else None
    if row and row["status"] != "pending":
        raise ManagedError("This request has already been answered.", "already-resolved")
    key = text(body.get("key"), limit=128, required=True)
    if not KEY.fullmatch(key) or (row and key not in row["keys"]):
        raise ManagedError("This key was not requested.")
    value = body.get("value")
    if not isinstance(value, str) or not value or len(value) > 32_000 or "\x00" in value or "\n" in value or "\r" in value:
        raise ManagedError("Enter a valid key value.")
    dek, profile = _password_key(root, binding["workspace"], body.get("password"))
    raw = _raw(root, binding["workspace"])
    overwrite = body.get("overwrite") is True and row is None
    if raw.get(key) and not overwrite:
        raise ManagedError("This key is already saved. It does not need adding again.", "already-present")
    sealed = vault.seal_value(key, value, dek, profile_id=profile)
    # Existing PassBook writer preserves comments/other values and writes an
    # encrypted value atomically. The managed transaction serializes its writers.
    passbook.set_values({key: sealed}, environ=env_for(root, binding["workspace"]),
                        path=workspace_path(root, binding["workspace"]), overwrite=overwrite)
    if row:
        row["missingKeys"] = [name for name in row["keys"] if not _raw(root, binding["workspace"]).get(name)]
        tx.put("request", row["id"], row)
    record(root, binding, "write", [key], request_id=row["id"] if row else "")
    return {"ok": True, **({"request": _public_request(row)} if row else {}), "saved": True}


def credential_names(root: Path, binding: Mapping[str, Any]) -> dict[str, Any]:
    credentials: set[str] = set()
    configuration: set[str] = set()
    names = set(passbook.workspaces(env_for(root))) | {"main", binding["workspace"]}
    for workspace in names:
        path = workspace_path(root, workspace)
        raw = _raw(root, workspace)
        skip = vault.skip_list(root=path.parent)
        for key, value in raw.items():
            (configuration if vault.matches_skip(key, skip) and not value.startswith("hive-sealed:")
             else credentials).add(key)
    return {"ok": True, "state": "paused" if binding.get("paused") else "ready",
            "credentialNames": sorted(credentials), "configurationNames": sorted(configuration - credentials),
            "workspaceNames": sorted(key for key, value in _raw(root, binding["workspace"]).items() if value)}


def _service_write(body: Mapping[str, Any], root: Path, binding: Mapping[str, Any], broker: Any) -> dict[str, Any]:
    if body.get("agentId"):
        raise ManagedError("Agent requests use connection operations.", "agent-write-forbidden")
    incoming = body.get("values")
    if not isinstance(incoming, dict):
        raise ManagedError("The requested keys are invalid.")
    keys = keys_of(list(incoming))
    if any(not isinstance(value, str) or not value or len(value) > 32_000 or any(c in value for c in "\0\r\n") for value in incoming.values()):
        raise ManagedError("A key value is invalid.")
    if _policy_denials(root, binding, {}, keys, broker):
        raise ManagedError("This connection is restricted by your key permissions.", "policy-denied")
    if _ready(binding, root, broker) != "ready":
        raise ManagedError("Unlock your keys before saving this connection.", "locked")
    dek, profile = broker._held_dek(binding["workspace"])
    sealed = {key: vault.seal_value(key, value, dek, profile_id=profile) for key, value in incoming.items()}
    path = workspace_path(root, binding["workspace"])
    passbook.set_values(sealed, environ=env_for(root, binding["workspace"]), path=path, overwrite=True)
    record(root, binding, "write", keys)
    return {"ok": True, "saved": keys}


def _service_remove(body: Mapping[str, Any], root: Path, binding: Mapping[str, Any], broker: Any) -> dict[str, Any]:
    if body.get("agentId"):
        raise ManagedError("Agent requests use connection operations.", "agent-write-forbidden")
    keys = keys_of(body.get("keys"))
    if _policy_denials(root, binding, {}, keys, broker):
        raise ManagedError("This connection is restricted by your key permissions.", "policy-denied")
    if _ready(binding, root, broker) != "ready":
        raise ManagedError("Unlock your keys before removing this connection.", "locked")
    result = passbook.remove_values(keys, workspace_id=binding["workspace"],
                                   environ=env_for(root, binding["workspace"]))
    record(root, binding, "remove", result["removed"])
    return {"ok": True, "removed": result["removed"], "absent": result["absent"]}


def handle(action: str, body: Mapping[str, Any], root: Path, tx: Transaction, binding: Mapping[str, Any], broker: Any) -> dict[str, Any]:
    if action == "supply-key":
        return _supply(body, root, tx, binding)
    if action == "service-write":
        return _service_write(body, root, binding, broker)
    if action == "service-remove":
        return _service_remove(body, root, binding, broker)
    ready = _ready(binding, root, broker)
    if action == "service-values":
        if body.get("agentId"):
            raise ManagedError("Agent requests use connection operations.", "agent-read-forbidden")
        keys = keys_of(body.get("keys"))
        if _policy_denials(root, binding, {}, keys, broker):
            raise ManagedError("This connection is restricted by your key permissions.", "policy-denied")
        record(root, binding, "read" if ready == "ready" else "denied", keys, granted=ready == "ready")
        return {"ok": True, "state": ready, "values": _values(root, binding["workspace"], keys, broker) if ready == "ready" else {}}
    row, candidate = _request(body, root, tx, binding, broker)
    safe = _public_request(row)
    if row["status"] == "consumed":
        if "result" in row:
            return {"ok": True, "state": "ready", "requestId": row["id"], "result": row["result"]}
        return {"ok": True, "state": "denied", "requestId": row["id"], "code": "outcome-unknown",
                "detail": "This operation may have completed. Check its result before trying again."}
    if row["status"] in {"denied", "cancelled", "expired"} or row["expiresMs"] <= now_ms():
        return {"ok": True, "state": "denied", "request": safe}
    if row["missingKeys"]:
        return {"ok": True, "state": "absent", "request": safe, "created": candidate.get("_created", False)}
    if ready != "ready":
        return {"ok": True, "state": "locked", "request": safe, "created": candidate.get("_created", False)}
    cover = _covering_grant(tx, row)
    if not cover:
        if row["status"] != "pending":
            row["status"] = "pending"
            row.pop("grantId", None)
            tx.put("request", row["id"], row)
        return {"ok": True, "state": "awaiting-approval", "request": _public_request(row),
                "created": candidate.get("_created", False)}
    if action == "request":
        return {"ok": True, "state": "ready", "request": safe}
    values = _values(root, binding["workspace"], row["keys"], broker)
    if set(values) != set(row["keys"]):
        return {"ok": True, "state": "locked", "request": safe}
    row["status"] = "consumed"
    tx.put("request", row["id"], row)
    if cover["scope"] == "once":
        cover["usedAt"] = stamp()
        tx.put("grant", cover["id"], cover)
    # Commit the reservation before contacting a provider. On a crash we report
    # an uncertain outcome instead of repeating a potentially destructive call.
    return {"_execute": {"requestId": row["id"], "parameters": row["parameters"],
                         "values": values, "installationId": binding["installationId"],
                         "binding": {"app": binding["app"], "workspace": binding["workspace"], "installationId": binding["installationId"]},
                         "agentId": row["agentId"]}}


def execute(plan: Mapping[str, Any], root: Path) -> dict[str, Any]:
    from passbook_managed_http import proxy
    # The reservation is durable first; the receipt is durable before secrets
    # leave for the provider. If the ledger cannot be written, do not send.
    record(root, plan["binding"], "use", sorted(plan["values"]),
           request_id=plan["requestId"], agent_id=plan["agentId"])
    result = proxy(plan["parameters"], plan["values"])
    with Store(root).transaction() as tx:
        row = tx.get("request", plan["requestId"])
        if row and row["installationId"] == plan["installationId"]:
            row["result"] = result
            tx.put("request", row["id"], row)
    return {"ok": True, "state": "ready", "requestId": plan["requestId"], "result": result}
