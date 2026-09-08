# SPDX-License-Identifier: Apache-2.0
"""Verified application connections and durable, workspace-bound agent grants.

Host assertions authenticate an enrolled installation. The host must verify its
agent and human principals before signing; model-supplied names are never proof.
The operating-system boundary separating agents from the host remains required.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import passbook
import passbook_vault as vault
from passbook_managed_store import (ManagedError, Store, Transaction, canonical, identifier,
                                   installation_id, now_ms, verified_body, verify)

ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
WORKSPACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SCOPES = {"once", "task", "remember", "all-keys"}
PENDING_MS = 24 * 60 * 60 * 1000
TASK_MS = 24 * 60 * 60 * 1000
CHALLENGE_MS = 2 * 60 * 1000


def stamp(value: int | None = None) -> str:
    return datetime.fromtimestamp((now_ms() if value is None else value) / 1000, timezone.utc).isoformat()


def record(root: Path, binding: Mapping[str, Any], op: str, keys=(), *,
           request_id: str = "", agent_id: str = "", granted: bool = True) -> None:
    """Use the established names-only hash chain for managed activity as well."""
    import passbook_stamp
    passbook_stamp.stamp(root=root, op=op, keys=keys, app=binding["app"],
                        workspace=binding["workspace"], actor_did=binding["installationId"],
                        granted=granted, reason="managed" + (" request=" + request_id if request_id else "")
                        + (" agent=" + agent_id if agent_id else ""))


def text(value: Any, *, limit: int = 200, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ManagedError("The request contains invalid text.")
    value = value.strip()
    if required and not value:
        raise ManagedError("The request is missing required information.")
    return value


def env_for(root: Path, workspace: str = "main") -> dict[str, str]:
    return {"HIVE_HOME": str(root), "HIVE_WORKSPACE": workspace, "HIVE_WORKSPACE_ID": workspace}


def workspace_path(root: Path, workspace: str) -> Path:
    if not WORKSPACE.fullmatch(workspace):
        raise ManagedError("Choose a valid workspace.")
    return passbook.workspace_env_path(workspace, env_for(root, workspace))


def _workspace_rows(root: Path) -> list[dict[str, Any]]:
    env = env_for(root)
    names = set(passbook.workspaces(env))
    if (root / ".env").exists() or vault.vault_path(root).exists():
        names.add("main")
    return [{"id": name, "name": passbook.workspace_label(name, env),
             "hasProfile": bool(vault.active_profile_id(root=workspace_path(root, name).parent))}
            for name in sorted(names)]


def _register_workspace(root: Path, workspace: str, label: str, *, isolated: bool, rename_initial: bool = False) -> None:
    env = env_for(root, workspace)
    manifest = dict(passbook.workspace_manifest(env))
    rows = [dict(row) for row in manifest.get("workspaces", []) if isinstance(row, dict)]
    existing = next((row for row in rows if row.get("id") == workspace), None)
    if existing:
        if rename_initial:
            existing["name"] = label
            manifest["workspaces"] = rows
            passbook._atomic_write(root / passbook.WORKSPACES_MANIFEST, json.dumps(manifest, indent=2) + "\n")
        return
    path = workspace_path(root, workspace)
    rows.append({"id": workspace, "name": label, "envPath": str(path), "inherit": not isolated})
    manifest.update({"version": manifest.get("version", 1), "workspaces": rows})
    # The first workspace establishes a default; later integration setup never
    # switches the workspace the owner is currently looking at.
    manifest.setdefault("activeWorkspaceId", "main" if workspace != "main" and (root / ".env").exists() else workspace)
    passbook._atomic_write(root / passbook.WORKSPACES_MANIFEST, json.dumps(manifest, indent=2) + "\n")


def _password_key(root: Path, workspace: str, password: Any) -> tuple[bytes, str]:
    if not isinstance(password, str) or not password or len(password) > 4096:
        raise ManagedError("Confirm with your PassBook password.", "authentication-required")
    target = workspace_path(root, workspace).parent
    profile = vault.active_profile_id(root=target)
    try:
        return vault.unlock_with_password(profile, password, root=target), profile
    except vault.VaultError as exc:
        raise ManagedError("The password was not accepted.", "authentication-failed") from exc


def _connect(body: Mapping[str, Any], ident: str, root: Path, tx: Transaction, broker: Any) -> dict[str, Any]:
    public = text(body.get("publicKey"), limit=64, required=True)
    if installation_id(public) != ident:
        raise ManagedError("The app's identity could not be verified.", "invalid-proof")
    app = text(body.get("app"), limit=64, required=True)
    if not WORKSPACE.fullmatch(app):
        raise ManagedError("The app's identity is invalid.")
    label = text(body.get("name") or app, limit=100)
    if body.get("consent") is not True:
        raise ManagedError("Approve this connection to continue.", "consent-required")
    previous = tx.get("binding", ident)
    rows = _workspace_rows(root)
    workspace = text(body.get("workspace") or (previous or {}).get("workspace") or ("main" if not rows else app), limit=64)
    path = workspace_path(root, workspace)
    known = {row["id"] for row in rows}
    if workspace not in known and not body.get("createWorkspace") and rows:
        raise ManagedError("Choose an existing workspace or create a new one.", "workspace-required")
    if previous and previous["workspace"] != workspace and not previous.get("revokedAt"):
        raise ManagedError("Disconnect the existing workspace before connecting another.", "already-connected")
    background = body.get("background") is True
    if background:
        import passbook_keystore
        if not passbook_keystore.available():
            raise ManagedError("This device cannot yet protect background access. Connect without it or use a trusted device.",
                               "background-unavailable")
    password = body.get("password")
    target = path.parent
    existing_profile = vault.active_profile_id(root=target)
    if not isinstance(password, str) or not (1 if existing_profile else 8) <= len(password) <= 4096:
        raise ManagedError("Enter your PassBook password" + ("." if existing_profile else " (at least 8 characters)."),
                           "authentication-required")
    recovered = {}
    if body.get("recoveryId"):
        import passbook_managed_recovery
        recovered = passbook_managed_recovery.recover(body, ident, root, tx)
        existing_profile = vault.active_profile_id(root=target)
    if not existing_profile:
        expected = path.read_text(encoding="utf-8") if path.exists() else ""
        # initialize_store fails closed on foreign ciphertext. Enrollment must
        # recover/join that workspace, never silently overwrite its key.
        try:
            vault.initialize_store(password, root=target, path=path, expected=expected)
        except vault.VaultError as exc:
            raise ManagedError("This workspace needs recovery before it can connect. Open its existing PassBook workspace.",
                               "workspace-recovery-required") from exc
    dek, profile = _password_key(root, workspace, password)
    device_factor = (previous or {}).get("deviceFactor", "")
    if background and device_factor:
        try:
            # Reconnection is owner-authenticated. Repair a removed or missing
            # factor rather than claiming that stale background access is ready.
            opened = vault.unlock_with_device(profile, root=target, factor_id=device_factor)
            if opened != dek:
                device_factor = ""
        except (vault.VaultError, OSError):
            device_factor = ""
    if background and not device_factor:
        try:
            factor = vault.add_device_factor(profile, dek=dek, label=f"{label} background access", root=target)
            device_factor = factor["id"]
        except vault.VaultError as exc:
            raise ManagedError("Background access could not be enabled. Your workspace is safe; try connecting again.",
                               "background-unavailable") from exc
    _register_workspace(root, workspace, label, isolated=workspace != "main", rename_initial=not existing_profile)
    connected = {"installationId": ident, "app": app, "name": label, "workspace": workspace,
                 "publicKey": public, "profile": profile, "background": background, "paused": False,
                 "connectedAt": (previous or {}).get("connectedAt") or stamp(), "deviceFactor": device_factor}
    # Reconnecting the same identity preserves exact agent grants. A revoked
    # installation starts with none; reconnecting never resurrects old authority.
    tx.put("binding", ident, connected)
    answer = broker._signin({"workspace": workspace, "password": password, "duration": "forever", "app": app}, root, None)
    if not answer.get("ok"):
        raise ManagedError("PassBook connected, but could not open this workspace. Please unlock it.", "locked")
    # This names-only ownership marker survives disconnect. Host adapters use
    # it to fail closed instead of falling back to legacy raw-file access when
    # the broker is offline. Failed or merely inspected enrollment never sets it.
    passbook._atomic_write(root / "passbook-managed.json", '{"version":1,"managed":true}\n')
    record(root, connected, "link")
    return {**_state(root, tx, connected, broker), **recovered}


def _public_binding(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {key: binding[key] for key in ("installationId", "app", "name", "workspace", "background", "paused", "connectedAt")}


def _ready(binding: Mapping[str, Any], root: Path, broker: Any) -> str:
    if binding.get("paused") or binding.get("revokedAt"):
        return "paused"
    if broker._held_dek(binding["workspace"])[0] is not None:
        return "ready"
    if binding.get("background"):
        answer = broker._signin({"workspace": binding["workspace"], "profile": binding["profile"],
                                 "device": True, "device_factor": binding.get("deviceFactor", ""),
                                 "app": binding["app"], "duration": "forever"}, root, None)
        if answer.get("ok"):
            return "ready"
    return "locked"


def _public_request(row: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if key not in {
        "installationId", "parameters", "idempotencyKey", "fingerprint", "expiresMs", "grantId", "result", "executing"}}


def _expire(tx: Transaction) -> None:
    for request in tx.all("request"):
        if request["status"] in {"pending", "approved"} and request["expiresMs"] <= now_ms():
            request["status"] = "expired"
            tx.put("request", request["id"], request)


def _state(root: Path, tx: Transaction, binding: Mapping[str, Any] | None, broker: Any) -> dict[str, Any]:
    import passbook_keystore
    _expire(tx)
    ident = (binding or {}).get("installationId")
    requests = [_public_request(row) for row in tx.all("request")
                if ident and row["installationId"] == ident and row["status"] == "pending"]
    grants = [{k: v for k, v in row.items() if k not in {"installationId", "expiresMs", "fingerprint", "createdAt"}}
              for row in tx.all("grant") if ident and row["installationId"] == ident and not row.get("revokedAt")
              and (not row.get("expiresMs") or row["expiresMs"] > now_ms())]
    return {"ok": True, "state": _ready(binding, root, broker) if binding else "unconfigured",
            "binding": _public_binding(binding) if binding else None, "workspaces": _workspace_rows(root),
            "requests": sorted(requests, key=lambda row: row["createdAt"]), "grants": grants,
            "auth": {"password": True, "hostProof": bool(binding),
                     "backgroundAvailable": passbook_keystore.available()}}


def require_request(tx: Transaction, binding: Mapping[str, Any], request_id: Any) -> dict[str, Any]:
    row = tx.get("request", text(request_id, limit=64, required=True))
    if not row or row["installationId"] != binding["installationId"]:
        raise ManagedError("This approval request is no longer available.", "request-not-found")
    if row["expiresMs"] <= now_ms():
        raise ManagedError("This approval request has expired.", "request-expired")
    return row


def _challenge(body: Mapping[str, Any], tx: Transaction, binding: Mapping[str, Any]) -> dict[str, Any]:
    row = require_request(tx, binding, body.get("requestId"))
    if row["status"] != "pending":
        raise ManagedError("This request has already been answered.", "already-resolved")
    scope, decision = body.get("scope"), body.get("decision")
    if scope not in SCOPES or decision not in {"allow", "deny"}:
        raise ManagedError("Choose how to answer this request.")
    if scope == "task" and not row["taskId"]:
        raise ManagedError("This request has no task. Choose Allow once.")
    challenge = {"requestId": row["id"], "requestDigest": row["digest"], "scope": scope,
                 "decision": decision, "challenge": identifier(), "expiresAt": stamp(now_ms() + CHALLENGE_MS)}
    tx.put("challenge", challenge["challenge"], {**challenge, "installationId": binding["installationId"],
                                                "expiresMs": now_ms() + CHALLENGE_MS})
    return {"ok": True, "challenge": challenge}


def _decision(body: Mapping[str, Any], root: Path, tx: Transaction, binding: Mapping[str, Any], broker: Any) -> dict[str, Any]:
    row = require_request(tx, binding, body.get("requestId"))
    challenge = tx.get("challenge", str(body.get("challenge") or ""))
    if (not challenge or challenge["installationId"] != binding["installationId"]
            or challenge["expiresMs"] <= now_ms()
            or any(body.get(key) != challenge[key] for key in ("requestId", "requestDigest", "scope", "decision"))
            or row["digest"] != challenge["requestDigest"]):
        raise ManagedError("Review this request again before approving it.", "invalid-challenge")
    if row["status"] != "pending":
        raise ManagedError("This request has already been answered.", "already-resolved")
    if body.get("password"):
        _password_key(root, binding["workspace"], body["password"])
        opened = broker._signin({"workspace": binding["workspace"], "password": body["password"],
                                  "app": binding["app"]}, root, None)
        if not opened.get("ok"):
            raise ManagedError("The workspace could not be unlocked. Please try again.", "locked")
    elif body.get("ownerVerified") is not True:
        raise ManagedError("Confirm this decision with your passkey or PassBook password.", "authentication-required")
    tx.delete("challenge", challenge["challenge"])
    row["status"] = "approved" if challenge["decision"] == "allow" else "denied"
    if row["status"] == "approved":
        scope = challenge["scope"]
        expires = now_ms() + (CHALLENGE_MS if scope == "once" else TASK_MS) if scope in {"once", "task"} else 0
        grant = {"id": identifier(), "installationId": binding["installationId"], "agentId": row["agentId"],
                 "workspace": row["workspace"], "project": row.get("project", ""),
                 "keys": [] if scope == "all-keys" else row["keys"], "scope": scope,
                 "operation": row["operation"], "destination": row["destination"], "account": row["account"],
                 "taskId": row["taskId"] if scope == "task" else "", "fingerprint": row["fingerprint"],
                 "createdAt": stamp(), "expiresMs": expires, "expiresAt": stamp(expires) if expires else ""}
        tx.put("grant", grant["id"], grant)
        row["grantId"] = grant["id"]
    tx.put("request", row["id"], row)
    record(root, binding, "approve" if row["status"] == "approved" else "denied", row["keys"],
           request_id=row["id"], agent_id=row["agentId"], granted=row["status"] == "approved")
    return {"ok": True, "request": _public_request(row), "state": "ready" if row["status"] == "approved" else "denied"}


def _revoke(body: Mapping[str, Any], root: Path, tx: Transaction, binding: dict[str, Any]) -> dict[str, Any]:
    ident = binding["installationId"]
    grant_id = text(body.get("grantId"), limit=64)
    if grant_id:
        grant = tx.get("grant", grant_id)
        if not grant or grant["installationId"] != ident:
            raise ManagedError("This permission is no longer available.", "grant-not-found")
        grant["revokedAt"] = stamp()
        tx.put("grant", grant_id, grant)
    else:
        binding["paused"] = True
        if body.get("disconnect") is True:
            binding["revokedAt"] = stamp()
            for lease in tx.all("peer-lease"):
                if lease["installationId"] == ident and not lease.get("revokedAt"):
                    lease["revokedAt"] = now_ms()
                    tx.put("peer-lease", lease["recordId"], lease)
        tx.put("binding", ident, binding)
        for grant in tx.all("grant"):
            if grant["installationId"] == ident and not grant.get("revokedAt"):
                grant["revokedAt"] = stamp()
                tx.put("grant", grant["id"], grant)
    for row in tx.all("request"):
        if row["installationId"] == ident and row["status"] in {"pending", "approved"} and (not grant_id or row.get("grantId") == grant_id):
            row["status"] = "cancelled"
            tx.put("request", row["id"], row)
    record(root, binding, "unlink", request_id=grant_id)
    return {"ok": True, "revoked": True}


def pause_workspace(workspace: str, root: Path) -> None:
    """An explicit vault lock must survive later automatic reconnects."""
    store = Store(root)
    if not store.path.exists():
        return
    with store.transaction() as tx:
        for binding in tx.all("binding"):
            if not workspace or binding["workspace"] == workspace:
                binding["paused"] = True
                tx.put("binding", binding["installationId"], binding)


def managed_workspace(workspace: str, root: Path) -> bool:
    store = Store(root)
    if not store.path.exists():
        return False
    with store.transaction() as tx:
        # Disconnect or a second manifest ID for the same file must never
        # reopen the legacy unsigned door. Ownership follows the actual store.
        target = passbook.workspace_env_path(workspace, env_for(root)).resolve()
        return any(row["workspace"] == workspace or
                   workspace_path(root, row["workspace"]).resolve() == target
                   for row in tx.all("binding"))


def handle(envelope: Mapping[str, Any], root: Path, broker: Any) -> dict[str, Any]:
    try:
        action = text(envelope.get("action"), limit=32, required=True)
        store = Store(root)
        with store.transaction() as tx:
            if action in {"authorize-begin", "authorize-inspect", "authorize-decide", "authorize-status", "authorize-cancel"}:
                import passbook_managed_authorize
                return passbook_managed_authorize.handle(action, envelope, root, tx, broker)
            if action in {"state", "begin"} and not envelope.get("signature"):
                return _state(root, tx, None, broker)
            if action == "recovery-pair":
                import passbook_managed_recovery
                body = envelope.get("body")
                if not isinstance(body, dict):
                    raise ManagedError("The recovery connection request is invalid.")
                return passbook_managed_recovery.pair(body, str(envelope.get("installationId") or ""), root, tx)
            if action == "recovery-part":
                import passbook_managed_recovery
                return passbook_managed_recovery.part(envelope, root, tx)
            if action == "connect":
                body = envelope.get("body")
                if not isinstance(body, dict):
                    raise ManagedError("The connection request is invalid.")
                return _connect(body, str(envelope.get("installationId") or ""), root, tx, broker)
            binding = verify(envelope, tx)
            body = verified_body(envelope)
            if action in {"state", "requests"}:
                return _state(root, tx, binding, broker)
            if action == "credential-names":
                from passbook_managed_use import credential_names
                return credential_names(root, binding)
            if action == "revoke":
                return _revoke(body, root, tx, binding)
            if action == "pause":
                if not isinstance(body.get("paused"), bool):
                    raise ManagedError("Choose whether to pause background access.")
                binding["paused"] = body["paused"]
                tx.put("binding", binding["installationId"], binding)
                return _state(root, tx, binding, broker)
            if action in {"peer-authorize", "peer-trust", "peer-refresh", "peer-leases", "peer-revoke"}:
                import passbook_managed_lease
                return passbook_managed_lease.handle(action, body, root, tx, binding, broker)
            if binding.get("paused"):
                raise ManagedError("Background access is paused. Reconnect to resume.", "paused")
            if action == "challenge":
                return _challenge(body, tx, binding)
            if action == "decision":
                return _decision(body, root, tx, binding, broker)
            if action in {"peer-pair", "peer-grant", "peer-accept"}:
                import passbook_managed_peer
                return passbook_managed_peer.handle(action, body, root, tx, binding, broker)
            if action in {"request", "use", "supply-key", "service-values", "service-write", "service-remove"}:
                import passbook_managed_use
                result = passbook_managed_use.handle(action, body, root, tx, binding, broker)
                if "_execute" not in result:
                    return result
            else:
                raise ManagedError("This connection action is not supported.", "unsupported-action")
        # Never hold the approval database lock while waiting for a provider.
        return passbook_managed_use.execute(result["_execute"], root)
    except ManagedError as exc:
        return {"ok": False, "error": str(exc), "code": exc.code}
    except (OSError, ValueError, TypeError, KeyError):
        # Payloads may include a submitted password or credential. Exception
        # reprs are not an acceptable error surface.
        return {"ok": False, "error": "PassBook could not complete this request. Please try again.", "code": "request-failed"}
