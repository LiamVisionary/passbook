# SPDX-License-Identifier: Apache-2.0
"""Desktop-owned app authorization. Links identify requests; they grant nothing.

The requesting installation proves possession before enrollment and on every
poll. An owner password, submitted in the PassBook window, authorizes the exact
saved installation and the workspace/background choice on that window. App
names are protocol labels, not operating-system code-signing attestations.
"""
from __future__ import annotations

from typing import Any, Mapping

from passbook_managed_store import (ManagedError, _verify_proof, identifier,
                                   installation_id, now_ms, verified_body)

LIFETIME_MS = 10 * 60 * 1000
MAX_REQUESTS = 32
MAX_ATTEMPTS = 5


def _summary(row):
    from passbook_integrations import stamp
    status = "expired" if row["expiresMs"] <= now_ms() else row["status"]
    return {"id": row["id"], "status": status, "name": "HivemindOS",
            "code": row["id"][:8].upper(), "expiresAt": stamp(row["expiresMs"])}


def _request(body, tx):
    request_id = body.get("requestId")
    if not isinstance(request_id, str) or len(request_id) != 32:
        raise ManagedError("This app authorization is no longer available.", "request-not-found")
    row = tx.get("authorize", request_id)
    if not row:
        raise ManagedError("This app authorization is no longer available.", "request-not-found")
    return row


def handle(action: str, envelope: Mapping[str, Any], root, tx, broker):
    from passbook_integrations import (_connect, _workspace_rows, text, workspace_path)
    if action == "authorize-begin":
        body = verified_body(envelope)
        if set(body) != {"publicKey", "app"} or body.get("app") != "hivemindos":
            raise ManagedError("This app authorization is not supported.")
        public = text(body.get("publicKey"), limit=64, required=True)
        ident = installation_id(public)
        _verify_proof(envelope, tx, {"installationId": ident, "publicKey": public})
        rows = tx.all("authorize")
        for row in rows:
            if row["expiresMs"] <= now_ms():
                tx.delete("authorize", row["id"])
        rows = [row for row in rows if row["expiresMs"] > now_ms()]
        existing = [row for row in rows if row["installationId"] == ident]
        pending = next((row for row in existing if row["status"] == "pending"), None)
        if pending:
            return {"ok": True, "request": _summary(pending)}
        if len(rows) >= MAX_REQUESTS or any(now_ms() - row["createdMs"] < 10_000 for row in existing):
            raise ManagedError("Wait a moment before starting another app authorization.", "authorization-busy")
        row = {"id": identifier(), "status": "pending", "installationId": ident,
               "publicKey": public, "app": "hivemindos", "createdMs": now_ms(),
               "expiresMs": now_ms() + LIFETIME_MS, "attempts": 0}
        tx.put("authorize", row["id"], row)
        return {"ok": True, "request": _summary(row)}

    signed = action in {"authorize-status", "authorize-cancel"}
    body = verified_body(envelope) if signed else envelope.get("body")
    if not isinstance(body, dict):
        raise ManagedError("This app authorization is invalid.")
    allowed = {"requestId"} if action != "authorize-decide" else {
        "requestId", "decision", "workspace", "createWorkspace", "background", "consent", "password"}
    if set(body) - allowed:
        raise ManagedError("This app authorization contains unsupported information.")
    row = _request(body, tx)
    if signed:
        _verify_proof(envelope, tx, row)
    summary = _summary(row)
    if action == "authorize-status":
        return {"ok": True, "request": summary}
    if action == "authorize-cancel":
        if summary["status"] == "pending":
            row["status"] = "cancelled"
            tx.put("authorize", row["id"], row)
        return {"ok": True, "request": _summary(row)}
    if summary["status"] == "expired":
        raise ManagedError("This app authorization expired. Start again in HivemindOS.", "request-expired")
    if summary["status"] != "pending":
        raise ManagedError("This app authorization has already been answered.", "already-resolved")
    if action == "authorize-inspect":
        import passbook_keystore
        binding = tx.get("binding", row["installationId"])
        return {"ok": True, "request": summary, "workspaces": _workspace_rows(root),
                "workspace": binding["workspace"] if binding and not binding.get("revokedAt") else None,
                "backgroundAvailable": passbook_keystore.available()}
    if action != "authorize-decide":
        raise ManagedError("This app authorization is not supported.")
    if body.get("decision") == "deny":
        # Refusal reduces authority and does not require a password. There is
        # still no enrollment, credential access, or result pickup via the link.
        row["status"] = "denied"
        tx.put("authorize", row["id"], row)
        return {"ok": True, "request": _summary(row)}
    if body.get("decision") != "allow" or body.get("consent") is not True or not isinstance(body.get("background"), bool):
        raise ManagedError("Review and authorize this connection to continue.", "consent-required")
    if row["attempts"] >= MAX_ATTEMPTS or row.get("retryAt", 0) > now_ms():
        raise ManagedError("Wait, then start a new app authorization in HivemindOS.", "authorization-busy")
    workspace = text(body.get("workspace"), limit=64, required=True)
    # An owner-created name is an identifier, never an arbitrary path. _connect
    # also rejects silently moving an existing live binding to another store.
    workspace_path(root, workspace)
    row["attempts"] += 1
    row["retryAt"] = now_ms() + 1000
    tx.put("authorize", row["id"], row)
    try:
        result = _connect({"publicKey": row["publicKey"], "app": row["app"], "name": "HivemindOS",
                           "workspace": workspace, "createWorkspace": body.get("createWorkspace") is True,
                           "background": body["background"], "consent": True, "password": body.get("password")},
                          row["installationId"], root, tx, broker)
    except ManagedError as exc:
        # Return inside the transaction so bounded failed attempts are retained.
        return {"ok": False, "error": str(exc), "code": exc.code}
    row["status"] = "approved"
    tx.put("authorize", row["id"], row)
    return {"ok": True, "request": _summary(row), "binding": result["binding"], "state": result["state"]}
