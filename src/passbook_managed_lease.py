# SPDX-License-Identifier: Apache-2.0
"""Bounded owner-approved peer refreshes, using existing installation proofs.

Leases contain public identities, scopes and ciphertext fingerprints only.
Transport locators describe a host; they never authorize an export or import.
"""
from __future__ import annotations

import hashlib
import secrets
from pathlib import Path
from typing import Any, Mapping

import passbook
import passbook_link as link
import passbook_sync as sync
import passbook_vault as vault
from passbook_integrations import _password_key, _ready, text, workspace_path
from passbook_managed_store import (ManagedError, Transaction, _verify_proof, canonical, identifier,
                                   installation_id, now_ms, verified_body)
from passbook_managed_use import _policy_denials, _raw, _values, keys_of

LEASE_MS = 30 * 24 * 60 * 60 * 1000


def _id(binding: Mapping[str, Any], direction: str, lease_id: str) -> str:
    return hashlib.sha256(canonical([binding["installationId"], binding["workspace"], direction, lease_id]).encode()).hexdigest()


def _names(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 2048:
        raise ManagedError("Choose the keys this device may keep updated.")
    return sorted({key for offset in range(0, len(value), 64) for key in keys_of(value[offset:offset + 64])})


def _fingerprint(value: Any) -> str:
    return "".join(text(value, limit=128, required=True).split()).replace("-", "").upper()


def _get(tx: Transaction, binding: Mapping[str, Any], lease_id: Any, direction: str) -> dict[str, Any]:
    row = tx.get("peer-lease", _id(binding, direction, text(lease_id, limit=64, required=True)))
    if not row or row.get("revokedAt") or row["expiresMs"] <= now_ms():
        raise ManagedError("This device permission expired or was revoked. Review the connection again.", "peer-lease-unavailable")
    return row


def _public(row: Mapping[str, Any]) -> dict[str, Any]:
    return {**{key: value for key, value in row.items() if key not in {
        "recordId", "installationId", "receiverPublicKey", "installedVersions"}},
        **({"ownedKeys": sorted(row.get("installedVersions", {}))} if row["direction"] == "receive" else {})}


def _owner(root: Path, binding: Mapping[str, Any], password: Any, broker: Any) -> None:
    _password_key(root, binding["workspace"], password)
    if _ready(binding, root, broker) != "ready":
        if not broker._signin({"workspace": binding["workspace"], "password": password,
                               "app": binding["app"]}, root, None).get("ok"):
            raise ManagedError("Unlock this workspace to connect the device.", "locked")


def _allowed(root: Path, binding: Mapping[str, Any], keys: list[str], broker: Any) -> list[str]:
    policy = broker.read_policy(root)
    denied = set(_policy_denials(root, binding, {}, keys, broker))
    return [key for key in keys if key not in denied and sync.may_leave_machine(key, policy)["allowed"]]


def _authorize(body, root, tx, binding, broker):
    _owner(root, binding, body.get("password"), broker)
    keys = _names(body.get("keys"))
    if _allowed(root, binding, keys, broker) != keys:
        raise ManagedError("Your permissions do not allow this device scope.", "policy-denied")
    public = text(body.get("receiverPublicKey"), limit=64, required=True)
    receiver_id = text(body.get("receiverInstallationId"), limit=64, required=True)
    if installation_id(public) != receiver_id:
        raise ManagedError("The receiving app's identity is invalid.", "invalid-proof")
    paired = link.read_pairing_token(text(body.get("pairingToken"), limit=4096, required=True))
    if not secrets.compare_digest(_fingerprint(paired["fingerprint"]), _fingerprint(body.get("confirmFingerprint"))):
        raise ManagedError("The receiving device could not be verified.", "peer-verification-failed")
    own = link.describe_identity(root=root)
    lease_id = identifier()
    row = {"id": lease_id, "direction": "send", "installationId": binding["installationId"],
           "workspace": binding["workspace"], "keys": keys, "allowFutureKeys": body.get("allowFutureKeys") is True,
           "expiresMs": now_ms() + LEASE_MS, "senderDid": own["did"], "senderFingerprint": own["fingerprint"],
           "receiverDid": paired["did"], "receiverFingerprint": paired["fingerprint"],
           "receiverInstallationId": receiver_id, "receiverPublicKey": public}
    row["recordId"] = _id(binding, "send", lease_id)
    tx.put("peer-lease", row["recordId"], row)
    return {"ok": True, "lease": _public(row)}


def _trust(body, root, tx, binding, broker):
    _owner(root, binding, body.get("password"), broker)
    incoming = body.get("lease")
    if not isinstance(incoming, dict):
        raise ManagedError("The sending device permission is invalid.")
    own = link.describe_identity(root=root)
    lease_id = text(incoming.get("id"), limit=64, required=True)
    keys = _names(incoming.get("keys"))
    expires = incoming.get("expiresMs")
    if (incoming.get("receiverInstallationId") != binding["installationId"]
            or incoming.get("receiverDid") != own["did"]
            or _fingerprint(incoming.get("receiverFingerprint")) != _fingerprint(own["fingerprint"])
            or isinstance(expires, bool) or not isinstance(expires, int) or not now_ms() < expires <= now_ms() + LEASE_MS):
        raise ManagedError("This device permission does not match this receiver.", "peer-verification-failed")
    future = incoming.get("allowFutureKeys") is True
    if future and body.get("allowFutureKeys") is not True:
        raise ManagedError("Approve future keys separately before enabling this scope.", "consent-required")
    sender_did = text(incoming.get("senderDid"), limit=128, required=True)
    link.public_from_did(sender_did)
    fingerprint = text(incoming.get("senderFingerprint"), limit=128, required=True)
    source_workspace = text(incoming.get("workspace"), limit=64, required=True)
    if _policy_denials(root, binding, {}, keys, broker) or any(sync.is_local_only(key) for key in keys):
        raise ManagedError("Your permissions do not allow this device scope.", "policy-denied")
    # Fresh owner approval may renew an expired permission. A repeated additive
    # import keeps existing entries, so its receipt alone has no owned versions.
    # Reuse only fingerprints previously recorded for this exact relationship;
    # never acquire authority over a local value merely because it is present.
    previous_rows = [row for row in tx.all("peer-lease") if row.get("direction") == "receive"
        and row.get("installationId") == binding["installationId"] and row.get("workspace") == binding["workspace"]
        and row.get("senderDid") == sender_did and row.get("sourceWorkspace") == source_workspace
        and _fingerprint(row.get("senderFingerprint")) == _fingerprint(fingerprint)]
    versions = {}
    for previous in sorted(previous_rows, key=lambda row: (row.get("lastImportedAt", 0), row["expiresMs"])):
        versions.update({key: value for key, value in previous.get("installedVersions", {}).items() if key in keys})
    current = _raw(root, binding["workspace"])
    for previous in previous_rows:
        for key, version in previous.get("installedVersions", {}).items():
            if key in keys and vault.is_sealed(current.get(key, "")) and hashlib.sha256(current[key].encode()).hexdigest() == version:
                versions[key] = version
    retries = body.get("idempotencyKeys", [])
    if not isinstance(retries, list) or len(retries) > 64:
        raise ManagedError("The completed imports could not be verified.")
    for retry in retries:
        receipt_id = hashlib.sha256(canonical([binding["installationId"], binding["workspace"],
                                               text(retry, limit=128, required=True)]).encode()).hexdigest()
        receipt = tx.get("peer-receipt", receipt_id)
        if (not receipt or receipt.get("issuerDid") != sender_did
                or _fingerprint(receipt.get("issuerFingerprint")) != _fingerprint(fingerprint)):
            raise ManagedError("The completed import does not match this device.", "peer-verification-failed")
        versions.update(receipt.get("installedVersions", {}))
    if body.get("recoveryId"):
        recovery = tx.get("recovery", text(body["recoveryId"], limit=64, required=True))
        if (not recovery or recovery.get("status") != "committed"
                or recovery["installationId"] != binding["installationId"] or recovery["workspace"] != binding["workspace"]
                or any(_fingerprint(item["fingerprint"]) != _fingerprint(fingerprint) for item in recovery["parts"])):
            raise ManagedError("The completed recovery does not match this device.", "peer-verification-failed")
        versions.update(recovery.get("installedVersions", {}))
    if not retries and not body.get("recoveryId"):
        raise ManagedError("Receive the reviewed initial snapshot before enabling updates.", "peer-verification-failed")
    transport = body.get("transport")
    if transport is not None:
        if not isinstance(transport, dict) or set(transport) != {"kind", "peerId", "name"} or transport.get("kind") != "hivemind-link":
            raise ManagedError("The device transport locator is invalid.")
        transport = {"kind": "hivemind-link", "peerId": text(transport["peerId"], limit=256, required=True),
                     "name": text(transport["name"], limit=100, required=True)}
    row = {"id": lease_id, "direction": "receive", "installationId": binding["installationId"],
           "workspace": binding["workspace"], "sourceWorkspace": source_workspace,
           "keys": keys, "allowFutureKeys": future, "expiresMs": expires, "senderDid": sender_did,
           "senderFingerprint": fingerprint, "receiverDid": own["did"], "receiverFingerprint": own["fingerprint"],
           "receiverInstallationId": binding["installationId"], "transport": transport,
           "installedVersions": {key: value for key, value in versions.items() if key in keys}, "lastImportedAt": now_ms()}
    row["recordId"] = _id(binding, "receive", lease_id)
    previous = tx.get("peer-lease", row["recordId"])
    if previous and previous.get("revokedAt"):
        raise ManagedError("This device permission was stopped. Review a new connection to resume updates.", "peer-lease-unavailable")
    if previous:
        if any(previous[key] != row[key] for key in ("senderDid", "senderFingerprint", "keys", "allowFutureKeys", "expiresMs")):
            raise ManagedError("This permission retry changed its scope.", "idempotency-conflict")
        return {"ok": True, "lease": _public(previous)}
    # Fresh owner approval replaces this source relationship, including keys
    # no longer selected. Two active writers would otherwise invalidate each
    # other's ciphertext fingerprints on every maintenance pass. A retry of
    # the same permission returns above and never changes another permission.
    for prior in previous_rows:
        if not prior.get("revokedAt"):
            prior["revokedAt"] = now_ms()
            tx.put("peer-lease", prior["recordId"], prior)
    tx.put("peer-lease", row["recordId"], row)
    return {"ok": True, "lease": _public(row)}


def _refresh(body, root, tx, binding, broker):
    proof = body.get("proof")
    if not isinstance(proof, dict) or proof.get("action") != "peer-refresh-proof":
        raise ManagedError("The receiving device proof is invalid.", "invalid-proof")
    request = verified_body(proof)
    if set(request) != {"leaseId", "pairingToken", "keys"}:
        raise ManagedError("The receiving device proof is invalid.", "invalid-proof")
    row = _get(tx, binding, request.get("leaseId"), "send")
    _verify_proof(proof, tx, {"installationId": row["receiverInstallationId"], "publicKey": row["receiverPublicKey"]})
    paired = link.read_pairing_token(text(request.get("pairingToken"), limit=4096, required=True))
    if paired["did"] != row["receiverDid"] or _fingerprint(paired["fingerprint"]) != _fingerprint(row["receiverFingerprint"]):
        raise ManagedError("This permission belongs to another receiving device.", "peer-verification-failed")
    if _ready(binding, root, broker) != "ready":
        raise ManagedError("The sending workspace is locked. Open it to resume updates.", "locked")
    raw = _raw(root, binding["workspace"])
    skip = vault.skip_list(root=workspace_path(root, binding["workspace"]).parent)
    present = sorted(key for key, value in raw.items() if value and
                     (value.startswith("hive-sealed:") or not vault.matches_skip(key, skip)))
    allowed = _allowed(root, binding, present if row["allowFutureKeys"] else row["keys"], broker)
    if request["keys"] == []:
        return {"ok": True, "leaseId": row["id"], "keys": sorted(set(present) & set(allowed)),
                "missing": sorted(set(row["keys"]) - set(present)), "expiresMs": row["expiresMs"]}
    keys = keys_of(request["keys"])
    if not set(keys) <= set(allowed):
        raise ManagedError("This refresh exceeds the approved device scope.", "policy-denied")
    if not set(keys) <= set(present):
        raise ManagedError("The source removed a requested key. Its saved local copy was retained.", "source-missing")
    result = link.grant(request["pairingToken"], keys, confirm_fingerprint=row["receiverFingerprint"],
                        root=root, workspace=binding["workspace"], resolve_values=lambda wanted: _values(root, binding["workspace"], wanted, broker))
    if len(result["envelope"]) > 40_000:
        raise ManagedError("Refresh fewer keys at a time.", "peer-transfer-too-large")
    return {"ok": True, "leaseId": row["id"], "envelope": result["envelope"], "keys": result["keys"],
            "issuerFingerprint": result["issuer_fingerprint"], "expires": result["expires"]}


def acceptance(tx: Transaction, binding: Mapping[str, Any], lease_id: Any, issuer: Mapping[str, Any]) -> dict[str, Any]:
    row = _get(tx, binding, lease_id, "receive")
    if (issuer["did"] != row["senderDid"] or _fingerprint(issuer["fingerprint"]) != _fingerprint(row["senderFingerprint"])
            or not row["allowFutureKeys"] and not set(issuer["keys"]) <= set(row["keys"])
            or any(cap.get("with") != "passbook://" + row["sourceWorkspace"]
                   for cap in issuer["_parsed"]["grant"].get("att", []) if cap.get("can") == "env/read") ):
        raise ManagedError("This encrypted snapshot exceeds the trusted device permission.", "peer-verification-failed")
    return row


def handle(action, body, root, tx, binding, broker):
    fields = {"peer-authorize": {"password", "pairingToken", "confirmFingerprint", "receiverInstallationId", "receiverPublicKey", "keys", "allowFutureKeys"},
              "peer-trust": {"password", "lease", "allowFutureKeys", "idempotencyKeys", "recoveryId", "transport"},
              "peer-refresh": {"proof"}, "peer-leases": set(), "peer-revoke": {"leaseId"}}
    if action not in fields or set(body) - fields[action]:
        raise ManagedError("This device permission request is invalid.")
    if action == "peer-leases":
        return {"ok": True, "leases": [{**_public(row), "active": not binding.get("paused") and not row.get("revokedAt") and row["expiresMs"] > now_ms()}
                for row in tx.all("peer-lease") if row["installationId"] == binding["installationId"] and row["workspace"] == binding["workspace"]]}
    if action == "peer-revoke":
        for direction in ("send", "receive"):
            ident = _id(binding, direction, text(body.get("leaseId"), limit=64, required=True))
            row = tx.get("peer-lease", ident)
            if row:
                row["revokedAt"] = now_ms()
                tx.put("peer-lease", ident, row)
        return {"ok": True, "revoked": True}
    if binding.get("paused") or binding.get("revokedAt"):
        raise ManagedError("Resume this connection before updating another device.", "paused")
    try:
        return {"peer-authorize": _authorize, "peer-trust": _trust, "peer-refresh": _refresh}[action](body, root, tx, binding, broker)
    except link.LinkError as exc:
        raise ManagedError(str(exc), "peer-verification-failed") from exc
