# SPDX-License-Identifier: Apache-2.0
"""Owner-approved encrypted peer snapshots for already-connected workspaces.

The caller verifies the installation signature in the normal managed dispatcher.
Transport and the owner's comparison of device identities remain host duties;
Tailnet reachability alone never approves an export or an import here.
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
from passbook_integrations import _password_key, _ready, env_for, text, workspace_path
from passbook_managed_store import ManagedError, Transaction, canonical, now_ms
from passbook_managed_use import _policy_denials, _values, keys_of


def handle(action: str, body: Mapping[str, Any], root: Path, tx: Transaction,
           binding: Mapping[str, Any], broker: Any) -> dict[str, Any]:
    """Execute after managed signature verification, under its transaction."""
    fields = {
        "peer-pair": set(),
        "peer-grant": {"pairingToken", "keys", "confirmFingerprint", "password"},
        "peer-accept": {"envelope", "issuerFingerprint", "password", "idempotencyKey", "leaseId"},
    }
    if action not in fields or set(body) - fields[action]:
        raise ManagedError("This device connection request is invalid.")
    if binding.get("paused") or binding.get("revokedAt"):
        raise ManagedError("Resume this connection before connecting another device.", "paused")
    workspace = binding["workspace"]
    try:
        if action == "peer-pair":
            return {"ok": True, "workspace": workspace, "installationId": binding["installationId"],
                    "publicKey": binding["publicKey"], **link.pairing_token(root=root)}

        # A host installation's signature is not an owner's fresh approval.
        # Authenticate without shortening or replacing an existing vault grant.
        lease = None
        if action == "peer-accept" and body.get("leaseId"):
            from passbook_managed_lease import acceptance
            lease = acceptance(tx, binding, body["leaseId"], link.envelope_issuer(
                text(body.get("envelope"), limit=40_000, required=True)))
        else:
            _password_key(root, workspace, body.get("password"))
        if _ready(binding, root, broker) != "ready":
            if lease:
                raise ManagedError("The receiving workspace is locked. Open it to resume updates.", "locked")
            opened = broker._signin({"workspace": workspace, "password": body["password"],
                                     "app": binding["app"]}, root, None)
            if not opened.get("ok"):
                raise ManagedError("Unlock this workspace before connecting another device.", "locked")

        if action == "peer-grant":
            keys = keys_of(body.get("keys"))
            policy = broker.read_policy(root)
            if (_policy_denials(root, binding, {}, keys, broker)
                    or any(not sync.may_leave_machine(key, policy)["allowed"] for key in keys)):
                raise ManagedError("Your key permissions do not allow this device connection.", "policy-denied")
            result = link.grant(
                text(body.get("pairingToken"), limit=4096, required=True), keys,
                confirm_fingerprint=text(body.get("confirmFingerprint"), limit=128, required=True),
                workspace=workspace, root=root,
                resolve_values=lambda wanted: _values(root, workspace, wanted, broker),
            )
            if len(result["envelope"]) > 40_000:
                raise ManagedError("Connect fewer keys at a time to fit this device transfer.", "peer-transfer-too-large")
            return {"ok": True, "workspace": workspace, "envelope": result["envelope"],
                    "keys": result["keys"], "fingerprint": result["fingerprint"],
                    "issuerFingerprint": result["issuer_fingerprint"], "expires": result["expires"]}

        envelope = text(body.get("envelope"), limit=40_000, required=True)
        issuer = link.envelope_issuer(envelope)
        confirmed = text(body.get("issuerFingerprint"), limit=128, required=True)
        normalize = lambda value: "".join(value.split()).upper().replace("-", "")
        # Even an established issuer must be the device selected for THIS
        # transfer; known_issuer is not permission to accept a different peer.
        if not secrets.compare_digest(normalize(confirmed), normalize(issuer["fingerprint"])):
            raise ManagedError("The sending device could not be verified.", "peer-verification-failed")
        keys = keys_of(issuer["keys"])
        if (_policy_denials(root, binding, {}, keys, broker)
                or any(sync.is_local_only(key) for key in keys)):
            raise ManagedError("Your key permissions do not allow this device connection.", "policy-denied")

        retry_key = text(body.get("idempotencyKey"), limit=128)
        receipt_id = hashlib.sha256(canonical([binding["installationId"], workspace, retry_key]).encode()).hexdigest()
        digest = hashlib.sha256(envelope.encode()).hexdigest()
        if retry_key:
            previous = tx.get("peer-receipt", receipt_id)
            if previous:
                if not secrets.compare_digest(previous["envelopeDigest"], digest):
                    raise ManagedError("This transfer retry names a different encrypted snapshot.", "idempotency-conflict")
                return previous["result"]

        def encrypted_writer(values: dict[str, str]) -> Mapping[str, Any]:
            if set(values) != set(keys) or any(len(value) > 32_000 or any(c in value for c in "\0\r\n")
                                               for value in values.values()):
                raise ManagedError("The sending device did not provide the requested keys.")
            dek, profile = broker._held_dek(workspace)
            if dek is None or not profile:
                raise ManagedError("Unlock this workspace before saving the keys.", "locked")
            sealed = {key: vault.seal_value(key, value, dek, profile_id=profile) for key, value in values.items()}
            try:
                written = passbook.set_values(sealed, environ=env_for(root, workspace),
                        path=workspace_path(root, workspace), overwrite=bool(lease),
                        expected_versions={key: lease["installedVersions"].get(key) for key in keys} if lease else None)
            except ValueError as exc:
                if lease:
                    raise ManagedError("A key changed locally. Its local value was preserved.", "peer-sync-conflict") from exc
                raise
            return {**written, "workspace": workspace}

        with passbook.store_lock(workspace_path(root, workspace)):
            result = link.accept(envelope, confirm_fingerprint=confirmed, root=root, write_values=encrypted_writer)
            raw = passbook.parse_env_text(workspace_path(root, workspace).read_text(encoding="utf-8"))
            versions = {key: hashlib.sha256(raw[key].encode()).hexdigest() for key in result["added"] + result["updated"]
                        if key in raw and vault.is_sealed(raw[key])}
        safe_result = {"ok": True, **{key: result[key] for key in ("keys", "added", "kept", "updated", "workspace", "expires")}}
        if retry_key:
            tx.put("peer-receipt", receipt_id, {"envelopeDigest": digest, "result": safe_result,
                   "issuerDid": issuer["did"], "issuerFingerprint": issuer["fingerprint"], "installedVersions": versions})
        if lease:
            lease["installedVersions"].update(versions)
            lease["lastImportedAt"] = now_ms()
            tx.put("peer-lease", lease["recordId"], lease)
        return safe_result
    except link.LinkError as exc:
        raise ManagedError(str(exc), "peer-verification-failed") from exc
