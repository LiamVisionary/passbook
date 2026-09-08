# SPDX-License-Identifier: Apache-2.0
"""Staged, owner-authorized recovery of ciphertext without a local profile.

Only public metadata and peer ciphertext enter SQLite. The original file bytes
are retained in the existing password-encrypted backup format before replacement.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from pathlib import Path
from typing import Any, Mapping

import passbook
import passbook_backup as backup
import passbook_link as link
import passbook_vault as vault
from passbook_managed_store import (ManagedError, Transaction, _verify_proof, canonical, identifier,
                                   installation_id, now_ms, verified_body)

MAX_BYTES = 2 * 1024 * 1024
MAX_PARTS = 64
TTL_MS = 10 * 60 * 1000
MAX_ARCHIVE_BYTES = MAX_BYTES * 8


def _digest(value: bytes | None) -> str:
    return hashlib.sha256(b"absent" if value is None else b"present\0" + value).hexdigest()


def _read(path: Path) -> bytes | None:
    if path.is_symlink():
        raise ManagedError("This workspace cannot be recovered safely.", "workspace-recovery-required")
    try:
        with path.open("rb") as stream:
            value = stream.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(value) > MAX_BYTES:
        raise ManagedError("This workspace is too large for this recovery connection.", "recovery-too-large")
    return value


def _snapshot(root: Path, workspace: str) -> dict[str, Any]:
    from passbook_integrations import workspace_path
    path = workspace_path(root, workspace)
    raw, meta = _read(path), _read(vault.vault_path(path.parent))
    manifest = _read(root / passbook.WORKSPACES_MANIFEST)
    return {"store": raw, "vault": meta, "manifest": manifest,
            "storeDigest": _digest(raw), "vaultDigest": _digest(meta), "manifestDigest": _digest(manifest)}


def _orphans(snapshot: Mapping[str, Any]) -> list[str]:
    try:
        meta = json.loads(snapshot["vault"]) if snapshot["vault"] else {}
        if (not isinstance(meta, dict) or meta.get("profiles") or meta.get("active")
                or meta.get("version", vault.VAULT_VERSION) != vault.VAULT_VERSION):
            raise ManagedError("This workspace already has a vault. Unlock it to connect.", "recovery-not-required")
        original = (snapshot["store"] or b"").decode("utf-8")
    except ManagedError:
        raise
    except (ValueError, UnicodeError) as exc:
        raise ManagedError("This workspace needs its original recovery files.", "workspace-recovery-required") from exc
    names = set()
    for line in original.splitlines():
        for key, value in passbook.parse_env_text(line).items():
            if value.startswith("hive-sealed:"):
                if not vault.is_sealed(value):
                    raise ManagedError("This workspace uses an older encrypted format. Recover it on its original device.",
                                       "workspace-recovery-required")
                names.add(key)
    if not names:
        raise ManagedError("This workspace can connect directly without recovery.", "recovery-not-required")
    current = passbook.parse_env_text(original)
    if any(not vault.is_sealed(current[key]) for key in names):
        raise ManagedError("This workspace contains conflicting entries. Its original files were preserved.",
                           "workspace-recovery-required")
    return sorted(names)


def pair(body: Mapping[str, Any], ident: str, root: Path, tx: Transaction) -> dict[str, Any]:
    from passbook_integrations import text
    public = text(body.get("publicKey"), limit=64, required=True)
    if installation_id(public) != ident:
        raise ManagedError("The app's identity could not be verified.", "invalid-proof")
    workspace = text(body.get("workspace") or "main", limit=64)
    snapshot = _snapshot(root, workspace)
    names = _orphans(snapshot)
    pending = []
    for row in tx.all("recovery"):
        if row["expiresMs"] <= now_ms():
            tx.delete("recovery", row["id"])
        elif row.get("status") != "committed":
            pending.append(row)
            if row["installationId"] == ident and row["workspace"] == workspace:
                if all(row[key] == snapshot[key] for key in ("storeDigest", "vaultDigest", "manifestDigest")):
                    return _public(row)
                tx.delete("recovery", row["id"])
    if len(pending) >= 4:
        raise ManagedError("Finish the current device connections before starting another.", "recovery-limit")
    token = link.pairing_token(root=root)
    row = {"id": identifier(), "installationId": ident, "publicKey": public, "workspace": workspace,
           "keys": names, "expiresMs": now_ms() + TTL_MS, "parts": [], "status": "pending", **token,
           **{key: snapshot[key] for key in ("storeDigest", "vaultDigest", "manifestDigest")}}
    tx.put("recovery", row["id"], row)
    return _public(row)


def _public(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"ok": True, "recoveryId": row["id"], **{key: row[key] for key in
            ("workspace", "keys", "token", "fingerprint", "did", "expires", "storeDigest", "vaultDigest")}}


def _row(tx: Transaction, ident: str, recovery_id: Any, *, allow_committed: bool = False) -> dict[str, Any]:
    row = tx.get("recovery", str(recovery_id or ""))
    if not row or row["installationId"] != ident or row["expiresMs"] <= now_ms():
        raise ManagedError("This recovery connection expired. Start it again.", "recovery-expired")
    if row["status"] == "committed" and not allow_committed:
        raise ManagedError("This recovery connection has already been completed.", "replayed-recovery")
    return row


def _fingerprint(value: str) -> str:
    return "".join(value.split()).upper().replace("-", "")


def part(envelope: Mapping[str, Any], root: Path, tx: Transaction) -> dict[str, Any]:
    from passbook_integrations import text
    body = verified_body(envelope)
    row = _row(tx, str(envelope.get("installationId") or ""), body.get("recoveryId"))
    _verify_proof(envelope, tx, row)
    value = text(body.get("envelope"), limit=40_000, required=True)
    fingerprint = text(body.get("issuerFingerprint"), limit=128, required=True)
    try:
        issuer = link.envelope_issuer(value)
    except link.LinkError as exc:
        raise ManagedError(str(exc), "peer-verification-failed") from exc
    if (not secrets.compare_digest(_fingerprint(fingerprint), _fingerprint(issuer["fingerprint"]))
            or issuer["_parsed"]["grant"].get("aud") != row["did"]):
        raise ManagedError("The device transfer could not be verified.", "peer-verification-failed")
    if not issuer["keys"] or not set(issuer["keys"]) <= set(row["keys"]):
        raise ManagedError("This transfer does not match the keys needing recovery.", "recovery-key-mismatch")
    digest = hashlib.sha256(value.encode()).hexdigest()
    if any(item["digest"] == digest for item in row["parts"]):
        return {"ok": True, "recoveryId": row["id"], "already": True}
    prior_keys = {key for item in row["parts"] for key in item["keys"]}
    if prior_keys.intersection(issuer["keys"]):
        raise ManagedError("This transfer repeats keys already received.", "recovery-key-mismatch")
    if len(row["parts"]) >= MAX_PARTS or sum(len(item["envelope"]) for item in row["parts"]) + len(value) > MAX_BYTES:
        raise ManagedError("This recovery connection is too large.", "recovery-too-large")
    row["parts"].append({"envelope": value, "digest": digest, "fingerprint": issuer["fingerprint"], "keys": issuer["keys"]})
    tx.put("recovery", row["id"], row)
    return {"ok": True, "recoveryId": row["id"], "received": sorted(prior_keys | set(issuer["keys"]))}


def recover(body: Mapping[str, Any], ident: str, root: Path, tx: Transaction) -> dict[str, Any]:
    from passbook_integrations import workspace_path
    row = _row(tx, ident, body.get("recoveryId"), allow_committed=body.get("recoveryRetry") is True)
    with passbook.store_lock(workspace_path(root, row["workspace"])):
        return _recover(body, ident, root, tx)


def _recover(body: Mapping[str, Any], ident: str, root: Path, tx: Transaction) -> dict[str, Any]:
    from passbook_integrations import _password_key, text, workspace_path
    row = _row(tx, ident, body.get("recoveryId"), allow_committed=body.get("recoveryRetry") is True)
    if (body.get("workspace") != row["workspace"] or installation_id(str(body.get("publicKey") or "")) != ident
            or any(body.get(key) != row[key] for key in ("storeDigest", "vaultDigest"))):
        raise ManagedError("This workspace changed during recovery. Start the connection again.", "recovery-changed")
    password = body.get("password")
    if not isinstance(password, str) or not 8 <= len(password) <= 4096:
        raise ManagedError("Choose a local PassBook password of at least 8 characters.", "authentication-required")
    fingerprint = text(body.get("issuerFingerprint"), limit=128, required=True)
    if (not row["parts"] or any(not secrets.compare_digest(_fingerprint(fingerprint), _fingerprint(item["fingerprint"]))
                               for item in row["parts"])):
        raise ManagedError("The sending device could not be verified.", "peer-verification-failed")
    if row["status"] == "committed":
        _, profile = _password_key(root, row["workspace"], password)
        binding = tx.get("binding", ident)
        if not binding or binding["workspace"] != row["workspace"] or profile != row.get("profile"):
            raise ManagedError("This recovery no longer matches the connected workspace.", "recovery-changed")
        return {"recovered": row["keys"], "recoveryCompleted": True}
    if {key for item in row["parts"] for key in item["keys"]} != set(row["keys"]):
        raise ManagedError("Some encrypted keys have not arrived. Nothing was replaced.", "recovery-incomplete")
    path = workspace_path(root, row["workspace"])
    snapshot = _snapshot(root, row["workspace"])
    directory = root / ".passbook-recovery"
    archive = directory / (row["id"] + ".passbook")
    if directory.is_symlink() or archive.is_symlink():
        raise ManagedError("The recovery backup cannot be saved safely.", "workspace-recovery-required")
    saved = None
    if archive.exists():
        try:
            with archive.open("r", encoding="utf-8") as stream:
                sealed_backup = stream.read(MAX_ARCHIVE_BYTES + 1)
            if len(sealed_backup) > MAX_ARCHIVE_BYTES:
                raise ManagedError("The recovery backup is too large to verify safely.", "recovery-too-large")
            saved = json.loads(backup.decrypt(sealed_backup, password)["keys"]["RECOVERY_SNAPSHOT"])
        except ManagedError:
            raise
        except (backup.BackupError, ValueError, KeyError) as exc:
            raise ManagedError("Use the local password chosen when this recovery began.", "authentication-failed") from exc
        if saved["recoveryId"] != row["id"] or saved["partDigests"] != [item["digest"] for item in row["parts"]]:
            raise ManagedError("The recovery backup does not match this connection.", "recovery-changed")
        if snapshot["storeDigest"] == saved["plannedStoreDigest"] and snapshot["vaultDigest"] == saved["plannedVaultDigest"]:
            # The replacement committed but app enrollment was interrupted.
            # The password-protected backup binds these exact verified bytes.
            for item in row["parts"]:
                issuer = link.envelope_issuer(item["envelope"])
                if (hashlib.sha256(item["envelope"].encode()).hexdigest() != item["digest"]
                        or issuer["_parsed"]["grant"].get("aud") != row["did"]
                        or set(issuer["keys"]) != set(item["keys"])
                        or _fingerprint(issuer["fingerprint"]) != _fingerprint(fingerprint)):
                    raise ManagedError("The recovery snapshot no longer matches this connection.", "recovery-changed")
                link._commit_acceptance(issuer["_parsed"]["grant"], item["keys"], root=root, workspace=row["workspace"])
            row["status"] = "committed"
            row["profile"] = vault.active_profile_id(root=path.parent)
            row["installedVersions"] = _versions(snapshot["store"], row["keys"])
            tx.put("recovery", row["id"], row)
            return {"recovered": row["keys"], "recoveryBackup": str(archive)}
        if snapshot["storeDigest"] == row["storeDigest"] and snapshot["vaultDigest"] == saved["plannedVaultDigest"]:
            # Interrupted between installing the new vault and replacing its
            # store. Restore only our exact planned vault, never another writer.
            original = saved["originalVault"]
            if original is None:
                vault.vault_path(path.parent).unlink()
            else:
                passbook._atomic_write(vault.vault_path(path.parent), base64.b64decode(original).decode("utf-8"), newline="")
            snapshot = _snapshot(root, row["workspace"])
    if any(snapshot[key] != row[key] for key in ("storeDigest", "vaultDigest", "manifestDigest")):
        raise ManagedError("This workspace changed during recovery. Its files were preserved.", "recovery-changed")
    _orphans(snapshot)
    values, accepted = {}, []
    try:
        for item in row["parts"]:
            grant, incoming = link._open_accepted(item["envelope"], confirm_fingerprint=fingerprint, root=root)
            if set(incoming) != set(item["keys"]) or any(not isinstance(value, str) or not value.strip()
                    or value.strip().startswith("hive-sealed:") for value in incoming.values()):
                raise ManagedError("The device did not provide usable recovery values.", "recovery-key-mismatch")
            values.update(incoming)
            accepted.append((grant, sorted(incoming)))
        if set(values) != set(row["keys"]):
            raise ManagedError("Some encrypted keys have not arrived.", "recovery-incomplete")

        def retain_original(planned_vault: bytes, planned_store: bytes) -> None:
            data = {"recoveryId": row["id"], "partDigests": [item["digest"] for item in row["parts"]],
                    "originalStore": base64.b64encode(snapshot["store"]).decode(),
                    "originalVault": base64.b64encode(snapshot["vault"]).decode() if snapshot["vault"] is not None else None,
                    "originalManifest": base64.b64encode(snapshot["manifest"]).decode() if snapshot["manifest"] is not None else None,
                    "plannedStoreDigest": _digest(planned_store), "plannedVaultDigest": _digest(planned_vault)}
            sealed = backup.encrypt({"RECOVERY_SNAPSHOT": canonical(data)}, password,
                                    workspace=row["workspace"], note="Private original-file recovery snapshot")
            if backup.decrypt(sealed, password)["keys"]["RECOVERY_SNAPSHOT"] != canonical(data):
                raise ManagedError("The recovery backup could not be verified.")
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.chmod(0o700)
            passbook._atomic_write(archive, sealed)

        vault.initialize_store(password, root=path.parent, path=path,
                               expected=snapshot["store"].decode("utf-8").replace("\r\n", "\n").replace("\r", "\n"),
                               recovered=values, before_commit=retain_original)
        for grant, keys in accepted:
            link._commit_acceptance(grant, keys, root=root, workspace=row["workspace"])
    except (link.LinkError, vault.VaultError, backup.BackupError) as exc:
        raise ManagedError("The recovery could not be verified. Its original files are preserved.", "workspace-recovery-required") from exc
    row["status"] = "committed"
    row["profile"] = vault.active_profile_id(root=path.parent)
    row["installedVersions"] = _versions(path.read_bytes(), row["keys"])
    tx.put("recovery", row["id"], row)
    return {"recovered": row["keys"], "recoveryBackup": str(archive)}


def _versions(raw: bytes, keys: list[str]) -> dict[str, str]:
    values = passbook.parse_env_text(raw.decode("utf-8"))
    return {key: hashlib.sha256(values[key].encode()).hexdigest() for key in keys
            if key in values and vault.is_sealed(values[key])}
