# SPDX-License-Identifier: Apache-2.0
"""Recover the actual orphan-ciphertext path without replacing it prematurely."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "src"), str(Path(__file__).resolve().parent)]
from test_passbook_integrations import Installation, PASSWORD
import passbook
import passbook_backup as backup
import passbook_broker as broker
import passbook_integrations as managed
import passbook_link as link
import passbook_managed_recovery as recovery
import passbook_managed_store as storage
import passbook_vault as vault

CLI = Path(__file__).resolve().parents[1] / "bin" / "passbook"
VALUE = "synthetic-recovered-value-496"
LOCAL_PASSWORD = "synthetic-new-local-password"


@pytest.fixture
def pending(tmp_path, monkeypatch):
    root = tmp_path / "receiver"
    root.mkdir()
    for name in ("HOME", "USERPROFILE", "HIVE_HOME"):
        monkeypatch.setenv(name, str(root))
    for name in ("HIVE_WORKSPACE", "HIVE_WORKSPACE_ID", "HIVE_ENV_FILES", "APP_SANDBOX_CONTAINER_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PASSBOOK_NO_NOTIFY", "1")
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)
    monkeypatch.setattr(backup, "SCRYPT_N", 1 << 12)
    broker._forget_dek()
    path = root / ".env"
    original = ("# Preserve this file\r\nAPI_KEY=" + vault.seal_value("API_KEY", VALUE, b"a" * 32, profile_id="foreign")
                + "\r\nNEXT_PUBLIC_FLAG=synthetic-config\r\n").encode()
    path.write_bytes(original)
    metadata = b'{"version":2,"profiles":[],"skip":["NEXT_PUBLIC_*"],"ownerNote":"synthetic-preserved"}'
    vault.vault_path(root).write_bytes(metadata)
    timestamps = root / ".env.meta.json"
    timestamps.write_text('{"API_KEY":123}')
    app = Installation(root)
    paired = app.transport({"action": "recovery-pair", "installationId": app.id,
                            "body": {"workspace": "main", "publicKey": app.public}})
    assert paired["ok"], paired
    sender = tmp_path / "sender"
    sender.mkdir()
    grant = link.grant(paired["token"], ["API_KEY"], root=sender, workspace="main",
                       confirm_fingerprint=paired["fingerprint"], resolve_values=lambda wanted: {"API_KEY": VALUE})
    assert app.call("recovery-part", {"recoveryId": paired["recoveryId"], "envelope": grant["envelope"],
                                      "issuerFingerprint": grant["issuer_fingerprint"]})["ok"]
    body = {"workspace": "main", "password": LOCAL_PASSWORD, "recoveryId": paired["recoveryId"],
            "issuerFingerprint": grant["issuer_fingerprint"], "storeDigest": paired["storeDigest"],
            "vaultDigest": paired["vaultDigest"]}
    yield {"root": root, "path": path, "original": original, "metadata": metadata,
           "app": app, "pair": paired, "grant": grant, "body": body}
    broker._forget_dek()


def test_pair_and_staging_leave_orphan_ciphertext_and_metadata_exactly_unchanged(pending):
    p = pending
    assert p["path"].read_bytes() == p["original"]
    assert vault.vault_path(p["root"]).read_bytes() == p["metadata"]
    assert not vault.active_profile_id(root=p["root"])
    with storage.Store(p["root"]).transaction() as tx:
        assert tx.all("binding") == [] and tx.all("grant") == []
    assert VALUE.encode() not in (p["root"] / storage.FILENAME).read_bytes()
    assert p["pair"]["keys"] == ["API_KEY"]


def test_recovery_commits_verified_values_and_keeps_password_encrypted_original_bytes(pending):
    p = pending
    result = p["app"].connect(**p["body"])
    assert result["ok"] and result["state"] == "ready", result
    profile = vault.active_profile_id(root=p["root"])
    dek = vault.unlock_with_password(profile, LOCAL_PASSWORD, root=p["root"])
    stored = passbook.parse_env_text(p["path"].read_text())
    assert vault.unseal_value("API_KEY", stored["API_KEY"], dek, profile_id=profile) == VALUE
    assert stored["NEXT_PUBLIC_FLAG"] == "synthetic-config"
    assert json.loads(vault.vault_path(p["root"]).read_text())["ownerNote"] == "synthetic-preserved"
    assert (p["root"] / ".env.meta.json").read_text() == '{"API_KEY":123}'
    archive = Path(result["recoveryBackup"])
    document = json.loads(backup.decrypt(archive.read_text(), LOCAL_PASSWORD)["keys"]["RECOVERY_SNAPSHOT"])
    assert base64.b64decode(document["originalStore"]) == p["original"]
    assert base64.b64decode(document["originalVault"]) == p["metadata"]
    assert VALUE not in archive.read_text() and "synthetic-config" not in archive.read_text()
    assert p["app"].connect(**p["body"])["code"] == "replayed-recovery"
    committed = p["path"].read_bytes()
    assert p["app"].connect(**p["body"], recoveryRetry=True)["recoveryCompleted"] is True
    assert p["path"].read_bytes() == committed
    assert p["app"].connect(**{**p["body"], "password": "wrong-password"}, recoveryRetry=True)["code"] == "authentication-failed"


@pytest.mark.parametrize("changed", ["store", "vault", "manifest", "fingerprint", "digest"])
def test_recovery_refuses_changed_context_without_overwriting_any_original(pending, changed):
    p = pending
    body = dict(p["body"])
    if changed == "store":
        p["path"].write_bytes(p["original"] + b"# concurrent change\n")
    elif changed == "vault":
        vault.vault_path(p["root"]).write_bytes(p["metadata"] + b"\n")
    elif changed == "manifest":
        (p["root"] / passbook.WORKSPACES_MANIFEST).write_text('{"workspaces":[]}')
    elif changed == "fingerprint":
        body["issuerFingerprint"] = "incorrect"
    else:
        body["storeDigest"] = "0" * 64
    before_store, before_vault = p["path"].read_bytes(), vault.vault_path(p["root"]).read_bytes()
    result = p["app"].connect(**body)
    assert not result["ok"]
    assert p["path"].read_bytes() == before_store and vault.vault_path(p["root"]).read_bytes() == before_vault
    assert not vault.active_profile_id(root=p["root"])


def test_recovery_fails_before_replacement_when_staged_ciphertext_cannot_be_verified(pending, monkeypatch):
    p = pending
    real = vault.seal_value
    monkeypatch.setattr(vault, "seal_value", lambda name, value, dek, **kw: real(name, "synthetic-corrupted-replacement", dek, **kw))
    result = p["app"].connect(**p["body"])
    assert not result["ok"]
    assert p["path"].read_bytes() == p["original"] and vault.vault_path(p["root"]).read_bytes() == p["metadata"]


def test_recovery_resumes_after_store_commit_but_before_app_enrollment(pending, monkeypatch):
    p = pending
    original_register = managed._register_workspace
    monkeypatch.setattr(managed, "_register_workspace", lambda *a, **kw: (_ for _ in ()).throw(OSError("synthetic interruption")))
    result = p["app"].connect(**p["body"])
    assert not result["ok"] and vault.active_profile_id(root=p["root"])
    monkeypatch.setattr(managed, "_register_workspace", original_register)
    assert p["app"].connect(**p["body"])["state"] == "ready"


def test_recovery_resume_repairs_acceptance_fence_after_interrupted_commit(pending, monkeypatch):
    p = pending
    original = link._commit_acceptance
    monkeypatch.setattr(link, "_commit_acceptance", lambda *a, **kw: (_ for _ in ()).throw(OSError("synthetic interruption")))
    assert not p["app"].connect(**p["body"])["ok"]
    assert not link.known_issuer(link.envelope_issuer(p["grant"]["envelope"])["did"], root=p["root"])
    monkeypatch.setattr(link, "_commit_acceptance", original)
    assert p["app"].connect(**p["body"])["state"] == "ready"
    with pytest.raises(link.LinkError, match="already"):
        link._open_accepted(p["grant"]["envelope"], confirm_fingerprint=p["grant"]["issuer_fingerprint"], root=p["root"])


def test_recovery_parts_require_the_saved_installation_and_are_idempotent(pending):
    p = pending
    body = {"recoveryId": p["pair"]["recoveryId"], "envelope": p["grant"]["envelope"],
            "issuerFingerprint": p["grant"]["issuer_fingerprint"]}
    assert p["app"].call("recovery-part", body)["already"] is True
    other = Installation(p["root"])
    assert not other.call("recovery-part", body)["ok"]
    tampered = p["app"].envelope("recovery-part", body)
    tampered["signature"] = storage.b64(b"x" * 64)
    assert p["app"].transport(tampered)["code"] == "invalid-proof"


def test_actual_cli_multipart_recovers_seventy_orphaned_keys_without_manual_broker_commands(tmp_path, monkeypatch):
    roots = [tmp_path / "sender", tmp_path / "receiver"]
    keys = {f"SYNTHETIC_KEY_{index:03}": f"synthetic-value-{index:03}" for index in range(70)}
    def call(root, action, body=None):
        env = {**os.environ, "HIVE_HOME": str(root), "HOME": str(root), "USERPROFILE": str(root),
               "SYNTHETIC_HOST_IDENTITY": "synthetic-protected-host-identity-" + root.name,
               "PASSBOOK_NO_BRIEF": "1", "PASSBOOK_NO_NOTIFY": "1"}
        for name in ("HIVE_WORKSPACE", "HIVE_WORKSPACE_ID", "HIVE_ENV_FILES", "APP_SANDBOX_CONTAINER_ID"):
            env.pop(name, None)
        done = subprocess.run([sys.executable, str(CLI), "integration", "--identity-env", "SYNTHETIC_HOST_IDENTITY", "--json"],
                              input=json.dumps({"action": action, "body": body or {}}), text=True,
                              capture_output=True, env=env, timeout=40)
        assert not done.stderr, "CLI transport must not log input values"
        result = json.loads(done.stdout)
        assert PASSWORD not in done.stdout and LOCAL_PASSWORD not in done.stdout
        return result
    try:
        sender, receiver = roots
        setup = {"app": "hivemindos", "name": "HivemindOS", "workspace": "main", "consent": True,
                 "password": PASSWORD, "background": False}
        assert call(sender, "connect", setup)["ok"]
        batches = [dict(list(keys.items())[offset:offset + 35]) for offset in (0, 35)]
        for batch in batches:
            assert call(sender, "service-write", {"values": batch})["ok"]
        receiver.mkdir(parents=True, exist_ok=True)
        original = (sender / ".env").read_bytes()
        (receiver / ".env").write_bytes(original)
        initial = call(receiver, "connect", {**setup, "password": LOCAL_PASSWORD})
        assert initial["code"] == "workspace-recovery-required"
        paired = call(receiver, "recovery-pair", {"workspace": "main"})
        assert paired["ok"] and len(paired["keys"]) == 70, paired
        for batch in batches:
            granted = call(sender, "peer-grant", {"pairingToken": paired["token"], "confirmFingerprint": paired["fingerprint"],
                           "keys": list(batch), "password": PASSWORD})
            assert granted["ok"], granted
            assert call(receiver, "recovery-part", {"recoveryId": paired["recoveryId"], "envelope": granted["envelope"],
                        "issuerFingerprint": granted["issuerFingerprint"]})["ok"]
            assert (receiver / ".env").read_bytes() == original
        result = call(receiver, "connect", {**setup, "password": LOCAL_PASSWORD, "recoveryId": paired["recoveryId"],
                      "issuerFingerprint": granted["issuerFingerprint"], "storeDigest": paired["storeDigest"],
                      "vaultDigest": paired["vaultDigest"]})
        assert result["ok"] and result["state"] == "ready", result
        profile = vault.active_profile_id(root=receiver)
        dek = vault.unlock_with_password(profile, LOCAL_PASSWORD, root=receiver)
        restored = {key: vault.unseal_value(key, value, dek, profile_id=profile)
                    for key, value in passbook.parse_env_text((receiver / ".env").read_text()).items()}
        assert restored == keys
        receiver_pair = call(receiver, "peer-pair")
        authorized = call(sender, "peer-authorize", {"password": PASSWORD, "pairingToken": receiver_pair["token"],
            "confirmFingerprint": receiver_pair["fingerprint"], "receiverInstallationId": receiver_pair["installationId"],
            "receiverPublicKey": receiver_pair["publicKey"], "keys": list(keys), "allowFutureKeys": False})
        assert authorized["ok"], authorized
        lease = authorized["lease"]
        trusted = call(receiver, "peer-trust", {"password": LOCAL_PASSWORD, "lease": lease,
                                              "recoveryId": paired["recoveryId"], "allowFutureKeys": False})
        assert trusted["ok"] and len(trusted["lease"]["ownedKeys"]) == 70, trusted
        assert call(sender, "service-write", {"values": {"SYNTHETIC_KEY_000": "synthetic-rotated-on-source"}})["ok"]
        proof = call(receiver, "peer-refresh-proof", {"leaseId": lease["id"], "pairingToken": receiver_pair["token"],
                                                     "keys": ["SYNTHETIC_KEY_000"]})
        refreshed = call(sender, "peer-refresh", {"proof": proof["proof"]})
        assert refreshed["ok"], refreshed
        accepted = call(receiver, "peer-accept", {"leaseId": lease["id"], "envelope": refreshed["envelope"],
                        "issuerFingerprint": refreshed["issuerFingerprint"], "idempotencyKey": "synthetic-auto-refresh:0"})
        assert accepted["ok"] and accepted["updated"] == ["SYNTHETIC_KEY_000"], accepted
        value = passbook.parse_env_text((receiver / ".env").read_text())["SYNTHETIC_KEY_000"]
        assert vault.unseal_value("SYNTHETIC_KEY_000", value, dek, profile_id=profile) == "synthetic-rotated-on-source"
        # Renewal performs another additive snapshot, which keeps all existing
        # names. Those empty added/updated receipts must not lose proven ownership.
        assert call(receiver, "service-write", {"values": {"SYNTHETIC_KEY_001": "synthetic-independent-local-edit"}})["ok"]
        for root in roots:
            with storage.Store(root).transaction() as tx:
                for row in tx.all("peer-lease"):
                    row["expiresMs"] = storage.now_ms() - 1
                    tx.put("peer-lease", row["recordId"], row)
        renewal_keys = ["SYNTHETIC_KEY_000", "SYNTHETIC_KEY_001"]
        snapshot = call(sender, "peer-grant", {"pairingToken": receiver_pair["token"], "confirmFingerprint": receiver_pair["fingerprint"],
                        "keys": renewal_keys, "password": PASSWORD})
        receipt = call(receiver, "peer-accept", {"envelope": snapshot["envelope"], "issuerFingerprint": snapshot["issuerFingerprint"],
                       "password": LOCAL_PASSWORD, "idempotencyKey": "synthetic-renewal:0"})
        assert receipt["kept"] == renewal_keys
        renewed = call(sender, "peer-authorize", {"password": PASSWORD, "pairingToken": receiver_pair["token"],
            "confirmFingerprint": receiver_pair["fingerprint"], "receiverInstallationId": receiver_pair["installationId"],
            "receiverPublicKey": receiver_pair["publicKey"], "keys": renewal_keys, "allowFutureKeys": False})["lease"]
        assert call(receiver, "peer-trust", {"password": LOCAL_PASSWORD, "lease": renewed,
                    "idempotencyKeys": ["synthetic-renewal:0"], "allowFutureKeys": False})["ok"]
        assert call(sender, "service-write", {"values": {"SYNTHETIC_KEY_000": "synthetic-renewed-source-value"}})["ok"]
        for key in renewal_keys:
            proof = call(receiver, "peer-refresh-proof", {"leaseId": renewed["id"], "pairingToken": receiver_pair["token"], "keys": [key]})
            refreshed = call(sender, "peer-refresh", {"proof": proof["proof"]})
            result = call(receiver, "peer-accept", {"leaseId": renewed["id"], "envelope": refreshed["envelope"],
                          "issuerFingerprint": refreshed["issuerFingerprint"], "idempotencyKey": "synthetic-renewed-refresh:" + key})
            assert result.get("updated") == [key] if key.endswith("000") else result.get("code") == "peer-sync-conflict"
        current = passbook.parse_env_text((receiver / ".env").read_text())
        assert vault.unseal_value("SYNTHETIC_KEY_000", current["SYNTHETIC_KEY_000"], dek, profile_id=profile) == "synthetic-renewed-source-value"
        assert vault.unseal_value("SYNTHETIC_KEY_001", current["SYNTHETIC_KEY_001"], dek, profile_id=profile) == "synthetic-independent-local-edit"
    finally:
        for root in roots:
            broker.stop(root=root)
