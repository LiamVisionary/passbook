# SPDX-License-Identifier: Apache-2.0
"""Owner-approved peer snapshots use the existing device envelope and local vaults."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook
import passbook_access as access
import passbook_broker as real_broker
import passbook_integrations as managed
import passbook_link as link
import passbook_managed_peer as peer
import passbook_managed_store as storage
import passbook_vault as vault

PASSWORD = "synthetic-peer-password"
VALUE = "synthetic-peer-credential-9682"


class IsolatedBroker:
    def __init__(self):
        self.keys = {}

    def _held_dek(self, workspace):
        return self.keys.get(workspace, (None, ""))

    def _signin(self, body, root, unused):
        self.keys[body["workspace"]] = managed._password_key(root, body["workspace"], body["password"])
        return {"ok": True}

    read_policy = staticmethod(access.read_policy)


class Device:
    def __init__(self, root, transport=None):
        self.root = root
        self.transport = transport
        self.broker = IsolatedBroker()
        self.private = Ed25519PrivateKey.generate()
        public = storage.b64(self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.ident = storage.installation_id(public)
        envelope = {"action": "connect", "installationId": self.ident, "body": {
            "publicKey": public, "app": "hivemindos", "workspace": "hivemindos", "consent": True,
            "createWorkspace": True, "password": PASSWORD, "background": False,
        }}
        reply = transport(envelope) if transport else managed.handle(envelope, root, self.broker)
        assert reply["ok"], reply

    def call(self, action, body=None):
        raw, issued, nonce = storage.canonical(body or {}), storage.now_ms(), storage.identifier()
        signature = self.private.sign(storage.signed_bytes(action, self.ident, issued, nonce, raw))
        envelope = {"action": action, "installationId": self.ident, "bodyJson": raw,
                    "issuedAt": issued, "nonce": nonce, "signature": storage.b64(signature)}
        if self.transport:
            return self.transport(envelope)
        with storage.Store(self.root).transaction() as tx:
            binding = storage.verify(envelope, tx)
            return peer.handle(action, storage.verified_body(envelope), self.root, tx, binding, self.broker)

    def values(self):
        path = managed.workspace_path(self.root, "hivemindos")
        dek, profile = self.broker._held_dek("hivemindos")
        return {key: vault.unseal_value(key, value, dek, profile_id=profile)
                for key, value in passbook.parse_env_text(path.read_text()).items()}

    def add(self, values):
        dek, profile = self.broker._held_dek("hivemindos")
        passbook.set_values({key: vault.seal_value(key, value, dek, profile_id=profile)
                             for key, value in values.items()},
                            path=managed.workspace_path(self.root, "hivemindos"),
                            environ=managed.env_for(self.root, "hivemindos"))


@pytest.fixture
def devices(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "ambient"))
    monkeypatch.setenv("PASSBOOK_NO_NOTIFY", "1")
    for name in ("HIVE_WORKSPACE", "HIVE_WORKSPACE_ID", "HIVE_ENV_FILES", "APP_SANDBOX_CONTAINER_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)
    return Device(tmp_path / "owner"), Device(tmp_path / "receiver")


def lend(owner, receiver, keys=None, **overrides):
    pairing = receiver.call("peer-pair")
    assert pairing["ok"], pairing
    body = {"pairingToken": pairing["token"], "confirmFingerprint": pairing["fingerprint"],
            "keys": keys or ["API_KEY"], "password": PASSWORD, **overrides}
    return owner.call("peer-grant", body)


def receive(receiver, grant, **overrides):
    return receiver.call("peer-accept", {"envelope": grant["envelope"],
                         "issuerFingerprint": grant["issuerFingerprint"], "password": PASSWORD, **overrides})


def test_owner_approved_peer_snapshot_stays_encrypted_and_bound_to_each_workspace(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE, "UNREQUESTED": "synthetic-withheld"})
    grant = lend(owner, receiver)
    assert VALUE not in json.dumps(grant)
    assert "UNREQUESTED" not in json.dumps(grant)
    result = receive(receiver, grant)
    assert result["ok"] and result["workspace"] == "hivemindos"
    assert result["keys"] == ["API_KEY"]
    assert VALUE not in json.dumps(result)
    assert receiver.values() == {"API_KEY": VALUE}
    path = managed.workspace_path(receiver.root, "hivemindos")
    assert VALUE not in path.read_text()
    assert not (receiver.root / ".env").exists()
    assert not (receiver.root.parent / "ambient" / ".env").exists()
    with pytest.raises(storage.ManagedError, match="already"):
        receive(receiver, grant)


def test_import_keeps_existing_local_keys_without_overwriting(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    receiver.add({"API_KEY": "synthetic-existing"})
    result = receive(receiver, lend(owner, receiver))
    assert result["kept"] == ["API_KEY"]
    assert receiver.values() == {"API_KEY": "synthetic-existing"}


def test_import_retry_returns_durable_receipt_only_for_same_envelope_and_owner(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    grant = lend(owner, receiver)
    receipt = receive(receiver, grant, idempotencyKey="synthetic-transfer:0")
    path = managed.workspace_path(receiver.root, "hivemindos")
    original = path.read_bytes()
    receiver.broker.keys.clear()
    assert receive(receiver, grant, idempotencyKey="synthetic-transfer:0") == receipt
    assert path.read_bytes() == original
    with pytest.raises(storage.ManagedError) as error:
        receive(receiver, grant, idempotencyKey="synthetic-transfer:0", password="wrong-password")
    assert error.value.code == "authentication-failed"
    with pytest.raises(storage.ManagedError) as error:
        receive(receiver, lend(owner, receiver), idempotencyKey="synthetic-transfer:0")
    assert error.value.code == "idempotency-conflict"
    with storage.Store(receiver.root).transaction() as tx:
        records = tx.all("peer-receipt")
    assert len(records) == 1
    assert VALUE not in json.dumps(records) and PASSWORD not in json.dumps(records)


def test_concurrent_import_retries_write_one_encrypted_snapshot(devices, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    grant = lend(owner, receiver)
    original_write, writes = passbook.set_values, []

    def counted_write(*args, **kwargs):
        writes.append(kwargs["path"])
        return original_write(*args, **kwargs)

    monkeypatch.setattr(passbook, "set_values", counted_write)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: receive(receiver, grant, idempotencyKey="concurrent:0"), range(2)))
    assert results[0] == results[1] and results[0]["added"] == ["API_KEY"]
    assert len(writes) == 1


@pytest.mark.parametrize("password", [None, "wrong-password"])
def test_peer_transfer_requires_owner_password_on_both_devices(devices, password):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    with pytest.raises(storage.ManagedError) as error:
        lend(owner, receiver, password=password)
    assert error.value.code in {"authentication-required", "authentication-failed"}
    grant = lend(owner, receiver)
    with pytest.raises(storage.ManagedError) as error:
        receive(receiver, grant, password=password)
    assert error.value.code in {"authentication-required", "authentication-failed"}
    assert receiver.values() == {}


def test_even_known_peer_must_match_the_selected_issuer_fingerprint(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    receive(receiver, lend(owner, receiver))
    with pytest.raises(storage.ManagedError) as error:
        receive(receiver, lend(owner, receiver), issuerFingerprint="incorrect")
    assert error.value.code == "peer-verification-failed"


@pytest.mark.parametrize("scope", ["machine", "workspace"])
def test_peer_export_respects_keys_that_must_stay_on_this_device(devices, scope):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    policy = access.read_policy(owner.root)
    access.set_scope("API_KEY", scope, policy=policy)
    access.write_policy(policy, root=owner.root)
    with pytest.raises(storage.ManagedError) as error:
        lend(owner, receiver)
    assert error.value.code == "policy-denied"


def test_peer_export_respects_explicit_key_refusal(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    policy = access.read_policy(owner.root)
    policy["apps"] = {"hivemindos": {"keys": {"API_KEY": {"mode": "never"}}}}
    access.write_policy(policy, root=owner.root)
    with pytest.raises(storage.ManagedError) as error:
        lend(owner, receiver)
    assert error.value.code == "policy-denied"


def test_peer_import_rejects_per_device_credentials_even_from_a_verified_sender(devices):
    owner, receiver = devices
    pairing = receiver.call("peer-pair")
    grant = link.grant(pairing["token"], ["HIVEMINDOS_DASHBOARD_DEVICE_TOKEN"], root=owner.root,
                       confirm_fingerprint=pairing["fingerprint"],
                       resolve_values=lambda keys: {keys[0]: "synthetic-local-only"})
    with pytest.raises(storage.ManagedError) as error:
        receive(receiver, {"envelope": grant["envelope"], "issuerFingerprint": grant["issuer_fingerprint"]})
    assert error.value.code == "policy-denied"
    assert receiver.values() == {}


def test_peer_request_never_changes_the_binding_workspace_or_accepts_an_agent(devices):
    owner, receiver = devices
    for body in ({"agentId": "agent-a"}, {"agentId": ""}, {"workspace": "main"}):
        with pytest.raises(storage.ManagedError):
            receiver.call("peer-pair", body)
    with storage.Store(owner.root).transaction() as tx:
        binding = tx.get("binding", owner.ident)
        binding["paused"] = True
        tx.put("binding", owner.ident, binding)
    with pytest.raises(storage.ManagedError) as error:
        owner.call("peer-pair")
    assert error.value.code == "paused"
    receiver.broker.keys.clear()
    assert receiver.call("peer-pair")["ok"], "a public pairing token does not open credentials"


def test_two_real_brokers_transfer_only_encrypted_snapshot_and_reject_replay(devices):
    roots = [device.root.parent / name for device, name in zip(devices, ("real-owner", "real-receiver"))]
    try:
        for root in roots:
            assert real_broker.start(root=root)["ok"]
        owner, receiver = [Device(root, lambda envelope, root=root: real_broker._ask(
            {"op": "managed", **envelope}, root=root)) for root in roots]
        assert owner.call("service-write", {"values": {"API_KEY": VALUE, "UNREQUESTED": "synthetic-withheld"}})["ok"]
        grant = lend(owner, receiver)
        assert grant["ok"], grant
        result = receive(receiver, grant)
        assert result["ok"] and result["added"] == ["API_KEY"], result
        retry_grant = lend(owner, receiver)
        retry_receipt = receive(receiver, retry_grant, idempotencyKey="real-restart:0")
        assert retry_receipt["ok"]
        assert VALUE not in json.dumps([grant, result])
        path = managed.workspace_path(receiver.root, "hivemindos")
        stored = passbook.parse_env_text(path.read_text())
        assert list(stored) == ["API_KEY"] and vault.is_sealed(stored["API_KEY"])
        profile = vault.active_profile_id(root=path.parent)
        dek = vault.unlock_with_password(profile, PASSWORD, root=path.parent)
        assert vault.unseal_value("API_KEY", stored["API_KEY"], dek, profile_id=profile) == VALUE
        assert real_broker.stop(root=receiver.root)["ok"]
        assert real_broker.start(root=receiver.root)["ok"]
        assert receive(receiver, retry_grant, idempotencyKey="real-restart:0") == retry_receipt
        repeated = receive(receiver, grant)
        assert not repeated["ok"] and repeated["code"] == "peer-verification-failed"
        legacy = real_broker._ask({"op": "request", "app": "hivemindos", "keys": ["API_KEY"],
                                  "workspace": "hivemindos"}, root=receiver.root)
        assert not legacy.get("granted")
    finally:
        for root in roots:
            real_broker.stop(root=root)
