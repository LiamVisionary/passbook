# SPDX-License-Identifier: Apache-2.0
"""Owner-approved recurring encrypted transfers keep local edits independent."""
import json
import sys
from pathlib import Path

import pytest

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "src"), str(Path(__file__).resolve().parent)]
from test_passbook_managed_peer import devices, lend, receive, PASSWORD, VALUE
import passbook
import passbook_integrations as managed
import passbook_managed_store as storage
import passbook_managed_lease as leases
import passbook_link as link
import passbook_access as access


def call(device, action, body=None):
    raw, at, nonce = storage.canonical(body or {}), storage.now_ms(), storage.identifier()
    proof = {"action": action, "installationId": device.ident, "bodyJson": raw, "issuedAt": at, "nonce": nonce,
             "signature": storage.b64(device.private.sign(storage.signed_bytes(action, device.ident, at, nonce, raw)))}
    return managed.handle(proof, device.root, device.broker)


def proof(receiver, lease, keys):
    paired = call(receiver, "peer-pair")
    raw, at, nonce = storage.canonical({"leaseId": lease["id"], "pairingToken": paired["token"], "keys": keys}), storage.now_ms(), storage.identifier()
    return {"action": "peer-refresh-proof", "installationId": receiver.ident, "bodyJson": raw, "issuedAt": at,
            "nonce": nonce, "signature": storage.b64(receiver.private.sign(
                storage.signed_bytes("peer-refresh-proof", receiver.ident, at, nonce, raw)))}


def enroll(owner, receiver, *, future=False, retry="enrollment:0", keys=None):
    keys = keys or ["API_KEY"]
    initial = lend(owner, receiver, keys)
    receipt = receive(receiver, initial, idempotencyKey=retry)
    assert receipt["ok"]
    pair = call(receiver, "peer-pair")
    granted = call(owner, "peer-authorize", {"password": PASSWORD, "pairingToken": pair["token"],
                   "confirmFingerprint": pair["fingerprint"], "receiverInstallationId": pair["installationId"],
                   "receiverPublicKey": pair["publicKey"], "keys": keys, "allowFutureKeys": future})
    assert granted["ok"], granted
    trusted = call(receiver, "peer-trust", {"password": PASSWORD, "lease": granted["lease"], "allowFutureKeys": future,
                   "idempotencyKeys": [retry], "transport": {"kind": "hivemind-link", "peerId": "synthetic-host", "name": "Synthetic source"}})
    assert trusted["ok"], trusted
    return granted["lease"]


def refresh(owner, receiver, lease, keys=None, **changes):
    granted = call(owner, "peer-refresh", {"proof": proof(receiver, lease, keys or ["API_KEY"])})
    assert granted["ok"], granted
    return call(receiver, "peer-accept", {"leaseId": lease["id"], "envelope": granted["envelope"],
                "issuerFingerprint": granted["issuerFingerprint"], "idempotencyKey": storage.identifier(), **changes})


def test_recurring_snapshot_rotates_only_approved_peer_owned_ciphertext_without_password(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    lease = enroll(owner, receiver)
    owner.add({"API_KEY": "synthetic-rotated-value"})
    # Device.add defaults to preserving, so use the owner-facing encrypted writer.
    assert call(owner, "service-write", {"values": {"API_KEY": "synthetic-rotated-value"}})["ok"]
    result = refresh(owner, receiver, lease)
    assert result["ok"] and result["updated"] == ["API_KEY"]
    assert receiver.values()["API_KEY"] == "synthetic-rotated-value"
    listed = call(receiver, "peer-leases")
    assert listed["leases"][0]["transport"]["peerId"] == "synthetic-host"
    assert PASSWORD not in json.dumps(listed) and VALUE not in json.dumps(listed)


def test_local_change_and_initially_kept_values_are_never_overwritten(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    receiver.add({"API_KEY": "synthetic-independent-local"})
    lease = enroll(owner, receiver)
    assert refresh(owner, receiver, lease)["code"] == "peer-sync-conflict"
    assert receiver.values()["API_KEY"] == "synthetic-independent-local"


def test_later_local_rotation_is_preserved_and_receipt_does_not_claim_it(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    lease = enroll(owner, receiver)
    assert call(receiver, "service-write", {"values": {"API_KEY": "synthetic-local-rotation"}})["ok"]
    assert refresh(owner, receiver, lease)["code"] == "peer-sync-conflict"
    assert receiver.values()["API_KEY"] == "synthetic-local-rotation"


def test_same_machine_other_workspace_is_not_covered_by_trusted_lease(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    lease = enroll(owner, receiver)
    pairing = call(receiver, "peer-pair")
    wrong = link.grant(pairing["token"], ["API_KEY"], root=owner.root, workspace="other-workspace",
                        confirm_fingerprint=pairing["fingerprint"], resolve_values=lambda _: {"API_KEY": "synthetic-wrong-workspace"})
    result = call(receiver, "peer-accept", {"leaseId": lease["id"], "envelope": wrong["envelope"],
                   "issuerFingerprint": wrong["issuer_fingerprint"]})
    assert result["code"] == "peer-verification-failed" and receiver.values()["API_KEY"] == VALUE


def test_lease_expiry_and_disconnect_cannot_be_undone_by_reconnect(devices, monkeypatch):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    lease = enroll(owner, receiver)
    with monkeypatch.context() as clock:
        clock.setattr(leases, "now_ms", lambda: lease["expiresMs"] + 1)
        assert call(owner, "peer-refresh", {"proof": proof(receiver, lease, ["API_KEY"])})["code"] == "peer-lease-unavailable"
    assert call(owner, "revoke", {"disconnect": True})["ok"]
    with storage.Store(owner.root).transaction() as tx:
        binding = tx.get("binding", owner.ident)
        binding.pop("revokedAt")
        binding["paused"] = False
        tx.put("binding", owner.ident, binding)
    assert call(owner, "peer-refresh", {"proof": proof(receiver, lease, ["API_KEY"])})["code"] == "peer-lease-unavailable"


def test_refresh_proof_cannot_be_replayed_forged_or_widened(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE, "UNREQUESTED": "synthetic-withheld"})
    lease = enroll(owner, receiver)
    signed = proof(receiver, lease, ["API_KEY"])
    assert call(owner, "peer-refresh", {"proof": signed})["ok"]
    assert call(owner, "peer-refresh", {"proof": signed})["code"] == "replayed-proof"
    forged = proof(receiver, lease, ["API_KEY"])
    forged["signature"] = storage.b64(b"x" * 64)
    assert call(owner, "peer-refresh", {"proof": forged})["code"] == "invalid-proof"
    assert call(owner, "peer-refresh", {"proof": proof(receiver, lease, ["UNREQUESTED"])})["code"] == "policy-denied"


def test_expiry_pause_revocation_and_source_removal_stop_refresh(devices, monkeypatch):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    lease = enroll(owner, receiver)
    assert call(owner, "pause", {"paused": True})["ok"]
    assert call(owner, "peer-refresh", {"proof": proof(receiver, lease, ["API_KEY"])})["code"] == "paused"
    assert call(owner, "pause", {"paused": False})["ok"]
    assert call(owner, "service-remove", {"keys": ["API_KEY"]})["ok"]
    missing = call(owner, "peer-refresh", {"proof": proof(receiver, lease, ["API_KEY"])})
    assert missing["code"] == "source-missing" and receiver.values()["API_KEY"] == VALUE
    assert call(owner, "peer-revoke", {"leaseId": lease["id"]})["ok"]
    assert call(owner, "peer-refresh", {"proof": proof(receiver, lease, ["API_KEY"])})["code"] == "peer-lease-unavailable"


def test_all_future_keys_requires_both_owners_consent_and_discovers_only_current_scope(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    lease = enroll(owner, receiver, future=True)
    refused = call(receiver, "peer-trust", {"password": PASSWORD, "lease": lease, "idempotencyKeys": ["enrollment:0"],
                                            "allowFutureKeys": False})
    assert refused["code"] == "consent-required"
    owner.add({"NEW_KEY": "synthetic-new-key"})
    listing = call(owner, "peer-refresh", {"proof": proof(receiver, lease, [])})
    assert listing["keys"] == ["API_KEY", "NEW_KEY"]
    assert refresh(owner, receiver, lease, ["NEW_KEY"])["added"] == ["NEW_KEY"]


def test_current_policy_and_receiver_expiry_are_checked_after_enrollment(devices, monkeypatch):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    lease = enroll(owner, receiver)
    granted = call(owner, "peer-refresh", {"proof": proof(receiver, lease, ["API_KEY"])})
    with monkeypatch.context() as clock:
        clock.setattr(leases, "now_ms", lambda: lease["expiresMs"] + 1)
        assert call(receiver, "peer-accept", {"leaseId": lease["id"], "envelope": granted["envelope"],
                    "issuerFingerprint": granted["issuerFingerprint"]})["code"] == "peer-lease-unavailable"
    policy = access.read_policy(owner.root)
    policy["apps"] = {"hivemindos": {"keys": {"API_KEY": {"mode": "never"}}}}
    access.write_policy(policy, root=owner.root)
    assert call(owner, "peer-refresh", {"proof": proof(receiver, lease, ["API_KEY"])})["code"] == "policy-denied"


def test_fresh_owner_renewal_retains_imported_versions_but_not_local_edits(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    old_lease = enroll(owner, receiver)
    with storage.Store(receiver.root).transaction() as tx:
        for row in tx.all("peer-lease"):
            row["expiresMs"] = storage.now_ms() - 1
            tx.put("peer-lease", row["recordId"], row)
    renewed = enroll(owner, receiver, retry="renewal:0")
    assert renewed["id"] != old_lease["id"]
    assert call(owner, "service-write", {"values": {"API_KEY": "synthetic-source-rotation-after-renewal"}})["ok"]
    assert refresh(owner, receiver, renewed)["updated"] == ["API_KEY"]
    assert receiver.values()["API_KEY"] == "synthetic-source-rotation-after-renewal"
    assert call(receiver, "service-write", {"values": {"API_KEY": "synthetic-independent-local-edit"}})["ok"]
    third = enroll(owner, receiver, retry="third:0")
    assert refresh(owner, receiver, third)["code"] == "peer-sync-conflict"
    assert receiver.values()["API_KEY"] == "synthetic-independent-local-edit"


def test_early_renewal_replaces_old_scope_and_stop_leaves_no_active_source_permission(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE, "DESELECTED_KEY": "synthetic-old-scope"})
    old = enroll(owner, receiver, keys=["API_KEY", "DESELECTED_KEY"])
    with storage.Store(receiver.root).transaction() as tx:
        previous = next(row for row in tx.all("peer-lease") if row["id"] == old["id"])
        unrelated = []
        for index, changed in enumerate([
            {"senderDid": link.describe_identity(root=receiver.root)["did"]},
            {"sourceWorkspace": "other-source-workspace"}, {"workspace": "other-local-workspace"},
            {"installationId": "f" * 64}, {"direction": "send"},
        ]):
            row = {**previous, **changed, "id": f"unrelated-{index}", "recordId": f"unrelated-{index}"}
            tx.put("peer-lease", row["recordId"], row)
            unrelated.append(row)
    renewed = enroll(owner, receiver, retry="early-renewal:0")
    rows = call(receiver, "peer-leases")["leases"]
    assert next(row for row in rows if row["id"] == old["id"])["active"] is False
    assert next(row for row in rows if row["id"] == renewed["id"])["active"] is True
    with storage.Store(receiver.root).transaction() as tx:
        assert all(tx.get("peer-lease", row["recordId"]) == row for row in unrelated)
    for value in ("synthetic-first-rotation", "synthetic-second-rotation"):
        assert call(owner, "service-write", {"values": {"API_KEY": value}})["ok"]
        assert refresh(owner, receiver, renewed)["updated"] == ["API_KEY"]
        assert receiver.values()["API_KEY"] == value
    # The source's grant lifetime is independent; receiver-side supersession
    # must reject the old permission even when that sender still authorizes it.
    assert refresh(owner, receiver, old)["code"] == "peer-lease-unavailable"
    assert call(receiver, "peer-revoke", {"leaseId": renewed["id"]})["ok"]
    relevant = [row for row in call(receiver, "peer-leases")["leases"] if row["id"] in {old["id"], renewed["id"]}]
    assert all(not row["active"] for row in relevant)
    assert receiver.values()["DESELECTED_KEY"] == "synthetic-old-scope"


def test_revoked_trust_retry_cannot_resurrect_or_replace_current_permission(devices):
    owner, receiver = devices
    owner.add({"API_KEY": VALUE})
    old = enroll(owner, receiver)
    assert call(receiver, "peer-revoke", {"leaseId": old["id"]})["ok"]
    renewed = enroll(owner, receiver, retry="new-consent:0")
    body = {"password": PASSWORD, "lease": old, "idempotencyKeys": ["enrollment:0"], "allowFutureKeys": False}
    assert call(receiver, "peer-trust", body)["code"] == "peer-lease-unavailable"
    retry = {"password": PASSWORD, "lease": renewed, "idempotencyKeys": ["new-consent:0"], "allowFutureKeys": False}
    assert call(receiver, "peer-trust", retry)["ok"]
    relevant = [row for row in call(receiver, "peer-leases")["leases"] if row["direction"] == "receive" and row["active"]]
    assert [row["id"] for row in relevant] == [renewed["id"]]
