# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Replication: the merge rules, and the reach that decides what may leave.

`plan_pull` and `plan_push` are pure on purpose — no network, no disk, no clock
— so every rule that decides whether a peer's value replaces a local one can be
stated as a case here rather than inferred from a live fleet. Each of these
corresponds to something that went wrong on a real machine.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import passbook_sync as sync  # noqa: E402

NOW = 1_800_000_000.0
OLDER = NOW - 3_600
NEWER = NOW + 3_600


def payload(values, ages=None, ok=True):
    return {"ok": ok, "values": values, "updatedAt": ages or {}}


# ── newest wins, per key ───────────────────────────────────────────────────

def test_a_newer_peer_value_replaces_an_older_local_one():
    plan = sync.plan_pull({"K": "old"}, {"K": OLDER},
                          [("peerA", payload({"K": "new"}, {"K": NEWER}))])
    assert plan["apply"] == {"K": "new"}
    assert plan["sources"]["K"] == "peerA"


def test_an_older_peer_value_is_ignored():
    plan = sync.plan_pull({"K": "mine"}, {"K": NEWER},
                          [("peerA", payload({"K": "theirs"}, {"K": OLDER}))])
    assert plan["apply"] == {}


def test_the_newest_across_several_peers_wins():
    plan = sync.plan_pull({}, {}, [
        ("peerA", payload({"K": "a"}, {"K": OLDER})),
        ("peerB", payload({"K": "b"}, {"K": NEWER})),
        ("peerC", payload({"K": "c"}, {"K": NOW})),
    ])
    assert plan["apply"] == {"K": "b"}
    assert plan["sources"]["K"] == "peerB"


def test_an_identical_value_is_never_rewritten():
    """The bug that decrypted 192 keys: a difference reported every pass."""
    plan = sync.plan_pull({"K": "same"}, {"K": OLDER},
                          [("peerA", payload({"K": "same"}, {"K": NEWER}))])
    assert plan["apply"] == {}


# ── the protections that stop a merge doing damage ─────────────────────────

def test_a_local_value_of_unknown_age_is_never_overwritten_blind():
    plan = sync.plan_pull({"K": "mine"}, {},
                          [("peerA", payload({"K": "theirs"}, {"K": NEWER}))])
    assert plan["apply"] == {}
    assert plan["skippedUnknownAge"] == ["K"]


def test_a_sealed_value_this_machine_cannot_open_is_never_overwritten():
    """Without the secret there is no telling 'the peer agrees' from 'the peer
    is newer', and guessing wrong writes plaintext over a sealed value."""
    plan = sync.plan_pull({"K": sync.UNOPENED}, {"K": OLDER},
                          [("peerA", payload({"K": "theirs"}, {"K": NEWER}))])
    assert plan["apply"] == {}
    assert plan["skippedSealedShut"] == ["K"]


def test_a_removed_key_is_not_resurrected_by_a_peer_holding_an_older_copy():
    """The tombstone: the key is gone locally but its stamp remains."""
    plan = sync.plan_pull({}, {"K": NEWER},
                          [("peerA", payload({"K": "zombie"}, {"K": OLDER}))])
    assert plan["apply"] == {}


def test_a_key_genuinely_new_on_a_peer_still_arrives():
    plan = sync.plan_pull({}, {}, [("peerA", payload({"K": "fresh"}, {"K": NOW}))])
    assert plan["apply"] == {"K": "fresh"}


def test_per_machine_credentials_never_arrive_from_a_peer():
    plan = sync.plan_pull({}, {}, [
        ("peerA", payload({"HIVEMINDOS_DASHBOARD_DEVICE_TOKEN": "theirs"}, {}))])
    assert plan["apply"] == {}


def test_a_malformed_key_name_is_ignored():
    plan = sync.plan_pull({}, {}, [("peerA", payload({"not a key": "x", "9BAD": "y"}, {}))])
    assert plan["apply"] == {}


# ── the reach decides what may leave ───────────────────────────────────────

def test_only_a_tailnet_key_may_leave_this_machine(monkeypatch):
    import passbook_access

    policy = {"version": passbook_access.POLICY_VERSION, "keys": {
        "WIDE": {"scope": "tailnet"},
        "HERE": {"scope": "machine"},
        "MINE": {"scope": "workspace"},
    }}
    assert sync.may_leave_machine("WIDE", policy)["allowed"] is True
    assert sync.may_leave_machine("HERE", policy)["allowed"] is False
    assert sync.may_leave_machine("MINE", policy)["allowed"] is False
    # The reason names the reach, so a person can act on it.
    assert "machine" in sync.may_leave_machine("HERE", policy)["why"]


def test_a_narrowed_key_is_withheld_from_a_push():
    import passbook_access

    policy = {"version": passbook_access.POLICY_VERSION, "keys": {
        "MINE": {"scope": "workspace"},
    }}
    plan = sync.plan_push({"WIDE": "a", "MINE": "b"}, {}, payload({}), policy=policy)
    assert plan["send"] == {"WIDE": "a"}
    assert plan["withheldByPolicy"] == ["MINE"]


def test_a_push_sends_only_what_the_peer_lacks():
    plan = sync.plan_push({"A": "1", "B": "2"}, {}, payload({"A": "1"}))
    assert plan["send"] == {"B": "2"}


def test_per_machine_credentials_are_never_pushed():
    plan = sync.plan_push({"HIVE_ENV_FILE": "/x", "OK": "1"}, {}, payload({}))
    assert plan["send"] == {"OK": "1"}
    assert "HIVE_ENV_FILE" in plan["withheldByPolicy"]


# ── the wire never carries ciphertext ──────────────────────────────────────

def test_a_value_that_cannot_be_opened_is_withheld_rather_than_sent_sealed(tmp_path):
    """A `hive-sealed:` blob is meaningless to every other machine."""
    values = {"OPEN": "plain", "SHUT": "hive-sealed:v2:AAAA"}
    served = sync.serve(values, tmp_path / ".env", opener=lambda keys: {})
    assert served["values"] == {"OPEN": "plain"}
    assert served["withheldSealed"] == ["SHUT"]
    assert "hive-sealed" not in str(served["values"])


def test_a_sealed_value_the_vault_can_open_is_served_as_plaintext(tmp_path):
    values = {"SHUT": "hive-sealed:v2:AAAA"}
    served = sync.serve(values, tmp_path / ".env",
                        opener=lambda keys: {"SHUT": "the-secret"})
    assert served["values"] == {"SHUT": "the-secret"}
    assert served["withheldSealed"] == []


def test_serving_applies_the_reach_before_it_applies_the_vault(tmp_path):
    import passbook_access

    policy = {"version": passbook_access.POLICY_VERSION,
              "keys": {"MINE": {"scope": "workspace"}}}
    served = sync.serve({"MINE": "secret", "WIDE": "shared"}, tmp_path / ".env",
                        policy=policy, opener=lambda keys: {})
    assert served["values"] == {"WIDE": "shared"}
    assert served["withheldByPolicy"] == ["MINE"]


# ── the age map ────────────────────────────────────────────────────────────

def test_touching_a_key_records_its_age(tmp_path):
    store = tmp_path / ".env"
    store.write_text("K=v\n", encoding="utf-8")
    sync.touch_meta(store, ["K"], when=NOW)
    assert sync.read_meta(store) == {"K": NOW}


def test_a_missing_or_damaged_age_map_reads_as_empty(tmp_path):
    store = tmp_path / ".env"
    assert sync.read_meta(store) == {}
    sync.meta_path(store).write_text("{not json", encoding="utf-8")
    assert sync.read_meta(store) == {}


def test_a_tombstone_survives_the_key_being_removed(tmp_path):
    store = tmp_path / ".env"
    store.write_text("K=v\n", encoding="utf-8")
    sync.touch_meta(store, ["K"], when=NOW)
    store.write_text("", encoding="utf-8")          # key removed
    sync.touch_meta(store, ["K"], when=NEWER)       # removal stamped
    assert sync.read_meta(store)["K"] == NEWER


def test_a_peer_serving_ciphertext_is_refused_rather_than_stored():
    """A peer's blob is sealed under THAT machine's data key, which never
    leaves it. Stored here it can never be opened, and it compares unequal to
    the real secret forever — so newest-wins rewrites it on every pass.

    Not hypothetical: three of four live peers were serving 41 sealed values
    each, from pre-fix code, at the time this was written.
    """
    plan = sync.plan_pull({}, {}, [
        ("stale-peer", payload({"K": "hive-sealed:v2:AAAA", "OK": "plain"},
                               {"K": NEWER, "OK": NEWER}))])
    assert plan["apply"] == {"OK": "plain"}
    assert plan["refusedSealedFromPeer"] == ["K"]


def test_a_stale_peers_blob_cannot_replace_a_good_local_value():
    plan = sync.plan_pull({"K": "the-real-secret"}, {"K": OLDER}, [
        ("stale-peer", payload({"K": "hive-sealed:v2:AAAA"}, {"K": NEWER}))])
    assert plan["apply"] == {}
    assert plan["refusedSealedFromPeer"] == ["K"]


# ── repairing a peer that holds our ciphertext ─────────────────────────────

def test_a_peer_holding_our_ciphertext_is_planned_for_repair():
    """259 blobs on each of three live machines, byte-identical to ours."""
    plan = sync.plan_repair(payload({"K": "hive-sealed:v2:AAAA", "FINE": "value"}),
                            {"K": "the-real-secret", "FINE": "value"})
    assert plan["broken"] == ["K"]
    assert plan["repair"] == {"K": "the-real-secret"}


def test_a_key_this_machine_also_cannot_open_is_not_repairable():
    plan = sync.plan_repair(payload({"K": "hive-sealed:v2:AAAA"}),
                            {"K": "hive-sealed:v2:BBBB"})
    assert plan["repair"] == {}
    assert plan["cannotOpen"] == ["K"]


def test_repair_still_respects_a_narrowed_reach():
    import passbook_access

    policy = {"version": passbook_access.POLICY_VERSION,
              "keys": {"MINE": {"scope": "workspace"}}}
    plan = sync.plan_repair(payload({"MINE": "hive-sealed:v2:AAAA"}),
                            {"MINE": "secret"}, policy=policy)
    assert plan["repair"] == {}
    assert plan["withheldByPolicy"] == ["MINE"]


def test_push_refuses_to_send_ciphertext():
    ok, why = sync.push("peer", "8798", {"K": "hive-sealed:v2:AAAA"})
    assert ok is False
    assert "plaintext" in why
