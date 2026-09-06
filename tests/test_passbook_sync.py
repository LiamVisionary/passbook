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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook_sync as sync  # noqa: E402

NOW = 1_800_000_000.0
OLDER = NOW - 3_600
NEWER = NOW + 3_600


def payload(values, ages=None, ok=True, withheld_sealed=()):
    """What `serve` actually returns, including the fields that say what it left
    out. `withheldSealed` is part of that contract and push-missing depends on
    it: a peer that does not say what it withheld cannot be seeded safely."""
    return {"ok": ok, "values": values, "updatedAt": ages or {},
            "withheldSealed": list(withheld_sealed), "withheldByPolicy": []}


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

def test_bootstrap_recovers_only_the_requested_orphaned_keys():
    plan = sync.plan_bootstrap(["K"], [
        ("peer", payload({"K": "recovered", "EXTRA": "unrequested"})),
    ], policy={})
    assert plan == {"values": {"K": "recovered"}, "missing": [], "conflicts": []}


def test_bootstrap_reports_missing_and_never_accepts_ciphertext_or_empty_values():
    plan = sync.plan_bootstrap(["V1", "V2", "FUTURE", "EMPTY", "MALFORMED", "ABSENT"], [
        ("peer", payload({"V1": "hive-sealed:v1:AAAA", "V2": "hive-sealed:v2:BBBB",
                          "FUTURE": "hive-sealed:v9:CCCC", "EMPTY": "", "MALFORMED": 42})),
    ], policy={})
    assert plan["values"] == {}
    assert plan["missing"] == ["ABSENT", "EMPTY", "FUTURE", "MALFORMED", "V1", "V2"]
    assert plan["conflicts"] == []


def test_bootstrap_respects_reach_and_machine_identity_boundaries():
    local_only = "HIVEMINDOS_DASHBOARD_DEVICE_TOKEN"
    policy = {"keys": {"HERE": {"scope": "machine"}, "MINE": {"scope": "workspace"}}}
    values = {"WIDE": "allowed", "HERE": "held", "MINE": "held", local_only: "held"}
    plan = sync.plan_bootstrap(values, [("peer", payload(values))], policy=policy)
    assert plan["values"] == {"WIDE": "allowed"}
    assert plan["missing"] == sorted(["HERE", "MINE", local_only])


def test_bootstrap_identical_values_do_not_need_timestamps():
    plan = sync.plan_bootstrap(["K"], [
        ("older", payload({"K": "same"}, {"K": OLDER})),
        ("unknown", payload({"K": "same"})),
    ], policy={})
    assert plan == {"values": {"K": "same"}, "missing": [], "conflicts": []}


def test_bootstrap_chooses_the_unique_newest_dated_value():
    plan = sync.plan_bootstrap(["K"], [
        ("older", payload({"K": "old"}, {"K": OLDER})),
        ("newer", payload({"K": "new"}, {"K": NEWER})),
        ("same-newer", payload({"K": "new"}, {"K": NEWER})),
    ], policy={})
    assert plan == {"values": {"K": "new"}, "missing": [], "conflicts": []}


@pytest.mark.parametrize("uncertain_age", [None, 0, -1, True, "new", float("nan"),
                                            float("inf"), NEWER])
def test_bootstrap_refuses_conflicts_with_unknown_or_tied_ages(uncertain_age):
    plan = sync.plan_bootstrap(["K", "RESOLVED"], [
        ("newer", payload({"K": "first", "RESOLVED": "safe"}, {"K": NEWER})),
        ("uncertain", payload({"K": "different"}, {"K": uncertain_age})),
    ], policy={})
    assert plan == {"values": {"RESOLVED": "safe"}, "missing": [], "conflicts": ["K"]}


def test_bootstrap_does_not_ignore_an_undated_copy_during_a_conflict():
    plan = sync.plan_bootstrap(["K"], [
        ("older", payload({"K": "old"}, {"K": OLDER})),
        ("newer", payload({"K": "new"}, {"K": NEWER})),
        ("undated", payload({"K": "old"})),
    ], policy={})
    assert plan == {"values": {}, "missing": [], "conflicts": ["K"]}


def test_bootstrap_ignores_failed_and_malformed_peer_payloads():
    plan = sync.plan_bootstrap(["K", "not a key"], [
        ("failed", payload({"K": "untrusted"}, ok=False)),
        ("malformed", {"values": ["untrusted"]}),
        ("empty", None),
        ("valid", payload({"K": "safe", "not a key": "invalid"})),
    ], policy={})
    assert plan == {"values": {"K": "safe"}, "missing": ["not a key"], "conflicts": []}


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


# ── conflict policy ────────────────────────────────────────────────────────
#
# `newest` is what the fleet has always run. The other three exist because
# "newest wins" is the wrong answer in two situations that both happened: a
# machine whose clock or meta is untrustworthy (you want local-wins while you
# work out why), and a deliberate one-way seed (remote-wins). `fail` is for a
# script that would rather stop than pick.


def _one_peer(value: str, age: float):
    return [("peer", {"values": {"K": value}, "updatedAt": {"K": age}})]


def test_newest_is_still_the_default_and_still_wins_on_age():
    assert sync.plan_pull({"K": "local"}, {"K": OLDER}, _one_peer("remote", NEWER))["apply"] == {"K": "remote"}
    assert sync.plan_pull({"K": "local"}, {"K": NEWER}, _one_peer("remote", OLDER))["apply"] == {}


def test_local_wins_never_overwrites_whatever_the_ages_say():
    plan = sync.plan_pull({"K": "local"}, {"K": OLDER}, _one_peer("remote", NEWER),
                          conflict="local-wins")
    assert plan["apply"] == {}
    assert plan["heldByConflictPolicy"] == ["K"]
    assert plan["disagreed"] == ["K"]


def test_remote_wins_takes_the_peer_copy_even_when_local_is_newer():
    plan = sync.plan_pull({"K": "local"}, {"K": NEWER}, _one_peer("remote", OLDER),
                          conflict="remote-wins")
    assert plan["apply"] == {"K": "remote"}


def test_fail_changes_nothing_and_names_every_disagreement():
    """Half-applying a run the caller asked to abort is the worst answer of the
    three: it leaves the fleet in a state nobody chose."""
    payloads = [("peer", {"values": {"K": "remote", "J": "same"},
                          "updatedAt": {"K": NEWER, "J": NEWER}})]
    plan = sync.plan_pull({"K": "local", "J": "same"}, {"K": OLDER, "J": OLDER},
                          payloads, conflict="fail")
    assert plan["apply"] == {}
    assert plan["disagreed"] == ["K"]


def test_a_conflict_policy_never_overrides_the_two_refusals():
    """`remote-wins` is about which SIDE wins a disagreement. It is not licence
    to take a peer's ciphertext, or to guess at a value the vault will not open
    — in neither case is there anything to compare."""
    sealed = [("peer", {"values": {"K": "hive-sealed:v2:blob"}, "updatedAt": {"K": NEWER}})]
    plan = sync.plan_pull({"K": "local"}, {"K": OLDER}, sealed, conflict="remote-wins")
    assert plan["apply"] == {} and plan["refusedSealedFromPeer"] == ["K"]

    shut = sync.plan_pull({"K": sync.UNOPENED}, {"K": OLDER}, _one_peer("remote", NEWER),
                          conflict="remote-wins")
    assert shut["apply"] == {} and shut["skippedSealedShut"] == ["K"]


def test_an_unknown_conflict_policy_is_refused_rather_than_guessed():
    with pytest.raises(ValueError):
        sync.plan_pull({}, {}, [], conflict="whatever-you-think-best")


# ── keys with no timestamp ─────────────────────────────────────────────────


def test_a_key_with_no_timestamp_is_found_so_it_stops_being_stranded():
    """Such a key is frozen BOTH ways: `plan_pull` reads its age as 0.0 and will
    not overwrite it, and `serve` offers it as updatedAt 0 so no peer adopts it.
    It then diverges silently the moment anyone edits it elsewhere."""
    assert sync.plan_backfill(["A", "B", "C"], {"A": NOW, "B": 0.0}) == ["B", "C"]
    assert sync.plan_backfill([], {}) == []


def test_backfill_leaves_a_real_stamp_alone():
    assert sync.plan_backfill(["A"], {"A": NOW}) == []


# ── what has not reached every peer ────────────────────────────────────────


def test_a_failed_delivery_survives_the_outage_that_caused_it(tmp_path):
    """Without a record, a key a peer missed is simply absent there until
    somebody happens to change it again — which on a fleet means "until somebody
    notices", and last time nobody noticed for a day."""
    sync.note_undelivered(["ALPHA", "BETA"], ["a", "b"], when=NOW, root=tmp_path)
    owed = sync.read_pending(tmp_path)
    assert owed["ALPHA"]["owed"] == ["a", "b"]

    sync.note_delivered(["ALPHA"], "a", root=tmp_path)
    owed = sync.read_pending(tmp_path)
    assert owed["ALPHA"]["owed"] == ["b"]

    # A host still down keeps its debt rather than losing it.
    assert sync.plan_retry(owed, ["a"]) == {"a": ["BETA"]}
    assert sync.plan_retry(owed, ["a", "b"]) == {"a": ["BETA"], "b": ["ALPHA", "BETA"]}


def test_a_key_owed_to_nobody_stops_being_pending(tmp_path):
    sync.note_undelivered(["ALPHA"], ["a"], when=NOW, root=tmp_path)
    sync.note_delivered(["ALPHA"], "a", root=tmp_path)
    assert sync.read_pending(tmp_path) == {}


def test_the_queue_holds_names_and_never_values(tmp_path):
    """It is bookkeeping about replication, not a second copy of the store."""
    sync.note_undelivered(["SECRET_KEY"], ["a"], when=NOW, root=tmp_path)
    text = sync.pending_path(tmp_path).read_text(encoding="utf-8")
    assert "SECRET_KEY" in text
    assert "value" not in text.lower()


def test_unreadable_bookkeeping_is_empty_rather_than_fatal(tmp_path):
    sync.pending_path(tmp_path).write_text("{ this is not json", encoding="utf-8")
    assert sync.read_pending(tmp_path) == {}


# ── bringing a plain .env in, and only what is missing ─────────────────────
#
# These live here rather than with the store tests because they exist for one
# reason: retiring hive-env-add, whose `--import-env` and `--ensure-placeholder`
# were the last two writing verbs PassBook had no answer for.


def _cli(tmp_path, monkeypatch, *args):
    import passbook_cli

    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    return passbook_cli.main(list(args))


def test_a_plain_env_file_can_be_brought_in(tmp_path, monkeypatch):
    source = tmp_path / "other.env"
    source.write_text("FROM_FILE=one\n# a comment\nALSO=two\n", encoding="utf-8")

    assert _cli(tmp_path, monkeypatch, "add", "--from-env", str(source)) == 0

    import passbook

    assert {"FROM_FILE", "ALSO"} <= set(passbook.key_names())


def test_a_missing_import_file_names_the_file(tmp_path, monkeypatch, capsys):
    assert _cli(tmp_path, monkeypatch, "add", "--from-env", str(tmp_path / "nope.env")) == 1
    assert "nope.env" in capsys.readouterr().err


def test_if_absent_leaves_a_key_that_is_already_set(tmp_path, monkeypatch):
    import passbook

    assert _cli(tmp_path, monkeypatch, "add", "KEEP_ME=original") == 0
    assert _cli(tmp_path, monkeypatch, "add", "--if-absent", "KEEP_ME=different") == 0
    assert passbook.load()["KEEP_ME"] == "original"


def test_if_absent_refuses_a_bare_key_instead_of_doing_nothing(tmp_path, monkeypatch, capsys):
    """hive-env's `--ensure-placeholder` writes `KEY=` to reserve a name. That
    does not port: this store drops empty values on write, so the placeholder
    would vanish silently — and if it did not, `check` would answer `set` for a
    key holding nothing, which is the one answer worse than `missing`.

    Saying so beats the first version of this, which accepted the key, wrote
    nothing, and printed nothing at all.
    """
    assert _cli(tmp_path, monkeypatch, "add", "--if-absent", "RESERVED") == 1
    said = capsys.readouterr().err
    assert "will not prompt" in said and "placeholder" in said


def test_a_deletion_is_written_down(tmp_path, monkeypatch):
    """`remove` calls itself "the one operation that can break another app on
    this box" and was the only mutation leaving no trace: `add` wrote a row and
    `remove` wrote nothing, so the record could show a credential arriving and
    never show it going. It is also the operation that has been buggy before —
    a sealed key reporting `removed` while staying on disk — which is precisely
    what a receipt is for.
    """
    import passbook_stamp

    assert _cli(tmp_path, monkeypatch, "add", "DOOMED=value") == 0
    assert _cli(tmp_path, monkeypatch, "remove", "DOOMED") == 0

    rows = [r for r in passbook_stamp.read_stamps(limit=50, root=tmp_path)
            if r.get("op") == "remove"]
    assert rows, "the deletion left no receipt"
    assert "DOOMED" in (rows[0].get("keys") or [])


def test_removing_a_key_that_was_not_there_writes_no_receipt(tmp_path, monkeypatch):
    """A record of something that did not happen is worse than no record."""
    import passbook_stamp

    assert _cli(tmp_path, monkeypatch, "remove", "NEVER_EXISTED") == 0
    assert not [r for r in passbook_stamp.read_stamps(limit=50, root=tmp_path)
                if r.get("op") == "remove"]


# ── seeding a peer, and refusing to guess ──────────────────────────────────


def test_a_peer_that_cannot_open_its_own_values_is_not_re_seeded():
    """A key absent from a peer's payload is not necessarily one the peer LACKS.
    `serve` leaves out anything it could not open, so a peer with a shut vault
    offers a short list of exactly what it can read.

    Measured on a real fleet: this machine's own collector served 18 of 305
    values, and a blind push-missing would have re-sent the other 286 over keys
    the peer already had.
    """
    theirs = payload({"A": "1"}, withheld_sealed=["B", "C"])
    plan = sync.plan_push({"A": "1", "B": "2", "C": "3", "D": "4"}, {}, theirs)
    assert plan["send"] == {"D": "4"}
    assert plan["heldBackAsUnopenableThere"] == ["B", "C"]


def test_a_peer_that_says_nothing_about_what_it_withheld_is_not_seeded_at_all():
    """An older or foreign server cannot tell us, and the answer there is to
    send nothing rather than to guess: an absent key is a gap a later pass can
    fill, and an overwrite is not undoable."""
    silent = {"ok": True, "values": {"A": "1"}, "updatedAt": {}}
    plan = sync.plan_push({"A": "1", "B": "2"}, {}, silent)
    assert plan["send"] == {}
    assert plan["cannotTell"] is True


def test_a_refused_write_says_the_key_was_not_written_and_gives_one_command(
        tmp_path, monkeypatch, capsys):
    """The message a person actually hits when they add a key to a sealed store
    with the vault shut.

    It used to read: "This store is encrypted, and the value could not be
    sealed: no broker is running, so nothing could be sealed" — the same fact
    twice, led by the mechanism, and never saying the thing the reader needs
    first, which is that their key was NOT written.

    It also buried the fix. `passbook signin` starts a broker when there is
    none, so it answers both causes; but nothing in "no broker is running" tells
    a reader that, and they would reasonably go looking for a broker command.
    """
    import passbook_cli

    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    monkeypatch.setattr(passbook_cli, "_sealed_store_present", lambda: True)

    import passbook_broker

    monkeypatch.setattr(passbook_broker, "seal_values",
                        lambda *a, **k: {"ok": False,
                                         "error": "no broker is running, so nothing could be sealed"})

    assert passbook_cli.main(["add", "SOME_KEY=value"]) == 1
    said = capsys.readouterr().err

    assert "Nothing was written" in said, "lead with the outcome, not the mechanism"
    assert "passbook signin" in said
    assert "starts the broker" in said, "the reader cannot know signin does this"
    # The mechanism is kept, but subordinate — it is for diagnosis, not the headline.
    assert "no broker is running" in said
    assert said.count("could not be sealed") == 0, "the doubled phrasing is gone"
