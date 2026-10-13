"""Where every key is, between machines, in names and counts: what the Devices page shows.

Written after a day in which two paired Macs each lacked the other's newest key and nothing on screen
said so (2026-10-13). The summary must tell "absent there" from "held there, not handed over" from
"kept there on purpose", never count a per-machine key as missing, and never carry a value.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook  # noqa: E402
import passbook_cli as cli  # noqa: E402
import passbook_sync as sync  # noqa: E402


def _payload(serves=(), sealed=(), stale=(), policy=(), restart=()):
    return {"ok": True, "values": {name: "a-value-that-must-not-travel" for name in serves},
            "withheldSealed": list(sealed), "withheldStale": list(stale), "withheldByPolicy": list(policy),
            "withheldUntilRestart": list(restart)}


def test_a_key_is_missing_only_where_it_is_neither_served_nor_held():
    local = ["SHARED", "ONLY_HERE", "HELD_THERE", "KEPT_THERE", "USEPOD_HOST_TOKEN", "HIVE_LINK_CONTROL_URL"]
    said = sync.summarize(local, [
        ("m2", _payload(serves=["SHARED", "ONLY_THERE"], sealed=["HELD_THERE"], policy=["KEPT_THERE"], restart=["HELD_THERE"])),
        ("vps", _payload(serves=["SHARED", "ONLY_HERE", "HELD_THERE", "KEPT_THERE"])),
    ], unreachable=["desktop"])
    by = {row["host"]: row for row in said["devices"]}
    assert by["m2"]["missingThere"] == ["ONLY_HERE"], "held and kept keys are there; per-machine keys never count"
    assert by["m2"]["heldBack"] == ["HELD_THERE"] and by["m2"]["restartWouldServe"] == ["HELD_THERE"]
    assert by["m2"]["keptByPolicy"] == 1 and by["m2"]["missingHere"] == ["ONLY_THERE"] and by["m2"]["serves"] == 2
    assert by["vps"]["missingThere"] == [] and by["vps"]["heldBack"] == []
    assert by["desktop"]["reachable"] is False and by["desktop"]["missingThere"] == [], "silence is not absence"
    assert said["notEverywhere"] == {"ONLY_HERE": ["m2"]}
    assert "a-value-that-must-not-travel" not in json.dumps(said)


def test_each_machines_own_usepod_host_keys_never_travel():
    assert sync.is_local_only("USEPOD_HOST_TOKEN") and sync.is_local_only("USEPOD_HOST_WALLET_ADDRESS")
    assert not sync.is_local_only("USEPOD_API_KEY")


def test_when_keys_last_moved_is_kept_by_machine(tmp_path):
    sync.note_exchange("sent", ["m2", "vps"], root=tmp_path, when=1000.0)
    sync.note_exchange("pulled", ["m2"], root=tmp_path, when=2000.0)
    sync.note_exchange("nonsense", ["m2"], root=tmp_path, when=3000.0)
    sync.note_exchange("sent", [], root=tmp_path, when=3000.0)
    kept = sync.read_exchanges(tmp_path)
    assert kept == {"m2": {"sent": 1000.0, "pulled": 2000.0}, "vps": {"sent": 1000.0}}
    said = sync.summarize([], [("m2", _payload())], exchanges=kept)
    assert said["devices"][0]["pulledAt"] == 2000.0 and said["devices"][0]["sentAt"] == 1000.0
    (tmp_path / "sync-exchanges.json").write_text("not json")
    assert sync.read_exchanges(tmp_path) == {}


@pytest.fixture
def home(tmp_path, monkeypatch):
    for name in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "PASSBOOK_GRANT", "PASSBOOK_APP", "PASSBOOK_REASON"):
        monkeypatch.delenv(name, raising=False)
    for name in ("HIVE_HOME", "HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path))
    monkeypatch.setenv("PASSBOOK_KEYSTORE", "file")
    passbook.set_values({"SHARED": "one", "ONLY_HERE": "two"})
    return tmp_path


def test_status_leaves_this_machine_out_of_its_own_peers_and_opens_nothing(home, monkeypatch, capsys):
    import passbook_fleet

    (home / "machine-id").write_text("this-machine\n")
    peers = [{"host": "hivemindos-me", "address": "a1", "port": "8798"}, {"host": "m2", "address": "a2", "port": "8787"},
             {"host": "asleep", "address": "a3", "port": "8787"}]
    monkeypatch.setattr(passbook_fleet, "reachable", lambda: list(peers))
    monkeypatch.setattr(passbook_fleet, "collector_health",
                        lambda address, port: {"machineId": "this-machine" if address == "a1" else "another"})
    asked = []

    def fetch(host, port, address=""):
        asked.append(host)
        return None if host == "asleep" else _payload(serves=["SHARED"])
    monkeypatch.setattr(sync, "fetch", fetch)
    monkeypatch.setattr(passbook, "request", lambda *a, **k: pytest.fail("status opens no value"))
    monkeypatch.setattr(cli, "_rerun_under_grant", lambda *a, **k: pytest.fail("status needs no grant"))
    args = argparse.Namespace(status=True, json=True)
    assert cli.cmd_sync(args) == 0
    said = json.loads(capsys.readouterr().out)
    assert asked == ["m2", "asleep"], "the machine's own link node is not one of its peers"
    hosts = {row["host"]: row for row in said["devices"]}
    assert set(hosts) == {"m2", "asleep"} and hosts["asleep"]["reachable"] is False
    assert hosts["m2"]["missingThere"] == ["ONLY_HERE"] and said["notEverywhere"] == {"ONLY_HERE": ["m2"]}
    assert "a-value-that-must-not-travel" not in json.dumps(said) and "checkedAt" in said


def test_state_says_when_each_key_was_written_and_which_rotations_are_open(home):
    sync.touch_meta(passbook.env_path(), ["SHARED"], when=1234.0)
    state = cli.machine_state()
    assert state["store"]["updated"].get("SHARED") == 1234.0
    assert state["rotations"] == []


def test_rotate_answers_the_window_in_one_object_and_never_with_a_value(home, monkeypatch, capsys):
    import io

    monkeypatch.setattr(cli, "_replicate_write", lambda keys, values: None)
    monkeypatch.setattr(cli, "_confirm_change", lambda *a, **k: True)
    assert cli.main(["rotate", "SHARED", "--status"]) == 0
    before = json.loads(capsys.readouterr().out)
    assert before["exists"] is True and before["pending"] is None and before["services"] == [] and before["provider"] is None

    monkeypatch.setattr(sys, "stdin", io.StringIO("the-new-secret-value"))
    assert cli.main(["rotate", "SHARED", "--stdin", "--json"]) == 0
    started = json.loads(capsys.readouterr().out)
    assert started["ok"] is True and started["pending"] and started["pending"]["restored"] is False
    assert any("replaced: SHARED" in line for line in started["said"])
    assert "the-new-secret-value" not in json.dumps(started) and "one" not in json.dumps(started["pending"])
    assert [row["key"] for row in cli.machine_state()["rotations"]] == ["SHARED"]

    monkeypatch.setattr(sys, "stdin", io.StringIO("another"))
    assert cli.main(["rotate", "SHARED", "--stdin", "--json"]) != 0
    refused = json.loads(capsys.readouterr().out)
    assert refused["ok"] is False and any("still open" in line for line in refused["problems"])

    assert cli.main(["rotate", "SHARED", "--confirm", "--json"]) == 0
    done = json.loads(capsys.readouterr().out)
    assert done["ok"] is True and done["pending"] is None


def test_a_providers_key_can_be_checked_only_when_it_is_the_key_its_reader_uses():
    assert cli.rotation_status("OPENROUTER_MANAGEMENT_KEY")["provider"] == {
        "id": "openrouter", "name": "OpenRouter", "site": "https://openrouter.ai", "canVerify": True}
    assert cli.rotation_status("OPENROUTER_API_KEY")["provider"]["canVerify"] is False, "the inference key does not read billing"
    assert cli.rotation_status("SOMETHING_ELSE")["provider"] is None


def test_a_sync_asked_for_as_json_answers_in_json_even_with_nobody_to_sync_with(home, monkeypatch, capsys):
    import passbook_fleet

    monkeypatch.setattr(passbook_fleet, "reachable", lambda: [])
    monkeypatch.setattr(passbook_fleet, "company_hosts_seen", lambda: [])
    monkeypatch.setattr(passbook_fleet, "available", lambda: (True, ""))
    monkeypatch.setattr(cli, "_rerun_under_grant", lambda *a, **k: None)
    args = argparse.Namespace(status=False, json=True, maintenance=True, apply=True, from_peer="", backfill_meta=False,
                              retry_pending=False, push_missing=False, repair=False, no_adopt=True, conflict="newest")
    assert cli.cmd_sync(args) == 0
    said = json.loads(capsys.readouterr().out)
    assert said["peers"] == [] and said["pulled"] == [] and said["sent"] == {}

