# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Where keys are pushed and noted survives other machines' copies, and a refused key says it was refused.

Both from the 2026-11-24 rotation. Two targets attached to LIVEKIT_API_KEY were gone an hour later while other
keys' targets survived, and rotated keys' targets read "not pushed yet" although their pushes had landed. The
record of targets is one store key that sync carries between machines, and the copy with the newer timestamp
replaced the other whole: a peer whose copy was newer only because something else in it changed wiped
everything recorded here since. And an agent a key was limited away from was told the store was encrypted and
to sign in, which changes nothing.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from _platform import broker_marker

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook  # noqa: E402
import passbook_cli  # noqa: E402
import passbook_services as services  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
needs_a_broker = broker_marker()


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    for leaked in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "APP_SANDBOX_CONTAINER_ID", "PASSBOOK_APP"):
        monkeypatch.delenv(leaked, raising=False)
    passbook.ensure(app="test")
    passbook.set_values({"LIVEKIT_API_KEY": "lk-value", "OTHER_KEY": "other-value"})
    return tmp_path / "hive"


def _copy(*steps):
    registry = services.parse(None)
    for step in steps:
        registry = step(registry)
    return registry


def test_a_newer_copy_from_another_machine_no_longer_drops_what_was_attached_here():
    # The peer's copy: an older attachment, then something else changed there (a push recorded), which made
    # it the newer copy.
    peer = services.attach("OTHER_KEY", "worker:a", "wrangler secret put OTHER_KEY", registry=services.parse(None))
    here = services.attach("LIVEKIT_API_KEY", "render:ami", "render-set LIVEKIT_API_KEY", registry=peer)
    here = services.attach("LIVEKIT_API_KEY", "env-file:ami/.env.local", "env-file-set", registry=here)
    here = services.record("LIVEKIT_API_KEY", "render:ami", ok=True, registry=here)
    time.sleep(0.01)
    peer = services.record("OTHER_KEY", "worker:a", ok=True, registry=peer)

    merged = services.merge(here, peer)
    names = [item["service"] for item in services.bindings("LIVEKIT_API_KEY", merged)]
    assert names == ["env-file:ami/.env.local", "render:ami"]
    assert services.bindings("LIVEKIT_API_KEY", merged)[1]["lastStatus"] == "ok"
    assert services.bindings("OTHER_KEY", merged)[0]["lastStatus"] == "ok"
    # Either way round, the same answer.
    assert services.dump(services.merge(peer, here)) == services.dump(merged)


def test_a_push_that_landed_is_not_reset_by_a_copy_from_before_it():
    before = services.attach("KEY_A", "env-file:x", "cmd", registry=services.parse(None))
    pushed = services.record("KEY_A", "env-file:x", ok=True, registry=before)
    assert services.bindings("KEY_A", services.merge(before, pushed))[0]["lastStatus"] == "ok"
    assert services.bindings("KEY_A", services.merge(pushed, before))[0]["lastStatus"] == "ok"


def test_a_target_removed_here_is_not_brought_back_and_one_attached_again_is_kept():
    both = services.attach("KEY_A", "worker:a", "cmd", registry=services.parse(None))
    removed, gone = services.detach("KEY_A", "worker:a", registry=both)
    assert gone
    assert services.bindings("KEY_A", services.merge(removed, both)) == []
    assert services.bindings("KEY_A", services.merge(both, removed)) == []
    time.sleep(0.01)
    again = services.attach("KEY_A", "worker:a", "cmd2", registry=removed)
    assert [item["command"] for item in services.bindings("KEY_A", services.merge(again, both))] == ["cmd2"]


def test_places_noted_by_hand_merge_the_same_way():
    first = services.add_place("KEY_A", "NYC Mac plist", record=services.parse_places(None))
    other = services.add_place("KEY_B", "a VPS", record=services.parse_places(None))
    merged = services.merge_places(first, other)
    assert services.keys_with_places(merged) == ["KEY_A", "KEY_B"]
    taken, _ = services.remove_place("KEY_A", "NYC Mac plist", record=first)
    assert services.places("KEY_A", services.merge_places(taken, first)) == []


def test_a_sync_pull_merges_the_record_instead_of_replacing_it(machine):
    here = services.attach("LIVEKIT_API_KEY", "render:ami", "render-set", registry=services.parse(None))
    services.write(here)
    peer = services.attach("OTHER_KEY", "worker:a", "wrangler", registry=services.parse(None))
    raw = passbook.parse_env_text(passbook.env_path().read_text(encoding="utf-8"))
    plan = {"apply": {services.REGISTRY_KEY: services.dump(peer)}}

    written, error = passbook_cli._apply_pull(plan, raw, passbook.env_path())
    assert written == [services.REGISTRY_KEY] and not error
    after = services.read()
    assert services.keys_with_bindings(after) == ["LIVEKIT_API_KEY", "OTHER_KEY"]


def test_a_peer_applying_our_push_with_add_replace_merges_too(machine):
    """hive-env-add applies a push to a sealed machine with `passbook add --stdin --replace`."""
    services.write(services.attach("LIVEKIT_API_KEY", "render:ami", "render-set", registry=services.parse(None)))
    peer = services.dump(services.attach("OTHER_KEY", "worker:a", "wrangler", registry=services.parse(None)))
    done = subprocess.run([sys.executable, "-m", "passbook_cli", "add", "--stdin", "--replace"],
                          input=f"{services.REGISTRY_KEY}='{peer}'\n", capture_output=True, text=True,
                          env={**os.environ, "PYTHONPATH": str(REPO / "src"), "PASSBOOK_APP": ""}, cwd=str(REPO))
    assert done.returncode == 0, done.stderr
    assert services.keys_with_bindings(services.read()) == ["LIVEKIT_API_KEY", "OTHER_KEY"]


@needs_a_broker
def test_a_key_limited_to_another_agent_says_so_instead_of_asking_to_sign_in(tmp_path):
    env = {**os.environ, "HIVE_HOME": str(tmp_path / "hive"), "HOME": str(tmp_path), "PASSBOOK_APP": "",
           "PASSBOOK_NO_BRIEF": "1", "PASSBOOK_KEYSTORE": "off", "PASSBOOK_NO_NOTIFY": "1",
           "PYTHONPATH": str(REPO / "src")}
    for leaked in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "APP_SANDBOX_CONTAINER_ID"):
        env.pop(leaked, None)

    def cli(*args, stdin=""):
        return subprocess.run([sys.executable, "-m", "passbook_cli", *args], input=stdin, capture_output=True,
                              text=True, env=env, cwd=str(REPO))

    assert cli("add", "--stdin", stdin="DEMO_KEY=abcdefghijklmnopqrstu\n").returncode == 0
    secured = cli("secure", "--profile-name", "Owner", "--password-stdin", stdin="throwaway-password-123\n")
    if secured.returncode != 0:
        pytest.skip(f"could not seal a store here: {secured.stderr[-200:]}")
    try:
        assert cli("policy", "--reads", "open").returncode == 0
        assert cli("agents", "set", "DEMO_KEY", "--only", "claude-code").returncode == 0
        allowed = cli("run", "--app", "claude-code", "--only", "DEMO_KEY", "--", "sh", "-c", 'test -n "$DEMO_KEY"')
        assert allowed.returncode == 0, allowed.stderr
        refused = cli("run", "--app", "other", "--only", "DEMO_KEY", "--", "sh", "-c", 'test -n "$DEMO_KEY"')
        assert refused.returncode != 0
        assert "limited to claude-code" in refused.stderr
        assert "sign in first" not in refused.stderr.lower() and "encrypted and locked" not in refused.stderr
    finally:
        cli("broker", "stop")
