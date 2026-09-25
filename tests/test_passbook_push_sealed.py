# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Pushing and rotating on a machine shaped like the one this was built for.

An encrypted store, sealed reads, a broker running. There the CLI cannot read a
value at all — which is the point of sealing — and `services update` used to
answer "is not set here, so there is nothing to push" about a key that was
present, encrypted and perfectly usable: the wrong one of the four states, with
the wrong repair. A push now re-runs itself under a grant for the one key, the
way replication does, and the value reaches the service without ever reaching
this process's output.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import passbook  # noqa: E402
import passbook_access as access  # noqa: E402
import passbook_broker  # noqa: E402
import passbook_vault as vault  # noqa: E402
from _platform import broker_marker, needs_a_posix_shell  # noqa: E402

pytestmark = [broker_marker(), needs_a_posix_shell]

SRC = Path(__file__).resolve().parents[1] / "src"
PASSWORD = "a properly long vault password"
OLD, NEW = "fake-sealed-old-111", "fake-sealed-new-222"


@pytest.fixture
def machine(tmp_path, monkeypatch):
    home = tmp_path / "hive"
    monkeypatch.setenv("HIVE_HOME", str(home))
    for leaked in ("HIVE_ENV_FILES", "APP_SANDBOX_CONTAINER_ID", "HIVE_WORKSPACE",
                   "PASSBOOK_GRANT", "PASSBOOK_SERVICE", "API_KEY"):
        monkeypatch.delenv(leaked, raising=False)
    monkeypatch.setenv("PASSBOOK_APPROVAL_TIMEOUT", "2")
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)

    passbook.ensure(app="test")
    passbook.set_values({"API_KEY": OLD})
    profile = vault.create_profile("Owner", password=PASSWORD, root=home)["id"]
    dek = vault.unlock_with_password(profile, PASSWORD, root=home)
    vault.seal_store(dek, profile_id=profile, root=home)

    started = passbook_broker.start()
    if not started.get("ok"):
        pytest.skip(f"the broker would not start here: {started.get('detail')}")
    passbook_broker.signin(profile=profile, password=PASSWORD, duration="always")
    policy = passbook_broker.read_policy()
    policy["reads"] = "sealed"
    passbook_broker.write_policy(policy)

    tools = tmp_path / "bin"
    tools.mkdir()
    (tools / "wrangler").write_text('#!/bin/sh\ncat > "$FAKE_SINKS/wrangler-$5"\necho uploaded\n')
    (tools / "wrangler").chmod(0o755)
    landed = tmp_path / "landed"
    landed.mkdir()

    def run(args, stdin=None):
        environment = {**os.environ, "HIVE_HOME": str(home), "FAKE_SINKS": str(landed),
                       "PATH": f"{tools}{os.pathsep}{os.environ.get('PATH', '')}",
                       "PYTHONPATH": str(SRC)}
        return subprocess.run([sys.executable, str(SRC / "passbook_cli.py"), *args],
                              capture_output=True, text=True, env=environment, input=stdin,
                              timeout=120)

    try:
        yield home, run, landed
    finally:
        passbook_broker.stop()


def _clean(*results):
    for result in results:
        assert OLD not in result.stdout + result.stderr
        assert NEW not in result.stdout + result.stderr


def test_the_value_really_is_sealed_and_unreadable_here(machine):
    home, run, _ = machine
    assert OLD not in (home / ".env").read_text()
    assert access.read_policy()["reads"] == "sealed"


def test_a_push_on_a_sealed_store_goes_through_a_grant(machine):
    home, run, landed = machine
    pushed = run(["push", "API_KEY", "--to", "wrangler:edge"])
    assert pushed.returncode == 0, pushed.stderr + pushed.stdout
    assert (landed / "wrangler-edge").read_text() == OLD
    listed = json.loads(run(["services", "list", "API_KEY", "--json"]).stdout)["API_KEY"]
    assert listed[0]["lastStatus"] == "ok"
    assert "PASSBOOK_SERVICE_BINDINGS=hive-sealed" not in (home / ".env").read_text(), \
        "the record stays readable in a sealed store"
    _clean(pushed)


def test_a_run_through_the_broker_records_where_it_pushed(machine):
    home, run, landed = machine
    done = run(["run", "--only", "API_KEY", "--", "sh", "-c",
                'printf %s "$API_KEY" | wrangler secret put API_KEY --name edge'])
    assert done.returncode == 0, done.stderr
    assert "recorded API_KEY on worker:edge" in done.stderr
    assert (landed / "wrangler-edge").read_text() == OLD
    _clean(done)


def test_rotate_and_roll_back_on_a_sealed_store(machine):
    home, run, landed = machine
    run(["push", "API_KEY", "--to", "wrangler:edge"])

    rotated = run(["rotate", "API_KEY", "--stdin"], stdin=NEW + "\n")
    assert rotated.returncode == 0, rotated.stderr + rotated.stdout
    assert (landed / "wrangler-edge").read_text() == NEW
    text = (home / ".env").read_text()
    assert NEW not in text and OLD not in text, "the new value went in sealed"
    kept = json.loads((home / "rotations.json").read_text())["API_KEY"]
    assert kept["previousSealed"] and kept["previous"].startswith("hive-sealed:"), \
        "the kept previous value is ciphertext, not a readable copy of a live key"
    assert "kept (encrypted" in rotated.stdout

    rolled = run(["rotate", "API_KEY", "--rollback"])
    assert rolled.returncode == 0, rolled.stderr + rolled.stdout
    assert (landed / "wrangler-edge").read_text() == OLD
    assert "API_KEY" not in json.loads((home / "rotations.json").read_text())
    _clean(rotated, rolled)
