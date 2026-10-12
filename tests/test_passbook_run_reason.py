# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""`passbook run` records what a key was used FOR, not only who used it.

The record said which app read which key, and through the broker the command;
never the purpose. An owner reading it later had a command line and had to
guess why, and an agent had nowhere to put it. Liam, 2026-10-12: "the key and
whats using it and for what is all properly recorded".

What these hold: the reason said (`--reason`, `--why`, or `PASSBOOK_REASON`) is
recorded beside the key and the command; it is handed down to the child so a
script that asks PassBook for a key of its own says the same; a run that says
nothing still runs, quietly, as it always did (a read that worked must not
start needing something), and is recorded with its command; and a plaintext
key handed to a run is recorded at all, which it was not before.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import passbook_mcp  # noqa: E402

PRINT_REASON = "import os; print(os.environ.get('PASSBOOK_REASON', ''))"


@pytest.fixture
def store(tmp_path):
    home = tmp_path / "hive"
    home.mkdir()
    env = {**os.environ, "HIVE_HOME": str(home), "PASSBOOK_KEYSTORE": "file"}
    for inherited in ("PASSBOOK_SERVICE", "PASSBOOK_GRANT", "PASSBOOK_APP", "PASSBOOK_REASON", "ALPHA", "BETA"):
        env.pop(inherited, None)

    def run(*args, extra=None):
        return subprocess.run([sys.executable, str(SRC / "passbook_cli.py"), *args],
                              capture_output=True, text=True, env={**env, **(extra or {})},
                              cwd=str(tmp_path), stdin=subprocess.DEVNULL)

    assert run("add", "ALPHA=first-value", "BETA=second-value").returncode == 0
    return run


def _history(store, key):
    done = store("history", key, "--json")
    assert done.returncode == 0, done.stderr
    return [row for row in json.loads(done.stdout) if row["op"] == "read"]


def test_the_reason_said_is_recorded_beside_the_key_and_the_command(store):
    done = store("run", "--reason", "deploy the gateway Worker", "--only", "ALPHA", "--",
                 sys.executable, "-c", "print('ok')")
    assert done.returncode == 0, done.stderr
    rows = _history(store, "ALPHA")
    assert rows, "a plaintext key handed to a run is recorded"
    program = Path(sys.executable).name
    assert rows[-1]["reason"] == f"deploy the gateway Worker (run {program})"
    assert not _history(store, "BETA"), "only the keys the run was given"


def test_why_is_the_same_flag(store):
    store("run", "--why", "rotate the token", "--only", "BETA", "--", sys.executable, "-c", "0")
    assert _history(store, "BETA")[-1]["reason"].startswith("rotate the token (run ")


def test_a_reason_set_for_a_process_tree_is_used_and_handed_down(store):
    done = store("run", "--only", "ALPHA", "--", sys.executable, "-c", PRINT_REASON,
                 extra={"PASSBOOK_REASON": "nightly backup"})
    assert done.stdout.strip() == "nightly backup", "the child says the same if it asks for a key itself"
    assert _history(store, "ALPHA")[-1]["reason"].startswith("nightly backup (run ")


def test_a_run_that_says_nothing_still_runs_quietly_and_names_its_command(store):
    done = store("run", "--only", "ALPHA", "--", sys.executable, "-c", PRINT_REASON)
    assert done.returncode == 0
    assert done.stderr == "", "a script or service is never asked, and never nagged"
    assert done.stdout.strip() == ""
    assert _history(store, "ALPHA")[-1]["reason"] == f"run {Path(sys.executable).name}"


def test_the_access_listing_shows_what_each_use_was_for(store):
    store("run", "--reason", "send the newsletter", "--only", "ALPHA", "--", sys.executable, "-c", "0")
    listing = store("access")
    assert "for: send the newsletter (run " in listing.stdout


def test_agents_must_say_what_a_run_or_a_request_is_for():
    tools = {tool["name"]: tool for tool in passbook_mcp.TOOLS}
    for name in ("run_with_credentials", "proxy_request"):
        assert "reason" in tools[name]["inputSchema"]["required"], name
