# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""`passbook run --only` must never say "locked" about a vault that is open.

It did. The locked notice was decided after `--only` had narrowed the
environment, so a name the store does not hold (a typo, or `--only A,B`, which
was read as one key literally called "A,B") left nothing resolved, and `run`
announced "The credential store is encrypted and locked … Sign in first:
passbook signin" on a machine that was signed in. The command then ran with
neither key, failed against its provider with an auth error, and every agent
that saw the two messages together told its owner to sign in again. The owner
was asked about ten times, across sessions, to sign in to a vault that was
already open. These tests are that loop, closed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import passbook_cli  # noqa: E402

LOCKED = "encrypted and locked"
PRINT_ENV = ("import json, os; print(json.dumps({k: bool(os.environ.get(k)) "
             "for k in ('ALPHA', 'BETA')}))")


@pytest.fixture
def store(tmp_path):
    home = tmp_path / "hive"
    home.mkdir()
    env = {**os.environ, "HIVE_HOME": str(home), "PASSBOOK_KEYSTORE": "file"}
    for inherited in ("PASSBOOK_SERVICE", "PASSBOOK_GRANT", "PASSBOOK_APP", "ALPHA", "BETA"):
        env.pop(inherited, None)

    def run(*args):
        return subprocess.run([sys.executable, str(SRC / "passbook_cli.py"), *args],
                              capture_output=True, text=True, env=env, cwd=str(tmp_path))

    assert run("add", "ALPHA=first-value", "BETA=second-value").returncode == 0
    return run


def _present(done):
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_a_comma_list_is_two_keys_and_the_vault_is_not_called_locked(store):
    done = store("run", "--only", "ALPHA,BETA", "--", sys.executable, "-c", PRINT_ENV)
    assert done.returncode == 0, done.stderr
    assert _present(done) == {"ALPHA": True, "BETA": True}
    assert LOCKED not in done.stderr
    assert "passbook signin" not in done.stderr


def test_repeating_the_flag_still_works(store):
    done = store("run", "--only", "ALPHA", "--only", "BETA", "--", sys.executable, "-c", PRINT_ENV)
    assert _present(done) == {"ALPHA": True, "BETA": True}
    assert LOCKED not in done.stderr


def test_a_name_the_store_lacks_is_named_and_is_not_a_locked_vault(store):
    done = store("run", "--only", "NO_SUCH_KEY", "--", sys.executable, "-c", PRINT_ENV)
    assert done.returncode == 0, done.stderr
    assert "Not in the store: NO_SUCH_KEY" in done.stderr
    assert "Nothing is locked" in done.stderr
    assert LOCKED not in done.stderr
    assert "passbook signin" not in done.stderr


def test_one_typo_among_good_names_still_hands_over_the_good_ones(store):
    done = store("run", "--only", "ALPHA,ALHPA", "--", sys.executable, "-c", PRINT_ENV)
    assert _present(done) == {"ALPHA": True, "BETA": False}
    assert "Not in the store: ALHPA" in done.stderr
    assert LOCKED not in done.stderr


def test_split_only_reads_commas_spaces_and_repeats():
    assert passbook_cli._split_only(["A,B", " C ", "A", ",,D,"]) == ["A", "B", "C", "D"]
    assert passbook_cli._split_only(None) == []


def _in_process_run(monkeypatch, capsys, *, resolved, stored, only):
    """cmd_run up to the exec, with the store's answers supplied."""
    monkeypatch.setattr(passbook_cli, "_store_values", lambda: dict(resolved))
    monkeypatch.setattr(passbook_cli.passbook, "key_names", lambda: list(stored))
    monkeypatch.setattr(passbook_cli, "_sealed_run", lambda *a, **k: None)
    monkeypatch.setattr(passbook_cli, "_use_broker_for_sealed_values", lambda *a, **k: None)
    monkeypatch.setattr(passbook_cli, "_run_recording_plan", lambda *a, **k: None)
    monkeypatch.setattr(passbook_cli, "_sealed_refusal", lambda keys: False)
    for name in stored:
        monkeypatch.delenv(name, raising=False)
    handed = {}

    def fake_exec(program, argv, env):
        handed.update(env)
        raise SystemExit(0)

    monkeypatch.setattr(passbook_cli.os, "execvpe", fake_exec)
    monkeypatch.setattr(passbook_cli.os, "name", "posix")
    args = argparse.Namespace(command=["--", "true"], only=list(only), keep=[], used_in="",
                              push_command="", app="", note="")
    with pytest.raises(SystemExit):
        passbook_cli.cmd_run(args)
    return capsys.readouterr().err, handed


def test_a_store_that_really_is_shut_is_still_called_locked(monkeypatch, capsys):
    err, _ = _in_process_run(monkeypatch, capsys, resolved={}, stored=["ALPHA", "BETA"], only=["ALPHA"])
    assert LOCKED in err
    assert "passbook signin" in err


def test_one_shut_key_in_an_open_store_is_named_on_its_own(monkeypatch, capsys):
    err, handed = _in_process_run(monkeypatch, capsys, resolved={"BETA": "readable"},
                                  stored=["ALPHA", "BETA"], only=["ALPHA", "BETA"])
    assert LOCKED not in err
    assert "In the store but encrypted, and not readable here: ALPHA" in err
    assert handed.get("BETA") == "readable" and "ALPHA" not in handed
