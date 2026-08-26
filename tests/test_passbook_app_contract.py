# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""The contract the PassBook app runs on.

The native app holds no logic: every question and every change goes through the
CLI, so the CLI *is* its API. That has one sharp edge — the Rust side treats a
non-zero exit as a failure and shows the user an error. A command that does its
job and then dies printing the result therefore looks like a broken feature.

That is not hypothetical. `broker start` started the broker and then crashed on
a stale `policy['mode']` from the version-1 shape, exiting 1. The broker was
running; the app would have said it failed. These tests pin the exit code and
the shape for every call the app makes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import passbook  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1]


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    monkeypatch.delenv("HIVE_WORKSPACE", raising=False)
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    passbook.ensure(app="test")
    passbook.set_values({"DEMO_KEY": "a-value", "OTHER_KEY": "another"})
    return tmp_path / "hive"


def _cli(*args, home: Path, stdin: str = ""):
    return subprocess.run(
        [sys.executable, "-m", "passbook_cli", *args],
        capture_output=True, text=True, input=stdin, cwd=str(PACKAGE),
        env={**os.environ, "HIVE_HOME": str(home), "PYTHONPATH": str(PACKAGE)},
    )


# ── every call the app makes must exit zero on success ─────────────────────


@pytest.mark.parametrize("args", [
    ("state",),
    ("policy",),
    ("policy", "--app", "agent", "--key", "DEMO_KEY", "--mode", "ask"),
    ("policy", "--app", "agent", "--key", "DEMO_KEY", "--mode", "always"),
    ("unlock", "--for", "15m", "--reason", "from PassBook"),
    ("lock",),
    ("link", "--json"),
    ("broker",),
])
def test_the_app_calls_exit_zero(machine, args):
    done = _cli(*args, home=machine)
    assert done.returncode == 0, f"{' '.join(args)} exited {done.returncode}: {done.stderr[-400:]}"


def test_starting_and_stopping_the_broker_both_exit_zero(machine):
    """The bug this file exists for: it started, then died printing the result."""
    started = _cli("broker", "start", home=machine)
    stopped = _cli("broker", "stop", home=machine)

    assert started.returncode == 0, started.stderr[-400:]
    assert "Traceback" not in started.stderr
    assert stopped.returncode == 0, stopped.stderr[-400:]


def test_adding_a_key_over_stdin_exits_zero(machine):
    """The app passes secrets on stdin, never as an argument — `ps` can read those."""
    done = _cli("add", "--stdin", home=machine, stdin="FROM_APP=value\n")

    assert done.returncode == 0, done.stderr[-400:]
    assert "FROM_APP" in _cli("list", home=machine).stdout


# ── the shape the window renders from ──────────────────────────────────────


def test_state_carries_every_section_the_window_needs(machine):
    done = _cli("state", home=machine)
    state = json.loads(done.stdout)

    assert set(state) >= {"store", "sealing", "access", "broker", "links", "record"}
    assert state["store"]["keys"] == ["DEMO_KEY", "OTHER_KEY"]
    assert state["store"]["writes_to"]
    assert state["access"]["modes"] == ["always", "ask", "window", "never"]
    assert state["access"]["presets"]
    assert isinstance(state["record"]["rows"], list)


def test_every_section_reports_its_own_availability(machine):
    """A surface should render what is there and say what is not, rather than
    showing an empty panel that reads as a bug."""
    state = json.loads(_cli("state", home=machine).stdout)

    for section in ("access", "broker", "links", "record"):
        assert "available" in state[section], f"{section} does not say whether it is installed"
    assert "supported" in state["sealing"]


def test_state_never_carries_a_value(machine):
    passbook.set_values({"SECRET_ONE": "a-value-nobody-should-see"})

    blob = _cli("state", home=machine).stdout

    assert "SECRET_ONE" in blob, "key names are the point"
    assert "a-value-nobody-should-see" not in blob


def test_state_still_answers_on_a_machine_with_nothing_optional_installed(machine, monkeypatch):
    """The app must open on a bare machine and show it honestly."""
    import builtins

    real_import = builtins.__import__
    optional = {"passbook_stamp", "passbook_seal", "passbook_link", "passbook_broker", "passbook_access"}

    def refuse(name, *args, **kwargs):
        if name in optional:
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)
    import passbook_cli

    state = passbook_cli.machine_state()

    assert state["store"]["keys"] == ["DEMO_KEY", "OTHER_KEY"]
    assert state["access"]["available"] is False
    assert state["broker"]["available"] is False
    assert state["record"]["available"] is False
    assert state["sealing"]["supported"] is False


# ── the vault calls the sign-in screen makes ───────────────────────────────

VAULT_PASSWORD = "a properly long vault password"


def _profile(home: Path):
    return _cli("profile", "create", "Owner", "--password-stdin",
                home=home, stdin=VAULT_PASSWORD + "\n")


def test_vault_state_exits_zero_and_is_json_on_a_bare_machine(machine):
    """The window asks this before anything exists, and must not be told an error."""
    done = _cli("vault", "--json", home=machine)
    assert done.returncode == 0, done.stderr[-400:]
    state = json.loads(done.stdout)
    assert state["profiles"] == [] and state["unlocked"] is False
    assert state["plaintext"], "a plaintext store should report what is readable"


def test_creating_a_profile_over_stdin_exits_zero(machine):
    done = _profile(machine)
    assert done.returncode == 0, done.stderr[-400:]
    assert "Traceback" not in done.stderr
    state = json.loads(_cli("vault", "--json", home=machine).stdout)
    assert [p["label"] for p in state["profiles"]] == ["Owner"]


def test_a_short_password_is_refused_without_a_traceback(machine):
    done = _cli("profile", "create", "Weak", "--password-stdin", home=machine, stdin="short\n")
    assert done.returncode == 1
    assert "Traceback" not in done.stderr
    assert "8 characters" in done.stderr


def test_seal_and_unseal_over_stdin_both_exit_zero(machine):
    _profile(machine)
    sealed = _cli("seal", "--password-stdin", home=machine, stdin=VAULT_PASSWORD + "\n")
    assert sealed.returncode == 0, sealed.stderr[-400:]
    assert "a-value" not in (machine / ".env").read_text(encoding="utf-8")

    opened = _cli("unseal", "--password-stdin", home=machine, stdin=VAULT_PASSWORD + "\n")
    assert opened.returncode == 0, opened.stderr[-400:]
    assert "DEMO_KEY=a-value" in (machine / ".env").read_text(encoding="utf-8")


def test_a_wrong_password_fails_cleanly(machine):
    """The app shows stderr verbatim, so it must be a sentence, not a stack trace."""
    _profile(machine)
    done = _cli("seal", "--password-stdin", home=machine, stdin="not the password\n")
    assert done.returncode == 1
    assert "Traceback" not in done.stderr
    assert done.stderr.strip() == "Wrong password"


def test_signin_and_signout_exit_zero(machine):
    _profile(machine)
    _cli("seal", "--password-stdin", home=machine, stdin=VAULT_PASSWORD + "\n")
    started = _cli("broker", "start", home=machine)
    assert started.returncode == 0, started.stderr[-400:]
    try:
        signed = _cli("signin", "--password-stdin", "--for", "15m",
                      home=machine, stdin=VAULT_PASSWORD + "\n")
        assert signed.returncode == 0, signed.stderr[-400:]

        state = json.loads(_cli("vault", "--json", home=machine).stdout)
        assert state["unlocked"] and state["fully_sealed"]

        out = _cli("signout", home=machine)
        assert out.returncode == 0, out.stderr[-400:]
        assert json.loads(_cli("vault", "--json", home=machine).stdout)["unlocked"] is False
    finally:
        _cli("broker", "stop", home=machine)


def test_no_vault_command_ever_takes_a_password_as_an_argument(machine):
    """A password in argv is readable by every process on the machine."""
    helptext = _cli("--help", home=machine).stdout
    for verb in ("seal", "unseal", "signin", "profile"):
        detail = _cli(verb, "--help", home=machine).stdout
        assert "--password " not in detail and "--password=" not in detail, verb
        assert "PASSWORD" not in detail.replace("--password-stdin", ""), verb
    assert "signin" in helptext and "unseal" in helptext


# ── presence must not lie about a sealed store ─────────────────────────────


def _sealed(home: Path):
    pw = "a properly long vault password\n"
    _cli("profile", "create", "Owner", "--password-stdin", home=home, stdin=pw)
    _cli("seal", "--password-stdin", home=home, stdin=pw)


def test_check_says_locked_not_missing_for_a_sealed_key(machine):
    """`check` had two answers where there are three, so a sealed store made it
    report a present, readable-through-the-broker key as `missing` — and then
    advise `passbook-add`, which would have overwritten a working credential
    with whatever the reader pasted."""
    _sealed(machine)
    done = _cli("check", "DEMO_KEY", home=machine)

    assert "DEMO_KEY: locked" in done.stdout
    assert "missing" not in done.stdout
    assert "passbook-add DEMO_KEY" not in done.stderr, "it advised overwriting a real key"
    assert "signin" in done.stderr


def test_check_still_says_missing_for_a_key_that_is_not_there(machine):
    _sealed(machine)
    done = _cli("check", "NOT_A_KEY", home=machine)
    assert "NOT_A_KEY: missing" in done.stdout
    assert "passbook-add NOT_A_KEY" in done.stderr
    assert done.returncode == 1


def test_check_separates_the_two_when_both_happen(machine):
    _sealed(machine)
    done = _cli("check", "DEMO_KEY", "NOT_A_KEY", home=machine)
    assert "DEMO_KEY: locked" in done.stdout
    assert "NOT_A_KEY: missing" in done.stdout
    # The destructive remedy must name only the key that is really absent.
    assert "passbook-add NOT_A_KEY" in done.stderr
    assert "passbook-add DEMO_KEY" not in done.stderr


def test_list_and_check_agree_about_what_the_store_holds(machine):
    """`list` read names and `check` read values, so they disagreed the moment
    the store was sealed — which is what sent someone hunting a lost key."""
    _sealed(machine)
    listed = [line.strip() for line in _cli("list", home=machine).stdout.splitlines() if line.strip()]
    assert "DEMO_KEY" in listed
    assert "DEMO_KEY: missing" not in _cli("check", "DEMO_KEY", home=machine).stdout
