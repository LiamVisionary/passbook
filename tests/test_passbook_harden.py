# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Refusing a debugger, and proving it with a debugger.

The interesting assertions here run `lldb` against a real process, because the
claim being made is about the kernel rather than about this code. A unit test
that only checked "we called ptrace" would have passed on a machine where the
call did nothing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook_harden as harden  # noqa: E402

# The tool an attacker would actually reach for. Absent on the CI runners that
# have no Xcode, and the point of this file is what the kernel does — so the
# proof tests skip rather than fail where it cannot be demonstrated.
_LLDB = shutil.which("lldb")
needs_lldb = pytest.mark.skipif(
    _LLDB is None or sys.platform != "darwin",
    reason="proving this needs lldb, which is macOS with developer tools")

CANARY = "canary-value-abcdef123456"


def _sleeper(deny: bool) -> str:
    """A script that holds a value in memory, optionally refusing debuggers."""
    prelude = (
        "import sys; sys.path.insert(0, %r)\n"
        "import passbook_harden; passbook_harden.deny_debugger()\n"
        % str(Path(__file__).resolve().parents[1] / "src")
    ) if deny else ""
    return prelude + f"SECRET = {CANARY!r}\nimport time; time.sleep(30)\n"


def _attaches(pid: int) -> bool:
    """Whether lldb can attach. True means the memory is readable."""
    try:
        done = subprocess.run([_LLDB, "-p", str(pid), "-b", "-o", "quit"],
                              capture_output=True, text=True, timeout=25)
    except subprocess.TimeoutExpired:
        # A denied attach can leave lldb waiting rather than erroring. Either
        # way it did not get in, which is the question being asked.
        return False
    return "stop reason" in (done.stdout + done.stderr)


@pytest.fixture
def sleeper():
    started: list[subprocess.Popen] = []

    def start(deny: bool) -> subprocess.Popen:
        child = subprocess.Popen([sys.executable, "-c", _sleeper(deny)])
        started.append(child)
        time.sleep(1.5)  # let the interpreter get past import and into sleep
        return child

    yield start
    for child in started:
        child.kill()


def test_it_reports_what_this_platform_can_do():
    """Never a claim it cannot back. A machine that cannot refuse a debugger
    must say so, because the alternative is a status screen that promises a
    boundary the kernel is not enforcing."""
    state = harden.status()
    assert state["supported"] == (sys.platform in ("darwin", "linux"))
    assert state["platform"] == sys.platform
    assert "root" in state["note"].lower()


def test_it_does_not_raise_on_a_platform_that_cannot(monkeypatch):
    """A credential daemon that will not start is an outage; one that starts
    slightly less hardened is a line in `status`."""
    monkeypatch.setattr(harden.sys, "platform", "sunos5")
    answer = harden.deny_debugger()
    assert answer["ok"] is False and answer["why"]


def test_preexec_is_none_where_it_cannot_run():
    """`preexec_fn` is unsupported on Windows and raises before the command
    runs, so the spawn sites must pass None rather than a no-op."""
    import passbook_grant

    hook = passbook_grant._hardened_child()
    if os.name == "nt" or not harden.available():
        assert hook is None
    else:
        assert callable(hook)


@needs_lldb
def test_an_ordinary_process_really_is_readable(sleeper):
    """The control. Without this, the test below proves nothing — a denied
    attach on a machine where nothing can be attached is not evidence."""
    assert _attaches(sleeper(deny=False).pid), (
        "lldb could not attach even without hardening; this machine cannot "
        "demonstrate the difference")


@needs_lldb
def test_a_hardened_process_refuses_the_debugger(sleeper):
    """The claim, checked against the tool an attacker would use."""
    child = sleeper(deny=True)
    assert not _attaches(child.pid)
    # And it is still running: refusing a debugger must not be a way to kill
    # the broker by trying to attach to it.
    assert child.poll() is None


@needs_lldb
def test_the_refusal_survives_exec_into_another_binary(sleeper):
    """The property the child hardening depends on, and the reason it can
    protect `wrangler` or `npm` — binaries that know nothing about PassBook.

    If the flag were cleared by exec, hardening the broker would protect the
    data key and leave every spawned credential in the open.
    """
    child = subprocess.Popen(
        [sys.executable, "-c", f"SECRET={CANARY!r}\nimport time; time.sleep(30)"],
        preexec_fn=harden.preexec)
    try:
        time.sleep(1.5)
        assert not _attaches(child.pid)
        assert child.poll() is None
    finally:
        child.kill()


# ── the daemon: root-owned code ────────────────────────────────────────────


def test_posture_names_the_gap_that_is_actually_open(tmp_path):
    """The report has to say the uncomfortable thing.

    On a normal install PassBook's code sits in the user's own home, so anything
    running as them can edit the redactor out of `passbook_grant` and never need
    a debugger. A posture report that omitted that would be worse than none —
    it would be a screen saying "hardened" over an open door.
    """
    state = harden.posture(runtime=tmp_path / "nowhere", plist=tmp_path / "no.plist")
    assert state["code"]["writable_by_you"] is True
    assert any("edit PassBook's own code" in gap for gap in state["gaps"])
    assert any("started by hand" in gap for gap in state["gaps"])
    assert "Root can defeat all of this" in state["always"]


def test_posture_never_omits_that_root_wins():
    assert "root" in harden.posture()["always"].lower()


def test_the_plan_is_readable_before_it_is_run():
    """A privileged installer that cannot be inspected first is one people run
    blind or not at all."""
    steps = harden.plan()
    assert steps and all(step["what"] and step["why"] for step in steps)
    # The step that does the actual work must be in there and must say so.
    assert any("chown" in step["what"] for step in steps)


def test_it_refuses_to_install_without_root_rather_than_half_finishing():
    if os.geteuid() == 0:  # pragma: no cover - the suite does not run as root
        pytest.skip("this asserts the unprivileged path")
    answer = harden.install()
    assert answer["ok"] is False and answer["needs_root"] is True


def test_undo_exists_and_also_needs_root():
    """Every privileged installer owes a way back."""
    if os.geteuid() == 0:  # pragma: no cover
        pytest.skip("this asserts the unprivileged path")
    assert harden.undo()["needs_root"] is True


def test_the_agent_runs_the_broker_and_comes_back_if_it_dies():
    """A credential broker that quietly stays down turns every read into a
    refusal, and nothing on the machine points at the broker as the cause."""
    plist = harden.agent_plist(Path("/usr/local/libexec/passbook/bin/passbook"))
    assert plist["ProgramArguments"][-2:] == ["broker", "run"]
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] == {"SuccessfulExit": False}


def test_it_is_a_launch_agent_not_a_daemon():
    """Deliberate: an Agent runs AS the user, so the login keychain, Touch ID
    and a store in the user's home all keep working. A daemon under its own uid
    has none of those, and a store it owned could strand the machine — which
    this project's own spec forbids a policy from doing."""
    assert "LaunchAgents" in str(harden.AGENT_PLIST)
    assert "LaunchDaemons" not in str(harden.AGENT_PLIST)
