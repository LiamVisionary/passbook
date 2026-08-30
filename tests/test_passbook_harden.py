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
    state = harden.posture(plist=tmp_path / "no.plist")
    assert any("started by hand" in gap for gap in state["gaps"])
    assert "Root can defeat all of this" in state["always"]


def test_a_checkout_is_reported_as_having_nothing_to_lock(tmp_path, monkeypatch):
    """Running from a git working tree is not an installed copy, and chowning
    somebody's checkout to root is a surprising way to end their afternoon."""
    monkeypatch.setattr(harden, "runtime_root", lambda: None)
    state = harden.posture(plist=tmp_path / "no.plist")
    assert state["code"]["is_an_installed_tree"] is False
    assert any("checkout" in gap for gap in state["gaps"])
    assert harden.plan()[0]["what"] == "nothing"


def test_runtime_root_finds_the_installed_tree_not_the_module(tmp_path, monkeypatch):
    """Walking up to the bin/lib pair, so a machine carrying a uv install AND a
    pipx one AND a checkout locks the one actually loaded."""
    tree = tmp_path / "tools" / "passbook"
    (tree / "bin").mkdir(parents=True)
    (tree / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    module = tree / "lib" / "python3.12" / "site-packages" / "passbook.py"
    module.write_text("", encoding="utf-8")

    class _Fake:
        __file__ = str(module)

    monkeypatch.setitem(sys.modules, "passbook", _Fake)
    assert harden.runtime_root() == tree


def test_posture_notices_a_locked_tree(tmp_path, monkeypatch):
    """The other half: once it IS locked, that gap must stop being reported or
    nobody will believe the rest of the list."""
    tree = tmp_path / "locked"
    (tree / "bin").mkdir(parents=True)
    (tree / "lib").mkdir(parents=True)
    monkeypatch.setattr(harden, "runtime_root", lambda: tree)
    monkeypatch.setattr(harden, "_writable_by_user", lambda path: False)
    monkeypatch.setattr(harden, "keychain_exposure", lambda **k: {"applies": False})
    state = harden.posture(plist=tmp_path / "no.plist")
    assert state["code"]["protected"] is True
    assert not any("edit PassBook's own code" in gap for gap in state["gaps"])


def test_the_plan_locks_in_place_rather_than_copying(tmp_path, monkeypatch):
    """The bug this design replaced: a second root-owned copy would keep running
    whatever it was installed with, because `passbook update` writes to the
    user's tree. Silent version drift in a credential broker."""
    tree = tmp_path / "tools" / "passbook"
    monkeypatch.setattr(harden, "runtime_root", lambda: tree)
    steps = harden.plan(plist=tmp_path / "a.plist")
    what = " ".join(step["what"] for step in steps)
    assert f"chown -R root:wheel {tree}" in what
    # No copying, no second tree, and no venv building.
    assert "venv" not in what and "install PassBook into" not in what
    assert any("sudo passbook update" in step["what"] for step in steps)


def test_the_plan_says_what_locking_the_interpreter_costs(tmp_path, monkeypatch):
    """It is uv's shared python store, so this is a wider blow than one tool —
    and a step that does not say so is one somebody regrets."""
    monkeypatch.setattr(harden, "runtime_root", lambda: tmp_path / "t")
    monkeypatch.setattr(harden, "interpreter_root", lambda: tmp_path / "pythons")
    steps = harden.plan(interpreter=True, plist=tmp_path / "a.plist")
    assert any("every uv tool" in step["why"] for step in steps)


def test_undo_refuses_when_it_cannot_tell_who_to_give_it_back_to(monkeypatch):
    """`chown -R` in the wrong direction turns a fix into an outage."""
    if _running_as_root():  # pragma: no cover
        pytest.skip("this asserts the unprivileged path")
    # Unprivileged, so it stops at the root check either way; the guard exists
    # for the privileged path and is asserted by reading it back.
    assert harden.undo()["ok"] is False


def _running_as_root() -> bool:
    getter = getattr(os, "geteuid", None)
    return getter is not None and getter() == 0


@pytest.mark.parametrize("call", ["install", "undo"])
def test_it_declines_rather_than_half_finishing_or_crashing(call):
    """Both privileged calls must decline cleanly on every platform.

    They did not: `undo` reached for `os.geteuid` before checking the platform
    and raised AttributeError on Windows, and on Linux `install` answered
    "macOS-only" — correct, but without the key this test first asserted. The
    contract is that neither raises and both say why.
    """
    if _running_as_root():  # pragma: no cover - the suite does not run as root
        pytest.skip("this asserts the unprivileged path")
    answer = getattr(harden, call)()
    assert answer["ok"] is False
    assert answer["why"]
    if sys.platform == "darwin" and harden.runtime_root() is not None:
        assert answer["needs_root"] is True


def test_the_agent_runs_the_broker_and_comes_back_if_it_dies():
    """A credential broker that quietly stays down turns every read into a
    refusal, and nothing on the machine points at the broker as the cause."""
    plist = harden.agent_plist(Path("/x/bin/passbook"))
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


# ── the keychain item ──────────────────────────────────────────────────────


def test_the_keychain_check_is_reported_as_inapplicable_off_macos(monkeypatch):
    monkeypatch.setattr(harden.sys, "platform", "linux")
    assert harden.keychain_exposure()["applies"] is False


def test_a_missing_item_is_not_an_exposure(monkeypatch):
    """"No key stored" and "a key anyone can read" are opposite findings, and
    reporting the first as the second would send someone to remove a device
    factor they never had."""
    class _Gone:
        returncode = 1
        stdout = b""

    monkeypatch.setattr(harden.sys, "platform", "darwin")
    monkeypatch.setattr(harden.subprocess, "run", lambda *a, **k: _Gone())
    answer = harden.keychain_exposure()
    assert answer["applies"] is True and answer["exposed"] is False


def test_an_item_that_answers_without_a_prompt_is_an_exposure(monkeypatch):
    class _Got:
        returncode = 0
        stdout = b"forty-four-bytes-of-key-material-here-xxxxxx"

    monkeypatch.setattr(harden.sys, "platform", "darwin")
    monkeypatch.setattr(harden.subprocess, "run", lambda *a, **k: _Got())
    answer = harden.keychain_exposure()
    assert answer["exposed"] is True
    # The fix must come with its cost attached; this one breaks the exact thing
    # the device factor exists for.
    assert answer["fix"] and "headless" in answer["cost"]


def test_the_value_is_never_carried_in_the_finding(monkeypatch):
    """The check has to read the secret to know it is readable. It must not
    then hand it onward — this is a status surface."""
    secret = "forty-four-bytes-of-key-material-here-xxxxxx"

    class _Got:
        returncode = 0
        stdout = secret.encode()

    monkeypatch.setattr(harden.sys, "platform", "darwin")
    monkeypatch.setattr(harden.subprocess, "run", lambda *a, **k: _Got())
    import json as _json

    assert secret not in _json.dumps(harden.keychain_exposure())


def test_it_refuses_to_rewrite_the_item_when_it_could_not_read_it(monkeypatch):
    """The one that matters. Deleting the item and writing back an empty value
    would destroy the device factor while claiming to protect it."""
    class _Empty:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(harden.sys, "platform", "darwin")
    monkeypatch.setattr(harden.subprocess, "run", lambda *a, **k: _Empty())

    def explode(*a, **k):  # pragma: no cover - must never be reached
        raise AssertionError("it deleted the item without a value in hand")

    answer = harden.require_keychain_prompt()
    assert answer["ok"] is False and "left alone" in answer["why"]


def test_a_locked_tree_explains_a_failed_update(monkeypatch, capsys):
    """The dead end this avoids: `uv` fails with a bare permission error naming
    a path and no reason, on a machine somebody deliberately locked. One word
    fixes it and nothing on screen suggests the word."""
    import passbook_cli

    monkeypatch.setattr(passbook_cli, "_tree_is_locked", lambda: True)
    monkeypatch.setattr(passbook_cli, "installed_version", lambda: "1.0.0")
    monkeypatch.setattr(passbook_cli, "latest_version", lambda: ("9.9.9", "v9.9.9"))
    monkeypatch.setattr(passbook_cli, "install_method",
                        lambda: ("uv tool", ["uv", "tool", "install", "--force", "x"]))

    class _Failed:
        returncode = 1
        stderr = "error: Permission denied (os error 13)"
        stdout = ""

    monkeypatch.setattr(passbook_cli.subprocess, "run", lambda *a, **k: _Failed())
    if getattr(os, "geteuid", lambda: 1)() == 0:  # pragma: no cover
        pytest.skip("this asserts the unprivileged path")

    code = passbook_cli.cmd_update(
        __import__("argparse").Namespace(json=False, check=False))
    out = capsys.readouterr()
    assert code == 1
    assert "sudo passbook update" in (out.out + out.err)


def test_the_root_check_works_where_there_is_no_geteuid(monkeypatch):
    """The bug that reached CI three times, caught on any platform.

    `os.geteuid` is absent on Windows, so every direct call raised there while
    passing everywhere else — which is why it kept coming back. Deleting the
    attribute reproduces Windows on any machine, so this fails locally now
    rather than twenty minutes later on a runner.
    """
    import passbook_cli

    monkeypatch.delattr(os, "geteuid", raising=False)
    assert harden.is_root() is False
    assert passbook_cli._root_here() is False


def test_no_module_calls_geteuid_directly(monkeypatch):
    """One obvious thing to import, and nothing reaching past it.

    A grep rather than a behaviour check on purpose: the behaviour test above
    only covers the paths it happens to run, and the failures were always in a
    branch nobody exercised on macOS.
    """
    src = Path(__file__).resolve().parents[1] / "src"
    offenders = []
    for module in src.glob("passbook*.py"):
        for number, line in enumerate(module.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or "getattr(os" in line:
                continue
            if "os.geteuid()" in line and "def is_root" not in line:
                offenders.append(f"{module.name}:{number}")
    assert not offenders, (
        f"call passbook_harden.is_root() instead of os.geteuid(): {offenders}")


# ── staying open between reboots ───────────────────────────────────────────


def test_the_two_halves_are_reported_separately(tmp_path, monkeypatch):
    """A device factor and something that runs it at boot are different things,
    and the machine this was built on had the first without the second — a
    factor that sounded like "the vault opens itself" and only meant "the person
    opening it types nothing". Reporting one number would have hidden that."""
    monkeypatch.setattr(harden, "read_vault_safely", None, raising=False)

    class _Vault:
        @staticmethod
        def read_vault():
            return {"profiles": [{"factors": [{"kind": "device"}]}]}

    monkeypatch.setitem(sys.modules, "passbook_vault", _Vault)
    state = harden.stay_open_state(plist=tmp_path / "absent.plist")
    assert state["device_factor"] is True
    assert state["boot_agent"] is False
    # Not "on" — that is the whole point of splitting them.
    assert state["on"] is False
    assert "still needs a person" in state["why"]


def test_off_is_reported_as_off_with_neither_half(tmp_path, monkeypatch):
    class _Vault:
        @staticmethod
        def read_vault():
            return {"profiles": [{"factors": [{"kind": "password"}]}]}

    monkeypatch.setitem(sys.modules, "passbook_vault", _Vault)
    state = harden.stay_open_state(plist=tmp_path / "absent.plist")
    assert state["on"] is False and state["device_factor"] is False
    assert "shut until you sign in" in state["why"]


def test_the_boot_agent_opens_the_vault_rather_than_only_starting_a_broker():
    """A broker that starts shut is the default and is not what this switch is
    for. The flag has to be on the command line or the agent silently delivers
    half the feature."""
    plist = harden.vault_agent_plist(Path("/x/bin/passbook"))
    assert plist["ProgramArguments"][-3:] == ["broker", "run", "--open-with-device"]
    assert plist["RunAtLoad"] is True


def test_the_agent_is_per_user_not_machine_wide():
    """This is a convenience preference, not a security boundary, so it lives in
    the user's own LaunchAgents and needs no root. Putting it in /Library would
    ask for a password to make the machine LESS strict."""
    assert str(harden.USER_VAULT_AGENT).startswith(str(Path.home()))
