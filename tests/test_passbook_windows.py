# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""What had to be true for Windows to be a platform rather than a build target.

A signed installer shipped that could not do anything once installed: the app
opened on "Could not run PassBook: program not found" because nothing had put
a CLI on the machine, and the CLI could not have signed in anyway because the
broker reached for `socket.AF_UNIX`, which CPython does not have on Windows.
Both were invisible from macOS, and the Windows CI job was green throughout —
the broker tests skipped themselves and the app was never installed.

These tests are the part of that which can be asserted from any machine. What
they cannot do is prove the pipe carries bytes on a real Windows kernel; the
broker suite does that, and it runs on Windows now precisely so it can.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import passbook_broker
import passbook_cli

REPO = Path(__file__).resolve().parents[1]
WINDOWS = os.name == "nt"


# ── the transport ──────────────────────────────────────────────────────────


def test_the_broker_names_a_transport_on_every_platform():
    """`endpoint` is what anything reporting the address asks.

    Before, half of these call sites read `socket_path` directly, which on
    Windows named a file that would never exist.
    """
    where = passbook_broker.endpoint()
    assert where
    if WINDOWS:
        assert where.startswith("\\\\.\\pipe\\")
    else:
        assert where.endswith(passbook_broker.SOCKET_FILENAME)


def test_the_pipe_module_refuses_to_load_where_it_makes_no_sense():
    """It is Windows-only and says so, rather than half-importing."""
    if WINDOWS:
        import passbook_pipe

        assert passbook_pipe.pipe_name(REPO).startswith("\\\\.\\pipe\\")
    else:
        with pytest.raises(ImportError):
            import passbook_pipe  # noqa: F401


@pytest.mark.skipif(not WINDOWS, reason="pipe naming is a Windows concern")
def test_two_stores_do_not_share_one_pipe():
    """Pipe names are machine-global, so the store has to be in the name.

    Sockets get this for free by being files inside the store. Getting it wrong
    here would point two different stores at one broker, and the second would
    be answered with the first one's keys.
    """
    import passbook_pipe

    assert passbook_pipe.pipe_name(REPO) != passbook_pipe.pipe_name(REPO / "other")


@pytest.mark.skipif(not WINDOWS, reason="the DACL is a Windows concern")
def test_the_pipe_is_restricted_to_this_user():
    """The named pipe's default DACL lets Everyone read. This one must not."""
    import passbook_pipe

    sid = passbook_pipe.current_user_sid()
    assert sid.startswith("S-1-")
    attributes, descriptor = passbook_pipe._security_attributes()
    try:
        assert attributes.lpSecurityDescriptor
    finally:
        passbook_pipe._kernel32.LocalFree(descriptor)


# ── the detach ─────────────────────────────────────────────────────────────


def test_the_broker_is_detached_by_a_means_this_platform_has():
    """`start_new_session` is POSIX. Windows accepts it and does nothing.

    So the broker stayed a child of whatever ran `passbook signin` and died
    with it — a sign-in that lasted exactly as long as the command that asked
    for one, which looks like the vault re-locking itself at random.
    """
    source = (REPO / "src" / "passbook_broker.py").read_text(encoding="utf-8")
    assert "_DETACHED_PROCESS" in source
    assert "creationflags" in source
    # The POSIX spelling must still be there for the platforms it works on.
    assert "start_new_session" in source


# ── the commands ───────────────────────────────────────────────────────────


def test_install_puts_the_commands_somewhere_windows_can_reach():
    """`~/.local/bin` is on nobody's PATH on Windows."""
    prefix = passbook_cli.default_prefix()
    if WINDOWS:
        assert ".local" not in prefix
        assert "PassBook" in prefix
    else:
        assert prefix == "~/.local/bin"


def test_the_windows_shim_does_not_leak_into_the_calling_prompt():
    """Without `setlocal`, running `passbook` once leaves PYTHONPATH set.

    Every command typed afterwards in that prompt would then import out of the
    checkout, which is a very confusing way to break an unrelated project.
    """
    body = passbook_cli.SHIM_WINDOWS % {
        "name": "passbook-add", "package": r"C:\x", "python": r"C:\py\python.exe"}
    assert "setlocal" in body
    # And the command's own exit code has to survive the shim, for the same
    # reason `passbook run` had to stop using `os.execvpe` on Windows.
    assert "exit /b" in body


def test_the_windows_shim_never_builds_an_empty_pythonpath_entry():
    """`set PYTHONPATH=x;%PYTHONPATH%` with nothing set leaves a trailing ';'.

    An empty entry on PYTHONPATH means the current directory, so every command
    would import from wherever it was run. The shim branches instead.
    """
    body = passbook_cli.SHIM_WINDOWS % {
        "name": "passbook", "package": r"C:\x", "python": r"C:\py\python.exe"}
    assert "if defined PYTHONPATH" in body


def test_every_command_gets_a_shim_windows_can_run():
    """A bare `passbook` resolves through PATHEXT, and no extension is on it."""
    subprocess.run([sys.executable, str(REPO / "scripts/stage-runtime.py")],
                   capture_output=True, text=True, check=True)
    staged = REPO / "app/src-tauri/bin"
    names = {path.stem for path in staged.glob("*.cmd")}
    expected = {"passbook", *passbook_cli.aliases()}
    assert expected <= names, f"missing shims: {sorted(expected - names)}"


# ── what the app carries ───────────────────────────────────────────────────


def test_the_staging_script_collects_every_module_the_cli_imports():
    """The app runs the CLI out of `cli/`, so a module left behind is an
    ImportError on somebody's desktop rather than a missing file here."""
    done = subprocess.run(
        [sys.executable, str(REPO / "scripts/stage-runtime.py")],
        capture_output=True, text=True,
    )
    assert done.returncode == 0, done.stderr
    staged = {path.name for path in (REPO / "app/src-tauri/cli").glob("*.py")}
    expected = {path.name for path in (REPO / "src").glob("passbook*.py")}
    assert staged == expected, f"staged {sorted(staged)}, repo has {sorted(expected)}"


def test_the_app_declares_the_cli_as_a_resource():
    """Staging it is half the job; the bundler has to be told to carry it."""
    import json

    config = json.loads((REPO / "app/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))
    assert "cli/**/*" in config["bundle"]["resources"]

    windows = json.loads(
        (REPO / "app/src-tauri/tauri.windows.conf.json").read_text(encoding="utf-8"))
    resources = windows["bundle"]["resources"]
    # Windows carries an interpreter too, because it is the one platform where
    # assuming a system Python is how this whole thing went wrong.
    for needed in ("cli/**/*", "runtime/**/*", "bin/**/*"):
        assert needed in resources, f"{needed} is not bundled on Windows"


def test_the_installer_puts_the_commands_on_path():
    """An app whose commands only work inside its own window is half a tool."""
    hooks = (REPO / "app/src-tauri/nsis/hooks.nsh").read_text(encoding="utf-8")
    assert "NSIS_HOOK_POSTINSTALL" in hooks
    assert "NSIS_HOOK_PREUNINSTALL" in hooks, "an uninstall must take its PATH entry with it"
    assert "path.ps1" in hooks

    import json
    windows = json.loads(
        (REPO / "app/src-tauri/tauri.windows.conf.json").read_text(encoding="utf-8"))
    assert windows["bundle"]["windows"]["nsis"]["installerHooks"] == "nsis/hooks.nsh"


def test_the_publisher_is_the_company_that_signs_it():
    """Windows showed `hivemindos`, derived from the identifier, while the
    Authenticode signature said Rizzma, Inc. Two answers to one question."""
    import json

    config = json.loads((REPO / "app/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))
    assert config["bundle"]["publisher"] == "Rizzma, Inc."


# ── the app's own resolution ───────────────────────────────────────────────


def test_the_app_looks_for_a_home_windows_actually_sets():
    """`HOME` is unset in a Windows desktop session; `USERPROFILE` is not.

    Reading only `HOME` made the path `.local/bin/passbook` — relative, matched
    nothing, and the fallback that was supposed to exist did not.
    """
    source = (REPO / "app/src-tauri/src/main.rs").read_text(encoding="utf-8")
    assert '"USERPROFILE"' in source


def test_the_app_falls_back_to_the_copy_it_carries():
    """The whole point: a fresh install with nothing else present still works."""
    source = (REPO / "app/src-tauri/src/main.rs").read_text(encoding="utf-8")
    assert "fn bundled_command" in source
    assert "resource_dir" in source
    # And it must not write bytecode into its own installed, signed bundle.
    assert "PYTHONPYCACHEPREFIX" in source


def test_stopping_a_broker_that_already_exited_is_not_an_error(tmp_path, monkeypatch):
    """POSIX raises ProcessLookupError; Windows raises WinError 87.

    `passbook broker stop` on a stale pid file answered "Could not stop the
    broker: [WinError 87] The parameter is incorrect", which reads like a bug
    rather than the ordinary case of a broker that is no longer there.
    """
    (tmp_path / passbook_broker.PID_FILENAME).write_text("999999", encoding="utf-8")

    def refuse(pid, sig):
        error = OSError(22, "The parameter is incorrect")
        error.winerror = 87
        raise error

    monkeypatch.setattr(passbook_broker.os, "kill", refuse)
    answer = passbook_broker.stop(root=tmp_path)

    assert answer["ok"], answer
    assert "already gone" in answer["detail"]
    assert not (tmp_path / passbook_broker.PID_FILENAME).exists(), "the stale pid file must go"


def test_the_shims_do_not_write_bytecode_into_the_install():
    """Python writes __pycache__ beside whatever it imports, and beside these
    modules is inside the installed app.

    Those .pyc files are not something the installer put there, so the
    uninstaller does not take them away: an uninstall left thirteen of them
    behind and the install directory with them. A per-machine install would not
    be writable there at all.
    """
    staged = REPO / "app/src-tauri/bin/passbook.cmd"
    if not staged.is_file():
        subprocess.run([sys.executable, str(REPO / "scripts/stage-runtime.py")],
                       capture_output=True, check=True)
    body = staged.read_text(encoding="ascii")
    assert "PYTHONPYCACHEPREFIX" in body
    assert "%~dp0..\\cli" not in body.split("PYTHONPYCACHEPREFIX")[1].split("\n")[0], \
        "the cache must not point back inside the install"
