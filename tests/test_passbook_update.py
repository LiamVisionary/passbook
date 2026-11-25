"""Updating an installed CLI must not strand sign-in or end live grants."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook
import passbook_broker as broker
import passbook_cli as cli
import passbook_vault as vault

PASSWORD = "synthetic update password"


@pytest.fixture
def machine(tmp_path, monkeypatch):
    for name in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "APP_SANDBOX_CONTAINER_ID"):
        monkeypatch.delenv(name, raising=False)
    for name in ("HIVE_HOME", "HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path))
    passbook.set_values({"EXISTING_KEY": "synthetic-original"})
    monkeypatch.setattr(broker, "running", lambda: True)
    monkeypatch.setattr(broker, "stop", lambda: pytest.fail("must preserve this broker"))
    monkeypatch.setattr(broker, "start", lambda: pytest.fail("must not start another broker"))
    monkeypatch.setattr(cli, "_ask_password", lambda *a, **k: pytest.fail("must not prompt"))
    return tmp_path


def unchanged(machine):
    assert not vault.profiles()
    assert passbook.parse_env_text((machine / ".env").read_text()) == {
        "EXISTING_KEY": "synthetic-original"}


def test_signin_preserves_a_healthy_running_broker(machine, monkeypatch, capsys):
    profile = vault.create_profile("Owner", password=PASSWORD)
    monkeypatch.setattr(broker, "vault_status", lambda **k: {
        "ok": True, "supported": True, "unlocked": True,
        "workspace": "main", "profile": profile["id"]})
    monkeypatch.setattr(broker, "_ask", lambda *a, **k: pytest.fail("no legacy probe needed"))
    assert cli.main(["signin"]) == 0
    assert "Already signed in" in capsys.readouterr().out


def test_signin_refreshes_an_unusable_legacy_broker_before_setup(machine, monkeypatch, capsys):
    events = []
    states = iter([{"ok": True, "supported": False}, {"ok": True, "supported": True}])
    monkeypatch.setattr(broker, "vault_status", lambda **k: next(states))
    def probe(payload):
        assert payload == {"op": "grants"}
        return {"ok": False, "error": "unknown operation"}
    monkeypatch.setattr(broker, "_ask", probe)
    monkeypatch.setattr(broker, "stop", lambda: events.append("stop") or {"ok": True})
    monkeypatch.setattr(broker, "start", lambda: events.append("start") or {"ok": True})
    def password(*args, **kwargs):
        assert events[:2] == ["stop", "start"]
        unchanged(machine)
        events.append("password")
        return PASSWORD
    monkeypatch.setattr(cli, "_ask_password", password)
    def signin(**kwargs):
        assert kwargs["password"] == PASSWORD
        assert kwargs["workspace"] == "main"
        assert kwargs["profile"] == vault.active_profile_id()
        return {"ok": True, "detail": "Signed in."}
    monkeypatch.setattr(broker, "signin", signin)
    assert cli.main(["signin"]) == 0
    assert events.count("stop") == 1
    assert vault.status()["fully_sealed"]
    said = capsys.readouterr()
    assert PASSWORD not in said.out + said.err
    assert "synthetic-original" not in said.out + said.err


@pytest.mark.parametrize("grants", [[], [{"id": "running-job"}]])
def test_unsupported_modern_broker_keeps_even_unlisted_running_jobs(machine, monkeypatch, capsys, grants):
    monkeypatch.setattr(broker, "vault_status", lambda **k: {"ok": True, "supported": False})
    monkeypatch.setattr(broker, "_ask", lambda *a, **k: {"ok": True, "grants": grants})
    assert cli.main(["signin"]) == 1
    unchanged(machine)
    assert "background service" in capsys.readouterr().err


@pytest.mark.parametrize("status", [None, {}, {"ok": True},
    {"ok": False, "supported": False, "error": "unavailable"},
    {"ok": True, "supported": 0}])
def test_ambiguous_vault_probe_never_refreshes_or_initializes(machine, monkeypatch, status):
    monkeypatch.setattr(broker, "vault_status", lambda **k: status)
    monkeypatch.setattr(broker, "_ask", lambda *a, **k: pytest.fail("not confirmed unsupported"))
    assert cli.main(["signin"]) == 1
    unchanged(machine)


@pytest.mark.parametrize("answer", [None, {}, {"ok": False, "error": "unavailable"},
    {"ok": False, "error": "unknown operation: grants"},
    {"ok": True, "error": "unknown operation"}])
def test_ambiguous_grants_probe_never_refreshes_or_initializes(machine, monkeypatch, answer):
    monkeypatch.setattr(broker, "vault_status", lambda **k: {"ok": True, "supported": False})
    monkeypatch.setattr(broker, "_ask", lambda *a, **k: answer)
    assert cli.main(["signin"]) == 1
    unchanged(machine)


@pytest.mark.parametrize("failure", ["stop", "start", "support"])
def test_failed_legacy_refresh_never_prompts_or_initializes(machine, monkeypatch, failure):
    monkeypatch.setattr(broker, "vault_status", lambda **k: {"ok": True, "supported": False})
    monkeypatch.setattr(broker, "_ask", lambda *a, **k: {"ok": False, "error": "unknown operation"})
    monkeypatch.setattr(broker, "stop", lambda: {"ok": failure != "stop", "detail": "stop unavailable"})
    if failure != "stop":
        monkeypatch.setattr(broker, "start", lambda: {"ok": failure != "start", "detail": "start unavailable"})
    assert cli.main(["signin"]) == 1
    unchanged(machine)


def test_missing_broker_uses_normal_first_signin_setup(machine, monkeypatch):
    monkeypatch.setattr(broker, "running", lambda: False)
    monkeypatch.setattr(broker, "vault_status", lambda **k: pytest.fail("no broker to probe"))
    monkeypatch.setattr(broker, "_ask", lambda *a, **k: pytest.fail("no broker to probe"))
    monkeypatch.setattr(broker, "start", lambda: {"ok": True})
    monkeypatch.setattr(cli, "_ask_password", lambda *a, **k: PASSWORD)
    monkeypatch.setattr(broker, "signin", lambda **k: {"ok": True})
    assert cli.main(["signin"]) == 0
    assert vault.status()["fully_sealed"]


def _behind_uv_tool_install(tmp_path, monkeypatch):
    """A uv tool install one release behind, with no background service to ask."""
    monkeypatch.setattr(passbook, "__file__", str(
        tmp_path / "uv/tools/passbook/lib/python3.12/site-packages/passbook.py"))
    monkeypatch.setenv("PASSBOOK_SOURCE", "git+https://example.test/passbook.git")
    monkeypatch.setattr(cli, "installed_version", lambda: "1.6.2")
    monkeypatch.setattr(cli, "latest_version", lambda: ("1.6.3", "v1.6.3"))
    monkeypatch.setattr(broker, "running", lambda: False)


def _recorded_runs(monkeypatch):
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(cli.subprocess, "run", run)
    return commands


def _program(path: Path) -> Path:
    """An empty file that PATH lookup accepts as a program on this platform."""
    if os.name == "nt":
        path = path.with_name(path.name + ".exe")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("")
    path.chmod(0o755)
    return path


def test_uv_update_preserves_interpreter_and_pins_the_release(tmp_path, monkeypatch):
    _behind_uv_tool_install(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_installer", lambda name: f"/found/{name}")
    interpreter = str(Path(getattr(sys, "_base_executable", None) or sys.executable).resolve())
    commands = _recorded_runs(monkeypatch)
    assert cli.main(["update"]) == 0
    assert commands == [["/found/uv", "tool", "install", "--force", "--python", interpreter,
                         "git+https://example.test/passbook.git@v1.6.3"]]


def test_update_finds_uv_where_a_short_path_leaves_it_out(tmp_path, monkeypatch):
    """2026-11-25: the app runs the command line with the PATH an app opened from
    the Dock gets, /usr/bin:/bin:/usr/sbin:/sbin, and its Update button answered
    with a FileNotFoundError traceback for `uv`, which that Mac keeps in
    /opt/homebrew/bin. uv is now looked for in the folders such a PATH leaves
    out, and run by its full path."""
    _behind_uv_tool_install(tmp_path, monkeypatch)
    home = tmp_path / "home"
    uv = _program(home / ".local" / "bin" / "uv")
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("PATH", str(tmp_path / "nothing-on-path"))
    commands = _recorded_runs(monkeypatch)
    assert cli.main(["update"]) == 0
    assert len(commands) == 1
    assert Path(commands[0][0]) == uv, "uv by its full path, not a bare name PATH cannot resolve"
    assert commands[0][1:4] == ["tool", "install", "--force"]


def test_an_installer_on_path_is_preferred_to_one_guessed(tmp_path, monkeypatch):
    """The folders are a fallback for a short PATH, not a second opinion on a full one."""
    home = tmp_path / "home"
    on_path = _program(tmp_path / "chosen" / "uv")
    guessed = _program(home / ".local" / "bin" / "uv")
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("PATH", str(on_path.parent))
    assert Path(cli._installer("uv")) == on_path
    monkeypatch.setenv("PATH", str(tmp_path / "nothing-on-path"))
    assert Path(cli._installer("uv")) == guessed
    assert cli._installer("no-such-installer-anywhere") == ""


def test_an_installer_that_will_not_run_is_said_in_a_sentence(tmp_path, monkeypatch, capsys):
    """The app shows what a failed update printed, as it is. With uv nowhere to be
    found, that was a traceback; now it is what is missing and where else to run it."""
    _behind_uv_tool_install(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_installer", lambda name: "")
    def missing(command, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", command[0])
    monkeypatch.setattr(cli.subprocess, "run", missing)
    assert cli.main(["update"]) == 1
    said = capsys.readouterr().err
    assert "Could not run uv, which installed this copy: No such file or directory." in said
    assert "In a terminal where uv runs:  passbook update" in said


def test_uv_interpreter_pin_uses_base_runtime_for_a_copied_venv_launcher(tmp_path, monkeypatch):
    target = tmp_path / "base/python.exe"
    target.parent.mkdir()
    target.touch()
    executable = tmp_path / "uv/tools/passbook/Scripts/python.exe"
    executable.parent.mkdir(parents=True)
    executable.touch()
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "_base_executable", str(target), raising=False)
    monkeypatch.setattr(passbook, "__file__", str(tmp_path / "uv/tools/passbook/Lib/site-packages/passbook.py"))
    method, command = cli.install_method()
    assert method == "uv tool"
    assert command[command.index("--python") + 1] == str(target.resolve())


def test_uv_interpreter_pin_falls_back_to_resolving_the_tool_symlink(tmp_path, monkeypatch):
    target = tmp_path / "base-python"
    target.touch()
    executable = tmp_path / "tool-python"
    try:
        executable.symlink_to(target)
    except OSError:
        pytest.skip("creating a symlink needs additional Windows privileges")
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.delattr(sys, "_base_executable", raising=False)
    monkeypatch.setattr(passbook, "__file__", str(tmp_path / "uv/tools/passbook/passbook.py"))
    method, command = cli.install_method()
    assert method == "uv tool"
    assert "--python" in command
    assert command[command.index("--python") + 1] == str(target.resolve())


def test_update_json_says_which_version_the_background_service_is_still_running(monkeypatch, capsys):
    """An update replaces files, not the process started from them; the app's Updates page shows the gap."""
    import argparse
    import json

    monkeypatch.setattr(cli, "installed_version", lambda: "1.10.5")
    monkeypatch.setattr(cli, "latest_version", lambda: ("1.10.5", "v1.10.5"))
    monkeypatch.setattr(cli, "install_method", lambda: ("uv tool", ["uv", "tool", "install"]))
    monkeypatch.setattr(broker, "running", lambda: True)
    monkeypatch.setattr(broker, "_ask", lambda message, timeout=1.0: {"version": "1.10.2"})
    assert cli.cmd_update(argparse.Namespace(json=True, check=False)) == 0
    said = json.loads(capsys.readouterr().out)
    assert said["service"] == "1.10.2" and said["service_behind"] is True and said["behind"] is False

    monkeypatch.setattr(broker, "_ask", lambda message, timeout=1.0: {"version": "1.10.5"})
    assert cli.cmd_update(argparse.Namespace(json=True, check=False)) == 0
    assert json.loads(capsys.readouterr().out)["service_behind"] is False

    monkeypatch.setattr(broker, "running", lambda: False)
    assert cli.cmd_update(argparse.Namespace(json=True, check=False)) == 0
    said = json.loads(capsys.readouterr().out)
    assert said["service"] == "" and said["service_behind"] is False, "no service is not a stale one"
