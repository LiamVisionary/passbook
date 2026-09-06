"""Updating an installed CLI must not strand sign-in or end live grants."""
from __future__ import annotations

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


def test_uv_update_preserves_interpreter_and_pins_the_release(tmp_path, monkeypatch):
    monkeypatch.setattr(passbook, "__file__", str(
        tmp_path / "uv/tools/passbook/lib/python3.12/site-packages/passbook.py"))
    monkeypatch.setenv("PASSBOOK_SOURCE", "git+https://example.test/passbook.git")
    monkeypatch.setattr(cli, "installed_version", lambda: "1.6.2")
    monkeypatch.setattr(cli, "latest_version", lambda: ("1.6.3", "v1.6.3"))
    interpreter = str(Path(getattr(sys, "_base_executable", None) or sys.executable).resolve())
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(cli.subprocess, "run", run)
    assert cli.main(["update"]) == 0
    assert commands == [["uv", "tool", "install", "--force", "--python", interpreter,
                         "git+https://example.test/passbook.git@v1.6.3"]]


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
