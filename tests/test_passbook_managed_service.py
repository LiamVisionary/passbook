# SPDX-License-Identifier: Apache-2.0
"""Managed startup owns one definition, preserves running grants and rolls back."""
from __future__ import annotations

import plistlib
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook_broker as broker
import passbook_managed_service as service


@pytest.fixture
def machine(tmp_path, monkeypatch):
    home, root = tmp_path / "user home", tmp_path / "selected store"
    home.mkdir()
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(service, "_home", lambda: home)
    monkeypatch.setattr(service, "_system", lambda: "darwin")
    monkeypatch.setattr(service, "_uid", lambda: 501)
    monkeypatch.setattr(service, "_user", lambda: "test-user")
    monkeypatch.setattr(broker, "running", lambda **kwargs: True)
    starts = []
    monkeypatch.setattr(broker, "start", lambda **kwargs: starts.append(kwargs) or {"ok": True, "already": True})
    monkeypatch.setattr(broker, "stop", lambda **kwargs: pytest.fail("startup configuration must not kill a broker"))
    commands = []
    def manager(command, **kwargs):
        commands.append(command)
        assert kwargs.get("shell", False) is False
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(service.subprocess, "run", manager)
    return {"home": home, "root": root, "commands": commands, "starts": starts}


@pytest.mark.parametrize("platform", ["darwin", "linux", "win32"])
def test_startup_definition_pins_only_the_root_and_foreground_broker(machine, monkeypatch, platform):
    monkeypatch.setattr(service, "_system", lambda: platform)
    plan = service.managed_service_plan(root=machine["root"], program=["/tools with spaces/passbook"])
    assert plan["label"] == "com.rizzma.passbook.integrations"
    assert plan["command"] == ["/tools with spaces/passbook", "broker", "run", "--root", str(machine["root"])]
    definition = plan["content"].decode()
    assert "HIVE_WORKSPACE" not in definition and "open-with-device" not in definition
    if platform == "darwin":
        plist = plistlib.loads(plan["content"])
        assert plist["ProgramArguments"] == plan["command"]
        assert plist["EnvironmentVariables"] == {"HIVE_HOME": str(machine["root"])}
        assert plist["RunAtLoad"] is True
        assert "LaunchAgents" in str(plan["path"])
    elif platform == "linux":
        assert 'ExecStart="/tools with spaces/passbook" "broker" "run" "--root"' in definition
        assert "WantedBy=default.target" in definition
        assert "Restart=on-failure" in definition
    else:
        tree = ET.fromstring(definition)
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        assert tree.findtext("t:Actions/t:Exec/t:Command", namespaces=ns) == "/tools with spaces/passbook"
        assert tree.findtext("t:Principals/t:Principal/t:LogonType", namespaces=ns) == "InteractiveToken"
        assert tree.findtext("t:Principals/t:Principal/t:RunLevel", namespaces=ns) == "LeastPrivilege"
        assert tree.find("t:Triggers/t:LogonTrigger", ns) is not None


def test_disabled_install_does_no_work(machine):
    answer = service.install_managed_service(root=machine["root"], install=False)
    assert answer["ok"] and answer["skipped"]
    assert machine["commands"] == machine["starts"] == []
    assert list(machine["home"].iterdir()) == []


def test_install_is_idempotent_and_does_not_bootout_an_existing_broker(machine):
    args = {"root": machine["root"], "program": ["/tools/passbook"]}
    first = service.install_managed_service(**args)
    assert first["ok"] and first["installed"] and first["deferred"]
    original = Path(first["path"]).read_bytes()
    again = service.install_managed_service(**args)
    assert again["ok"] and again["already"]
    assert Path(first["path"]).read_bytes() == original
    assert all("bootout" not in command and "bootstrap" not in command for command in machine["commands"])


def test_a_different_root_cannot_take_over_the_same_service_label(machine):
    assert service.install_managed_service(root=machine["root"], program=["/tools/passbook"])["ok"]
    path = service.managed_service_plan(root=machine["root"], program=["/tools/passbook"])["path"]
    original = path.read_bytes()
    answer = service.install_managed_service(root=machine["root"].parent / "other", program=["/tools/passbook"])
    assert not answer["ok"] and answer["code"] == "service-conflict"
    assert path.read_bytes() == original


def test_an_unowned_definition_is_never_replaced_or_removed(machine):
    path = service.managed_service_plan(root=machine["root"])["path"]
    path.parent.mkdir(parents=True)
    path.write_text("another service owns this file")
    assert not service.install_managed_service(root=machine["root"])["ok"]
    assert not service.uninstall_managed_service(root=machine["root"])["ok"]
    assert path.read_text() == "another service owns this file"
    assert machine["commands"] == []


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_manager_failure_rolls_back_new_artifact_without_touching_other_services(machine, monkeypatch, platform):
    monkeypatch.setattr(service, "_system", lambda: platform)
    def failure(command, **kwargs):
        machine["commands"].append(command)
        return subprocess.CompletedProcess(command, 1, "", "synthetic service manager refusal")
    monkeypatch.setattr(service.subprocess, "run", failure)
    plan = service.managed_service_plan(root=machine["root"])
    answer = service.install_managed_service(root=machine["root"])
    assert not answer["ok"] and not plan["path"].exists()
    assert all(service.LABEL in " ".join(command) or command[-1] == "daemon-reload" for command in machine["commands"])


def test_broker_start_failure_rolls_back_only_new_startup_definition(machine, monkeypatch):
    monkeypatch.setattr(broker, "running", lambda **kwargs: False)
    monkeypatch.setattr(broker, "start", lambda **kwargs: {"ok": False, "detail": "could not start"})
    plan = service.managed_service_plan(root=machine["root"])
    answer = service.install_managed_service(root=machine["root"])
    assert not answer["ok"] and not plan["path"].exists()


def test_uninstall_is_idempotent_and_leaves_vault_and_other_agents_alone(machine):
    answer = service.install_managed_service(root=machine["root"])
    unrelated = Path(answer["path"]).with_name("com.rizzma.passbook.vault.plist")
    unrelated.write_text("unrelated vault service")
    assert service.uninstall_managed_service(root=machine["root"])["ok"]
    assert not Path(answer["path"]).exists()
    assert unrelated.read_text() == "unrelated vault service"
    assert service.uninstall_managed_service(root=machine["root"])["already"]


def test_systemd_arguments_escape_specifiers_and_environment_expansion(machine, monkeypatch):
    monkeypatch.setattr(service, "_system", lambda: "linux")
    plan = service.managed_service_plan(root=machine["root"].parent / 'a%name $HOME "quoted"', program=["/bin/passbook"])
    text = plan["content"].decode()
    assert "a%%name $$HOME" in text and '\\"quoted\\"' in text


def test_unsupported_platform_has_no_side_effects(machine, monkeypatch):
    monkeypatch.setattr(service, "_system", lambda: "freebsd")
    answer = service.install_managed_service(root=machine["root"])
    assert not answer["ok"] and answer["code"] == "unsupported-platform"
    assert machine["commands"] == machine["starts"] == []


def test_windows_installs_queries_and_removes_only_its_owned_task(machine, monkeypatch):
    monkeypatch.setattr(service, "_system", lambda: "win32")
    task = {"content": None}
    def manager(command, **kwargs):
        machine["commands"].append(command)
        assert command[0] == "schtasks" and command[command.index("/TN") + 1] == service.LABEL
        if "/Query" in command:
            return subprocess.CompletedProcess(command, 0 if task["content"] else 1, task["content"] or "", "")
        if "/Create" in command:
            task["content"] = Path(command[command.index("/XML") + 1]).read_text()
        if "/Delete" in command:
            task["content"] = None
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(service.subprocess, "run", manager)
    first = service.install_managed_service(root=machine["root"])
    assert first["ok"] and task["content"]
    assert service.managed_service_state(root=machine["root"])["installed"]
    assert service.install_managed_service(root=machine["root"])["already"]
    assert sum("/Create" in command for command in machine["commands"]) == 1
    assert not any("/Run" in command or "/End" in command for command in machine["commands"])
    assert service.uninstall_managed_service(root=machine["root"])["ok"]
    assert task["content"] is None


def test_existing_startup_file_is_restored_when_an_update_fails(machine, monkeypatch):
    assert service.install_managed_service(root=machine["root"], program=["/old/passbook"])["ok"]
    path = service.managed_service_plan(root=machine["root"])["path"]
    original = path.read_bytes()
    monkeypatch.setattr(broker, "start", lambda **kwargs: {"ok": False})
    answer = service.install_managed_service(root=machine["root"], program=["/new/passbook"])
    assert not answer["ok"] and answer["rolledBack"]
    assert path.read_bytes() == original


def test_registered_windows_task_for_another_root_is_preserved_even_without_local_xml(machine, monkeypatch):
    monkeypatch.setattr(service, "_system", lambda: "win32")
    foreign = service.managed_service_plan(root=machine["root"].parent / "other")["content"].decode()
    def manager(command, **kwargs):
        assert "/Query" in command
        return subprocess.CompletedProcess(command, 0, foreign, "")
    monkeypatch.setattr(service.subprocess, "run", manager)
    answer = service.install_managed_service(root=machine["root"])
    assert answer["code"] == "service-conflict"
    assert not service.managed_service_plan(root=machine["root"])["path"].exists()


def test_definition_rejects_symlinks_and_control_characters(machine):
    path = service.managed_service_plan(root=machine["root"])["path"]
    path.parent.mkdir(parents=True)
    other = machine["home"] / "unrelated"
    other.write_text("preserve")
    try:
        path.symlink_to(other)
    except OSError:
        pytest.skip("this Windows account cannot create symlinks")
    assert service.install_managed_service(root=machine["root"])["code"] == "service-conflict"
    assert other.read_text() == "preserve"
    with pytest.raises(service.ServiceError):
        service.managed_service_plan(root=machine["root"], program=["/tools/passbook\ninvalid"])
