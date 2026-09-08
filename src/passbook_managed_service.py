# SPDX-License-Identifier: Apache-2.0
"""One user-owned login service for managed PassBook connections.

The service starts a locked broker. A verified request may open only its bound
workspace through that installation's device factor. Installing startup never
restarts a running broker or changes the owner's active workspace.
"""
from __future__ import annotations

import getpass
import json
import os
import plistlib
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence
from xml.etree import ElementTree as ET

import passbook
import passbook_broker as broker

LABEL = "com.rizzma.passbook.integrations"
TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
ROOT_MARKER = "PassBookManagedRoot"


class ServiceError(ValueError):
    def __init__(self, detail: str, code: str = "service-unavailable"):
        super().__init__(detail)
        self.code = code


def _system() -> str:
    return sys.platform


def _home() -> Path:
    return Path.home()


def _uid() -> int:
    return os.getuid()


def _user() -> str:
    name = os.environ.get("USERNAME") or getpass.getuser()
    domain = os.environ.get("USERDOMAIN")
    return f"{domain}\\{name}" if domain and "\\" not in name else name


def _clean(value: str) -> str:
    if not value or any(ord(char) < 32 for char in value):
        raise ServiceError("The startup command contains an invalid path.", "invalid-path")
    return value


def _quote_systemd(value: str, *, command: bool = True) -> str:
    value = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    if command:
        value = value.replace("$", "$$")
    return '"' + value + '"'


def _default_program() -> list[str]:
    # An absolute script path also works from a checkout. It avoids relying on
    # a login shell's PATH or PYTHONPATH to select the intended installation.
    return [sys.executable, str(Path(__file__).with_name("passbook_cli.py").resolve())]


def managed_service_plan(*, root: Path | None = None,
                         program: Sequence[str] | None = None) -> dict[str, Any]:
    """Render startup configuration without reading secrets or changing state."""
    system = _system()
    root = Path(root if root is not None else passbook.root()).expanduser().resolve()
    if isinstance(program, (str, bytes)):
        raise ServiceError("Pass the startup executable as an argument list.", "invalid-path")
    prefix = list(program) if program is not None else _default_program()
    if not prefix:
        raise ServiceError("A PassBook executable is required.", "invalid-path")
    command = [_clean(str(item)) for item in prefix] + ["broker", "run", "--root", _clean(str(root))]
    metadata = json.dumps({"label": LABEL, "root": str(root)}, sort_keys=True)
    if system == "darwin":
        import passbook_harden
        payload = passbook_harden.agent_plist(Path(command[0]), label=LABEL)
        payload.update({"ProgramArguments": command, "EnvironmentVariables": {"HIVE_HOME": str(root)},
                        ROOT_MARKER: str(root), "ThrottleInterval": 10})
        path = _home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"
        content = plistlib.dumps(payload)
    elif system.startswith("linux"):
        system = "linux"
        config = Path(os.environ.get("XDG_CONFIG_HOME") or _home() / ".config").expanduser()
        path = config / "systemd" / "user" / f"{LABEL}.service"
        content = (f"# {ROOT_MARKER}={metadata}\n"
                   "[Unit]\nDescription=PassBook managed connections\n\n[Service]\nType=simple\n"
                   f"ExecStart={' '.join(_quote_systemd(item) for item in command)}\n"
                   f"Environment={_quote_systemd('HIVE_HOME=' + str(root), command=False)}\n"
                   "Restart=on-failure\nRestartSec=10\nUMask=0077\n\n[Install]\nWantedBy=default.target\n").encode()
    elif system == "win32":
        if any("%" in item for item in command):
            raise ServiceError("Windows startup paths cannot contain environment-variable markers.", "invalid-path")
        ET.register_namespace("", TASK_NS)
        task = ET.Element(f"{{{TASK_NS}}}Task", {"version": "1.2"})
        def node(parent, tag, text=None, **attributes):
            item = ET.SubElement(parent, f"{{{TASK_NS}}}{tag}", attributes)
            if text is not None:
                item.text = text
            return item
        node(node(task, "RegistrationInfo"), "Description", metadata)
        trigger = node(node(task, "Triggers"), "LogonTrigger")
        node(trigger, "Enabled", "true")
        node(trigger, "UserId", _user())
        principal = node(node(task, "Principals"), "Principal", id="Owner")
        node(principal, "UserId", _user())
        node(principal, "LogonType", "InteractiveToken")
        node(principal, "RunLevel", "LeastPrivilege")
        settings = node(task, "Settings")
        for name, value in (("MultipleInstancesPolicy", "IgnoreNew"), ("DisallowStartIfOnBatteries", "false"),
                            ("StopIfGoingOnBatteries", "false"), ("StartWhenAvailable", "true"),
                            ("Enabled", "true"), ("ExecutionTimeLimit", "PT0S")):
            node(settings, name, value)
        restart = node(settings, "RestartOnFailure")
        node(restart, "Interval", "PT1M")
        node(restart, "Count", "999")
        execute = node(node(task, "Actions", Context="Owner"), "Exec")
        node(execute, "Command", command[0])
        node(execute, "Arguments", subprocess.list2cmdline(command[1:]))
        local = Path(os.environ.get("LOCALAPPDATA") or _home() / "AppData" / "Local")
        path = local / "PassBook" / "Services" / f"{LABEL}.xml"
        content = ET.tostring(task, encoding="utf-8", xml_declaration=True)
    else:
        raise ServiceError("Automatic startup is not supported on this platform.", "unsupported-platform")
    return {"label": LABEL, "platform": system, "root": str(root), "path": path,
            "command": command, "content": content}


def _definition_root(content: bytes, system: str) -> str:
    try:
        if system == "darwin":
            data = plistlib.loads(content)
            return data.get(ROOT_MARKER, "") if data.get("Label") == LABEL else ""
        if system == "linux":
            prefix = f"# {ROOT_MARKER}="
            first = content.decode().splitlines()[0]
            data = json.loads(first[len(prefix):]) if first.startswith(prefix) else {}
        else:
            task = ET.fromstring(content)
            data = json.loads(task.findtext(f"{{{TASK_NS}}}RegistrationInfo/{{{TASK_NS}}}Description") or "{}")
        return data.get("root", "") if data.get("label") == LABEL else ""
    except (ValueError, TypeError, AttributeError, IndexError, ET.ParseError):
        return ""


def _existing(plan: dict[str, Any]) -> bytes | None:
    path = plan["path"]
    if path.is_symlink():
        raise ServiceError("The startup definition is a symbolic link; it was left unchanged.", "service-conflict")
    try:
        old = path.read_bytes()
    except FileNotFoundError:
        return None
    if _definition_root(old, plan["platform"]) != plan["root"]:
        raise ServiceError("This startup label belongs to another definition or store; it was left unchanged.", "service-conflict")
    return old


def _run(command: list[str], *, required: bool = True):
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ServiceError("The user startup manager could not be reached.") from exc
    if required and done.returncode != 0:
        raise ServiceError("The user startup manager did not accept this change.")
    return done


def _task_definition() -> bytes | None:
    answer = _run(["schtasks", "/Query", "/TN", LABEL, "/XML"], required=False)
    return answer.stdout.encode() if answer.returncode == 0 and answer.stdout.strip() else None


def _public(plan: dict[str, Any]) -> dict[str, Any]:
    return {key: str(plan[key]) for key in ("label", "platform", "root", "path")}


def managed_service_state(*, root: Path | None = None) -> dict[str, Any]:
    try:
        plan = managed_service_plan(root=root)
        installed = _existing(plan) is not None
        if plan["platform"] == "win32":
            task = _task_definition()
            if task and _definition_root(task, "win32") != plan["root"]:
                raise ServiceError("This startup task belongs to another store.", "service-conflict")
            installed = installed and task is not None
        return {"ok": True, **_public(plan), "installed": installed,
                "running": broker.running(root=Path(plan["root"]))}
    except (ServiceError, OSError) as exc:
        return {"ok": False, "installed": False, "code": getattr(exc, "code", "service-unavailable"),
                "detail": str(exc)}


def install_managed_service(*, root: Path | None = None, install: bool = True,
                            program: Sequence[str] | None = None) -> dict[str, Any]:
    """Install next-login startup and keep the current broker available.

    `install=False` is an explicit embedding/test choice; it does not consult
    environment flags and never changes the user's service manager.
    """
    if not install:
        return {"ok": True, "installed": False, "skipped": True}
    plan = None
    old = None
    written = False
    registered = False
    previous_task = None
    try:
        plan = managed_service_plan(root=root, program=program)
        old = _existing(plan)
        if plan["platform"] == "win32":
            previous_task = _task_definition()
            if previous_task and _definition_root(previous_task, "win32") != plan["root"]:
                raise ServiceError("This startup task belongs to another store; it was left unchanged.", "service-conflict")
        if old != plan["content"]:
            passbook._atomic_write(plan["path"], plan["content"].decode())
            written = True
        system = plan["platform"]
        if system == "linux":
            _run(["systemctl", "--user", "daemon-reload"])
            registered = True
            _run(["systemctl", "--user", "enable", f"{LABEL}.service"])
        elif system == "win32" and (written or previous_task is None):
            command = ["schtasks", "/Create", "/TN", LABEL, "/XML", str(plan["path"])]
            if previous_task is not None:
                command.append("/F")  # only after verifying our own root-bound task
            registered = True
            _run(command)
        elif system == "darwin":
            # Undo this module's prior disable without replacing a running job.
            _run(["launchctl", "enable", f"gui/{_uid()}/{LABEL}"])
        answer = broker.start(root=Path(plan["root"]))
        if not answer.get("ok"):
            raise ServiceError("PassBook could not start its broker. Startup changes were rolled back.", "broker-unavailable")
        return {"ok": True, **_public(plan), "installed": True, "already": old == plan["content"],
                "running": True, "deferred": True,
                "detail": "PassBook is available now and will start at login. The current broker was preserved."}
    except (ServiceError, OSError) as exc:
        rollback_ok = True
        if plan and written:
            try:
                if old is None:
                    if registered and plan["platform"] == "linux":
                        cleanup = _run(["systemctl", "--user", "disable", f"{LABEL}.service"], required=False)
                        rollback_ok = rollback_ok and cleanup.returncode == 0
                    elif registered and plan["platform"] == "win32" and previous_task is None:
                        task = _task_definition()
                        if task and _definition_root(task, "win32") == plan["root"]:
                            cleanup = _run(["schtasks", "/Delete", "/TN", LABEL, "/F"], required=False)
                            rollback_ok = rollback_ok and cleanup.returncode == 0
                    plan["path"].unlink(missing_ok=True)
                else:
                    passbook._atomic_write(plan["path"], old.decode())
                    if registered and plan["platform"] == "win32":
                        cleanup = _run(["schtasks", "/Create", "/TN", LABEL, "/XML", str(plan["path"]), "/F"], required=False)
                        rollback_ok = rollback_ok and cleanup.returncode == 0
                if plan["platform"] == "linux":
                    cleanup = _run(["systemctl", "--user", "daemon-reload"], required=False)
                    rollback_ok = rollback_ok and cleanup.returncode == 0
            except (ServiceError, OSError):
                rollback_ok = False
        return {"ok": False, "installed": old is not None, "code": getattr(exc, "code", "service-unavailable"),
                "detail": str(exc), "rolledBack": rollback_ok}


def uninstall_managed_service(*, root: Path | None = None) -> dict[str, Any]:
    """Remove our startup registration without stopping current credential use."""
    try:
        plan = managed_service_plan(root=root)
        old = _existing(plan)
        if old is None:
            return {"ok": True, **_public(plan), "installed": False, "already": True}
        if plan["platform"] == "darwin":
            _run(["launchctl", "disable", f"gui/{_uid()}/{LABEL}"])
        elif plan["platform"] == "linux":
            _run(["systemctl", "--user", "disable", f"{LABEL}.service"])
        else:
            task = _task_definition()
            if task and _definition_root(task, "win32") != plan["root"]:
                raise ServiceError("This startup task belongs to another store; it was left unchanged.", "service-conflict")
            if task:
                _run(["schtasks", "/Delete", "/TN", LABEL, "/F"])
        plan["path"].unlink()
        if plan["platform"] == "linux":
            _run(["systemctl", "--user", "daemon-reload"])
        return {"ok": True, **_public(plan), "installed": False, "already": False,
                "detail": "Automatic startup was removed. The current broker and saved credentials were preserved."}
    except (ServiceError, OSError) as exc:
        return {"ok": False, "code": getattr(exc, "code", "service-unavailable"), "detail": str(exc)}
