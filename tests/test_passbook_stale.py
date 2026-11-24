# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""A replaced key leaves no copy of its old value in an env file, found by value (passbook_stale.py).

On 2026-11-24 26 rotated Ami keys stayed stale in `~/ami-stream-build/.env.local`, a second checkout nobody had
attached, and another machine's agent hit 401 on the dead OpenRouter key. The claim tested here is the one Liam
asked for: rotating a key leaves no copy of the old value in any env-like file, on this machine or on another
that applies the push, including a file nothing ever attached, while a file that rightly holds a DIFFERENT key
under the same name is left alone.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook_stale as stale  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
OLD = "sk-or-v1-old-0123456789abcdefABCDEF"
NEW = "sk-or-v1-new-fedcba9876543210FEDCBA"
OTHER = "eleven-ami-key-aaaaaaaaaaaaaaaaaaaa"


class Machine:
    def __init__(self, base: Path):
        self.base = base
        self.home = base / "home"
        self.home.mkdir(parents=True)
        self.env = {**os.environ, "HIVE_HOME": str(base / "hive"), "HOME": str(self.home), "PASSBOOK_APP": "",
                    "PASSBOOK_NO_BRIEF": "1", "PASSBOOK_KEYSTORE": "off", "PASSBOOK_NO_NOTIFY": "1",
                    "PASSBOOK_FLEET": "off", "PASSBOOK_STALE": "on", "PASSBOOK_STALE_ROOTS": str(self.home),
                    "PYTHONPATH": str(REPO / "src")}
        for leaked in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "APP_SANDBOX_CONTAINER_ID", "PASSBOOK_GRANT"):
            self.env.pop(leaked, None)

    def run(self, *args, stdin=""):
        return subprocess.run([sys.executable, "-m", "passbook_cli", *args], input=stdin, capture_output=True,
                              text=True, env=self.env, cwd=str(REPO), timeout=120)

    def plant(self, relative: str, text: str, mode: int = 0o640) -> Path:
        file = self.home / relative
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(text.encode("utf-8"))
        os.chmod(file, mode)
        return file

    def wait_for_sweep(self, timeout: float = 60.0) -> None:
        """A background sweep holds stale.lock while it runs; wait until a run has finished."""
        lock = self.base / "hive" / stale.LOCK
        deadline = time.time() + timeout
        import fcntl

        time.sleep(0.5)
        while time.time() < deadline:
            if lock.exists():
                with open(lock, "a+") as handle:
                    try:
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(handle, fcntl.LOCK_UN)
                        return
                    except OSError:
                        pass
            time.sleep(0.2)
        raise AssertionError("the background sweep did not finish")


@pytest.fixture
def machine(tmp_path):
    box = Machine(tmp_path / "a")
    assert box.run("add", "--stdin", stdin=f"OPENROUTER_API_KEY={OLD}\nAMI_ELEVENLABS_API_KEY={OTHER}\n").returncode == 0
    return box


def _planted(box: Machine) -> dict[str, Path]:
    return {
        # A checkout nothing attached, holding the old value under another name, with every shape a line takes.
        "unattached": box.plant("ami-stream-build/.env.local",
                                "# Ami\r\n"
                                f"export OPENROUTER_KEY=\"{OLD}\"  # the router\r\n"
                                f"ELEVENLABS_API_KEY={OTHER}\r\n"
                                "PORT=8080\r\n"
                                f"SECOND='{OLD}'\r\n"),
        # The same NAME, rightly holding a different key: never touched.
        "same_name": box.plant("other-app/.env", "OPENROUTER_API_KEY=sk-or-v1-a-different-key-entirely-123\n"),
        "dev_vars": box.plant("worker/.dev.vars", f"OPENROUTER_API_KEY={OLD}\n"),
        "snapshot": box.plant("ami-stream-build/.env.local.bak-20261125", f"OPENROUTER_API_KEY={OLD}\n"),
        "skipped": box.plant("proj/node_modules/pkg/.env", f"OPENROUTER_API_KEY={OLD}\n"),
    }


def test_a_rotation_leaves_no_copy_of_the_old_value_in_any_env_file(machine):
    files = _planted(machine)
    machine.run("stale")  # what the daily pass has already done: noticed every value and listed the files
    done = machine.run("rotate", "OPENROUTER_API_KEY", "--stdin", stdin=NEW + "\n")
    assert done.returncode == 0, done.stderr
    assert "~/ami-stream-build/.env.local  OPENROUTER_KEY" in done.stdout
    assert OLD not in done.stdout + done.stderr and NEW not in done.stdout + done.stderr

    text = files["unattached"].read_bytes().decode("utf-8")
    assert OLD not in text
    assert text == ("# Ami\r\n"
                    f"export OPENROUTER_KEY=\"{NEW}\"  # the router\r\n"
                    f"ELEVENLABS_API_KEY={OTHER}\r\n"
                    "PORT=8080\r\n"
                    f"SECOND='{NEW}'\r\n")
    assert stat.S_IMODE(files["unattached"].stat().st_mode) == 0o640
    assert f"OPENROUTER_API_KEY={NEW}" in files["dev_vars"].read_text()
    assert "a-different-key" in files["same_name"].read_text()
    # Kept on purpose, so reported and never rewritten; and dependencies are never walked.
    assert OLD in files["snapshot"].read_text() and OLD in files["skipped"].read_text()

    # The file is a push target now, so the next rotation writes there directly.
    listed = machine.run("services", "list", "--json")
    services = __import__("json").loads(listed.stdout)["OPENROUTER_API_KEY"]
    paths = {item.get("path") for item in services if item.get("kind") == "env-file"}
    assert os.path.realpath(files["unattached"]) in paths

    # The previous version is kept, owner-only, beside the store and outside every swept folder.
    backups = list((machine.base / "hive" / stale.BACKUPS).rglob("*-.env.local"))
    assert backups and stat.S_IMODE(backups[0].stat().st_mode) == 0o600

    report = machine.run("stale", "--json")
    copies = __import__("json").loads(report.stdout)["copies"]
    assert [(item["file"], item["status"]) for item in copies] == [
        ("~/ami-stream-build/.env.local.bak-20261125", "snapshot")]


def test_another_machine_applying_the_push_sweeps_itself(machine, tmp_path):
    """The same rotation as it lands on a second machine: hive-env-add applies a push to a sealed store with
    `passbook add --stdin --replace`, and a sweep starts there on its own."""
    peer = Machine(tmp_path / "b")
    assert peer.run("add", "--stdin", stdin=f"OPENROUTER_API_KEY={OLD}\n").returncode == 0
    stray = peer.plant("ami-stream-build/.env.local", f"OPENROUTER_API_KEY={OLD}\nOTHER=x\n")
    applied = peer.run("add", "--stdin", "--replace", stdin=f"OPENROUTER_API_KEY={NEW}\n")
    assert applied.returncode == 0, applied.stderr
    peer.wait_for_sweep()
    assert stray.read_text() == f"OPENROUTER_API_KEY={NEW}\nOTHER=x\n"


def test_a_value_changed_any_other_way_is_noticed_by_the_next_look(machine):
    """A pull from another machine, or hive-env-add writing the store itself, goes round `rotate` and `add`."""
    files = _planted(machine)
    assert machine.run("stale").returncode == 0  # the values as they were
    sys_env = {**os.environ, **machine.env}
    subprocess.run([sys.executable, "-c", "import passbook; passbook.set_values({'OPENROUTER_API_KEY': %r}, "
                    "overwrite=True)" % NEW], env=sys_env, check=True, cwd=str(REPO))
    seen = machine.run("stale")
    assert "stale copy: ~/ami-stream-build/.env.local  OPENROUTER_KEY" in seen.stdout
    assert OLD in files["unattached"].read_text()  # a look changes nothing
    assert machine.run("stale", "--fix").returncode == 0
    assert OLD not in files["unattached"].read_text()


def test_a_rollback_puts_the_old_value_back_everywhere_the_sweep_moved_it(machine):
    files = _planted(machine)
    machine.run("stale")
    assert machine.run("rotate", "OPENROUTER_API_KEY", "--stdin", stdin=NEW + "\n").returncode == 0
    assert NEW in files["dev_vars"].read_text()
    rolled = machine.run("rotate", "OPENROUTER_API_KEY", "--rollback")
    assert rolled.returncode == 0, rolled.stderr
    assert f"OPENROUTER_API_KEY={OLD}" in files["dev_vars"].read_text()
    record = stale.read(machine.base / "hive")
    current = stale.mark(record, OLD)
    assert current not in record["retired"]  # current again, so not stale


def test_short_values_and_values_another_key_holds_are_never_retired(tmp_path):
    record = stale.read(tmp_path)
    raw = {"PORT": "8080", "FLAG": "true", "A": OLD, "B": OLD}
    stale.notice(record, raw, raw)
    stale.notice(record, {"PORT": "9090", "FLAG": "false"}, {**raw, "PORT": "9090", "FLAG": "false"})
    assert record["retired"] == {}
    assert stale.retire(record, "A", OLD) is False  # B still holds it


def test_a_folder_that_cannot_be_read_is_said_never_reported_clean(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    shut = tmp_path / "shut"
    shut.mkdir()
    (shut / ".env").write_text("X=1\n")
    os.chmod(shut, 0)
    try:
        found, unreadable = stale.discover([tmp_path])
        assert str(shut) in unreadable
    finally:
        os.chmod(shut, 0o700)


def test_the_env_file_target_writes_one_variable_in_place(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    file = tmp_path / ".env.local"
    file.write_text("# top\nexport A='old-value'  # note\nB=2\n")
    os.chmod(file, 0o600)
    assert stale.set_var(str(file), "A", "new-value") == "updated"
    assert stale.set_var(str(file), "C", "third") == "added"
    assert stale.set_var(str(file), "C", "third") == "unchanged"
    assert file.read_text() == "# top\nexport A='new-value'  # note\nB=2\nC=third\n"
    assert stat.S_IMODE(file.stat().st_mode) == 0o600
    with pytest.raises(ValueError):
        stale.set_var(str(file), "A", "it's quoted")


def test_the_suite_does_not_sweep_by_default():
    assert os.environ.get("PASSBOOK_STALE") == "off" and stale.off()


@pytest.mark.skipif(sys.platform == "win32", reason="the broker speaks over a Unix socket")
def test_on_a_sealed_store_the_old_value_is_read_before_it_is_replaced(machine):
    """The broker opens values by name, so a value read after the write is the new one: on a sealed store the
    sweep would have looked for the new value and found nothing."""
    files = _planted(machine)
    secured = machine.run("secure", "--profile-name", "Owner", "--password-stdin", stdin="throwaway-password-123\n")
    if secured.returncode != 0:
        pytest.skip(f"could not seal a store here: {secured.stderr[-200:]}")
    try:
        raw = (machine.base / "hive" / ".env").read_text()
        assert "OPENROUTER_API_KEY=hive-sealed:" in raw.replace("'", "").replace('"', "")
        # No earlier look, so nothing but the rotation itself knows what the old value was.
        done = machine.run("rotate", "OPENROUTER_API_KEY", "--stdin", stdin=NEW + "\n")
        assert done.returncode == 0, done.stderr
        machine.wait_for_sweep()
        assert OLD not in files["unattached"].read_text() and NEW in files["unattached"].read_text()
        assert f"OPENROUTER_API_KEY={NEW}" in files["dev_vars"].read_text()
        assert OLD not in done.stdout + done.stderr and NEW not in done.stdout + done.stderr
    finally:
        machine.run("broker", "stop")


def test_a_process_that_started_before_the_replacement_is_named_for_a_restart(monkeypatch):
    import passbook_broker

    now = time.time()
    monkeypatch.setattr(passbook_broker, "running", lambda: True)
    monkeypatch.setattr(passbook_broker, "_ask", lambda request: {"grants": [
        {"app": "ami-server", "pid": 41, "age_seconds": 3600, "keys": ["OPENROUTER_API_KEY", "OTHER"],
         "command": ["node", "server.js"]},
        {"app": "fresh", "pid": 42, "age_seconds": 5, "keys": ["OPENROUTER_API_KEY"], "command": ["node"]}]})
    named = stale.holders({"OPENROUTER_API_KEY": now - 60})
    assert named == [{"app": "ami-server", "pid": 41, "keys": ["OPENROUTER_API_KEY"], "command": "node server.js"}]
