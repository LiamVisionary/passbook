# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Telling the agents on this machine that PassBook exists.

PassBook installed 46 commands and an MCP server and told nobody. The symptom
was specific and it looked like a PassBook bug from the outside: on a sealed
store `hive-env-run` correctly drops values it cannot open, so an agent asking
after a key saw it as MISSING — and sometimes offered to add it again, over a
credential that was there the whole time behind a locked vault.

These files belong to other tools, and several already carry a HivemindOS block.
Most of what follows is about not damaging them.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

import passbook_brief as brief  # noqa: E402

HIVEMIND = """<!-- BEGIN HIVEMINDOS_SHARED_SKILLS -->
## Shared Hive Env
Use `hive-env-check KEY`.
<!-- END HIVEMINDOS_SHARED_SKILLS -->
"""


@pytest.fixture
def machine(tmp_path):
    """A home with two runtimes, one already carrying somebody else's block."""
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".claude/CLAUDE.md").write_text(
        HIVEMIND + "\n## My own notes\n\nKeep this.\n", encoding="utf-8")
    return tmp_path


def cli(*args, home: Path):
    return subprocess.run(
        [sys.executable, "-m", "passbook_cli", *args],
        capture_output=True, text=True, cwd=str(REPO),
        env={**os.environ, "HOME": str(home), "USERPROFILE": str(home),
             "HIVE_HOME": str(home / "hive"), "PYTHONPATH": str(SRC)},
    )


# ── finding the runtimes ────────────────────────────────────────────────────


def test_only_runtimes_with_a_footprint_are_found(machine):
    assert sorted(r.id for r in brief.detected(machine)) == ["claude", "codex"]


def test_a_machine_with_no_agents_is_not_an_error(tmp_path):
    assert brief.detected(tmp_path) == []


def test_every_runtime_declares_where_it_reads_from():
    for runtime in brief.RUNTIMES:
        assert runtime.marks and runtime.context, runtime.id
        assert not runtime.context.startswith("/"), f"{runtime.id}: must be home-relative"


def test_the_runtimes_are_distinct():
    ids = [r.id for r in brief.RUNTIMES]
    assert len(ids) == len(set(ids))


# ── writing into somebody else's file ───────────────────────────────────────


def test_another_tools_block_is_left_exactly_as_it_was(machine):
    path = machine / ".claude/CLAUDE.md"
    brief.install(brief.detected(machine), root=machine)
    text = path.read_text(encoding="utf-8")
    assert HIVEMIND.strip() in text, "the HivemindOS block was damaged"


def test_a_persons_own_notes_survive(machine):
    brief.install(brief.detected(machine), root=machine)
    assert "Keep this." in (machine / ".claude/CLAUDE.md").read_text(encoding="utf-8")


def test_installing_twice_leaves_one_block(machine):
    """The failure mode of appending: every install adds another copy, and the
    file grows until it crowds out the context it was meant to add to."""
    brief.install(brief.detected(machine), root=machine)
    brief.install(brief.detected(machine), root=machine)
    text = (machine / ".claude/CLAUDE.md").read_text(encoding="utf-8")
    assert text.count(brief.BEGIN) == 1 and text.count(brief.END) == 1


def test_the_second_install_reports_nothing_changed(machine):
    brief.install(brief.detected(machine), root=machine)
    again = brief.install(brief.detected(machine), root=machine)
    assert {entry["state"] for entry in again} == {"already current"}


def test_a_missing_context_file_is_created(machine):
    """Codex has a directory but no AGENTS.md here, which is the ordinary state
    of a freshly installed runtime."""
    assert not (machine / ".codex/AGENTS.md").exists()
    brief.install(brief.detected(machine), root=machine)
    assert brief.BEGIN in (machine / ".codex/AGENTS.md").read_text(encoding="utf-8")


def test_a_stale_block_is_replaced_rather_than_duplicated(machine):
    path = machine / ".codex/AGENTS.md"
    path.write_text(f"top\n\n{brief.BEGIN}\nOLD TEXT\n{brief.END}\n\nbottom\n", encoding="utf-8")
    brief.install(brief.detected(machine), root=machine)
    text = path.read_text(encoding="utf-8")
    assert "OLD TEXT" not in text
    assert text.count(brief.BEGIN) == 1
    assert text.startswith("top") and text.rstrip().endswith("bottom")


# ── taking it back out ──────────────────────────────────────────────────────


def test_removal_leaves_everything_else(machine):
    brief.install(brief.detected(machine), root=machine)
    brief.remove(brief.detected(machine), root=machine)
    text = (machine / ".claude/CLAUDE.md").read_text(encoding="utf-8")
    assert brief.BEGIN not in text
    assert HIVEMIND.strip() in text
    assert "Keep this." in text


def test_removing_when_nothing_is_installed_is_quiet(machine):
    assert brief.remove(brief.detected(machine), root=machine) == []


# ── what it actually says ───────────────────────────────────────────────────


def test_the_brief_names_all_three_states():
    """The whole reason this exists: a locked key reported as missing."""
    text = brief.block()
    assert "sealed" in text and "passbook signin" in text
    assert "refused" in text
    assert "absent" in text


def test_the_brief_forbids_printing_values():
    text = brief.block()
    assert "Never print" in text
    assert "passbook get" in text and "not" in text


def test_the_brief_says_the_older_commands_still_work():
    """A brief that contradicted HivemindOS's would make agents pick a side."""
    assert "hive-env-run" in brief.block()


def test_the_brief_points_at_the_mcp_server():
    assert "passbook mcp" in brief.block()


def test_the_brief_is_short_enough_to_carry_everywhere():
    """It is prepended to every prompt in every session of every runtime, so
    length is a running cost rather than a one-off."""
    assert len(brief.block()) < 2500, len(brief.block())


# ── through the command line ────────────────────────────────────────────────


def test_status_reports_each_runtime(machine):
    done = cli("brief", "--json", home=machine)
    assert done.returncode == 0, done.stderr
    found = {e["id"]: e for e in json.loads(done.stdout)}
    assert set(found) == {"claude", "codex"}
    assert all(not e["briefed"] for e in found.values())


def test_install_then_status_says_current(machine):
    assert cli("brief", "install", home=machine).returncode == 0
    found = json.loads(cli("brief", "--json", home=machine).stdout)
    assert all(e["current"] for e in found), found


def test_only_targets_one_runtime(machine):
    cli("brief", "install", "--only", "codex", home=machine)
    assert brief.BEGIN in (machine / ".codex/AGENTS.md").read_text(encoding="utf-8")
    assert brief.BEGIN not in (machine / ".claude/CLAUDE.md").read_text(encoding="utf-8")


def test_an_unknown_runtime_is_refused_with_the_list(machine):
    done = cli("brief", "install", "--only", "notarealagent", home=machine)
    assert done.returncode != 0
    assert "not a runtime" in done.stderr and "claude" in done.stderr


def test_no_value_reaches_an_agent_context_file(machine):
    """The brief is written on a machine with a live store. It must carry names
    and instructions, never a credential."""
    import passbook
    os.environ["HIVE_HOME"] = str(machine / "hive")
    passbook.ensure(app="test")
    passbook.set_values({"A_SECRET_KEY": "not-a-real-value"})
    cli("brief", "install", home=machine)
    for path in (machine / ".claude/CLAUDE.md", machine / ".codex/AGENTS.md"):
        assert "not-a-real-value" not in path.read_text(encoding="utf-8")


# ── the suite must not touch the machine it runs on ─────────────────────────


def test_installing_only_briefs_inside_the_home_it_was_given(tmp_path):
    """`install` writes OUTSIDE its own prefix, into agent context files it
    finds under HOME. A test that overrode only HIVE_HOME therefore wrote this
    block into the developer's own ~/.claude/CLAUDE.md every time the suite ran,
    which is exactly what happened once.

    Asserted here rather than only fixed in the setup tests, because the next
    person to add an install test will copy an existing one.
    """
    fake_home = tmp_path / "home"
    (fake_home / ".claude").mkdir(parents=True)
    done = subprocess.run(
        [sys.executable, "-m", "passbook_cli", "install",
         "--prefix", str(tmp_path / "bin"), "--no-runtime"],
        capture_output=True, text=True, cwd=str(REPO),
        env={**os.environ, "HIVE_HOME": str(tmp_path / "hive"),
             "HOME": str(fake_home), "USERPROFILE": str(fake_home),
             "PYTHONPATH": str(SRC)},
    )
    assert done.returncode == 0, done.stderr
    assert brief.BEGIN in (fake_home / ".claude/CLAUDE.md").read_text(encoding="utf-8")


def test_no_agents_leaves_every_context_file_alone(tmp_path):
    fake_home = tmp_path / "home"
    (fake_home / ".claude").mkdir(parents=True)
    subprocess.run(
        [sys.executable, "-m", "passbook_cli", "install", "--prefix", str(tmp_path / "bin"),
         "--no-runtime", "--no-agents"],
        capture_output=True, text=True, cwd=str(REPO),
        env={**os.environ, "HIVE_HOME": str(tmp_path / "hive"),
             "HOME": str(fake_home), "USERPROFILE": str(fake_home),
             "PYTHONPATH": str(SRC)},
    )
    assert not (fake_home / ".claude/CLAUDE.md").exists()


# ── MCP registration ────────────────────────────────────────────────────────
#
# These files belong to running tools and hold state far beyond MCP —
# ~/.claude.json is 70KB of session history. Every test here is about not
# damaging something.


CLAUDE_JSON = """{
  "userID": "abc",
  "mcpServers": {
    "hivemind": {"command": "node", "args": ["/somewhere/hivemind-mcp"]}
  },
  "seenNotifications": ["a", "b"]
}
"""

CODEX_TOML = """model = "gpt-5.6-sol"

[mcp_servers.hivemind]
command = "node"
args = ["/somewhere/hivemind-mcp"]

[mcp_servers.other]
command = "thing"
args = []
"""


@pytest.fixture
def configured(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".claude.json").write_text(CLAUDE_JSON, encoding="utf-8")
    (tmp_path / ".codex/config.toml").write_text(CODEX_TOML, encoding="utf-8")
    return tmp_path


def _runtimes(*ids):
    return [r for r in brief.RUNTIMES if r.id in ids]


def test_registering_keeps_every_other_server(configured):
    brief.register(_runtimes("claude", "codex"), root=configured)
    data = json.loads((configured / ".claude.json").read_text(encoding="utf-8"))
    assert sorted(data["mcpServers"]) == ["hivemind", "passbook"]
    assert data["mcpServers"]["hivemind"]["args"] == ["/somewhere/hivemind-mcp"]


def test_registering_keeps_unrelated_json_keys(configured):
    """`~/.claude.json` is mostly session state. Losing it would be losing the
    user's history to add one server."""
    brief.register(_runtimes("claude"), root=configured)
    data = json.loads((configured / ".claude.json").read_text(encoding="utf-8"))
    assert data["userID"] == "abc" and data["seenNotifications"] == ["a", "b"]


def test_the_toml_still_parses_and_keeps_its_other_tables(configured):
    tomllib = pytest.importorskip("tomllib")
    brief.register(_runtimes("codex"), root=configured)
    parsed = tomllib.loads((configured / ".codex/config.toml").read_text(encoding="utf-8"))
    assert parsed["model"] == "gpt-5.6-sol"
    assert sorted(parsed["mcp_servers"]) == ["hivemind", "other", "passbook"]
    assert parsed["mcp_servers"]["hivemind"]["command"] == "node"


def test_registering_twice_changes_nothing(configured):
    brief.register(_runtimes("claude", "codex"), root=configured)
    again = brief.register(_runtimes("claude", "codex"), root=configured)
    assert {e["state"] for e in again} == {"already registered"}


def test_a_backup_is_left_beside_the_file(configured):
    """These are other tools' files. If this gets it wrong the original should
    still be there to put back."""
    brief.register(_runtimes("claude"), root=configured)
    backup = configured / (".claude.json" + brief.BACKUP_SUFFIX)
    assert backup.is_file()
    assert json.loads(backup.read_text(encoding="utf-8"))["mcpServers"].keys() == {"hivemind"}


def test_unregistering_leaves_the_file_as_it_was(configured):
    tomllib = pytest.importorskip("tomllib")
    before = tomllib.loads((configured / ".codex/config.toml").read_text(encoding="utf-8"))
    brief.register(_runtimes("claude", "codex"), root=configured)
    brief.register(_runtimes("claude", "codex"), root=configured, remove=True)

    after = tomllib.loads((configured / ".codex/config.toml").read_text(encoding="utf-8"))
    assert after == before
    data = json.loads((configured / ".claude.json").read_text(encoding="utf-8"))
    assert sorted(data["mcpServers"]) == ["hivemind"]
    assert data["userID"] == "abc"


def test_a_runtime_with_nowhere_to_put_it_is_reported_not_skipped(configured):
    """Cline keeps servers in a VS Code extension's storage. Saying so beats
    appearing to have done something."""
    done = brief.register(_runtimes("cline"), root=configured)
    assert done[0]["state"] == "no MCP config to edit"


def test_a_damaged_config_is_left_alone(tmp_path):
    """Half-written JSON is somebody's problem, and overwriting it would make it
    this tool's problem too."""
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text("{not json", encoding="utf-8")
    done = brief.register(_runtimes("claude"), root=tmp_path)
    assert done[0]["state"].startswith("left alone")
    assert (tmp_path / ".claude.json").read_text(encoding="utf-8") == "{not json"


def test_the_server_command_is_absolute_when_it_can_be():
    """Agents are launched by editors whose PATH is not a login shell's."""
    entry = brief.server_entry()
    assert entry["args"] == ["mcp"]
    assert entry["command"].endswith("passbook")


def test_a_missing_config_file_is_created(tmp_path):
    (tmp_path / ".cursor").mkdir()
    brief.register(_runtimes("cursor"), root=tmp_path)
    data = json.loads((tmp_path / ".cursor/mcp.json").read_text(encoding="utf-8"))
    assert "passbook" in data["mcpServers"]


def test_status_says_whether_the_tools_are_there_too(configured):
    before = {e["id"]: e for e in brief.status(configured)}
    assert before["claude"]["mcp"] is False and before["claude"]["mcp_possible"] is True
    brief.register(_runtimes("claude"), root=configured)
    after = {e["id"]: e for e in brief.status(configured)}
    assert after["claude"]["mcp"] is True


# ── every way PassBook arrives ──────────────────────────────────────────────
#
# "Installed" means several different things here, and only some of them run
# code. `uv tool install` puts 46 commands on PATH and executes none of them.


def test_the_shell_installer_briefs(tmp_path):
    """install.sh hands over to `passbook install`, so it inherits this."""
    fake_home = tmp_path / "home"
    (fake_home / ".claude").mkdir(parents=True)
    done = subprocess.run(
        ["/bin/sh", str(REPO / "install.sh"), "--prefix", str(tmp_path / "bin"), "--no-runtime"],
        capture_output=True, text=True,
        env={**os.environ, "HIVE_HOME": str(tmp_path / "hive"), "HOME": str(fake_home),
             "USERPROFILE": str(fake_home), "PASSBOOK_PYTHON": sys.executable},
    )
    assert done.returncode == 0, done.stderr
    assert brief.BEGIN in (fake_home / ".claude/CLAUDE.md").read_text(encoding="utf-8")


def test_status_says_when_agents_have_not_been_briefed(tmp_path):
    """The path nothing can hook: `uv tool install` runs no code, so the first
    command a person types is the earliest honest moment to mention it."""
    fake_home = tmp_path / "home"
    (fake_home / ".claude").mkdir(parents=True)
    done = subprocess.run(
        [sys.executable, "-m", "passbook_cli", "status"],
        capture_output=True, text=True, cwd=str(REPO),
        env={**os.environ, "HIVE_HOME": str(tmp_path / "hive"), "HOME": str(fake_home),
             "USERPROFILE": str(fake_home), "PYTHONPATH": str(SRC)},
    )
    assert "not briefed" in done.stdout, done.stdout
    assert "passbook brief install" in done.stdout


def test_status_does_not_write_to_agent_files(tmp_path):
    """It reports and does not repair. Writing into somebody's CLAUDE.md as a
    side effect of asking for status is how a tool loses trust."""
    fake_home = tmp_path / "home"
    (fake_home / ".claude").mkdir(parents=True)
    subprocess.run(
        [sys.executable, "-m", "passbook_cli", "status"],
        capture_output=True, text=True, cwd=str(REPO),
        env={**os.environ, "HIVE_HOME": str(tmp_path / "hive"), "HOME": str(fake_home),
             "USERPROFILE": str(fake_home), "PYTHONPATH": str(SRC)},
    )
    assert not (fake_home / ".claude/CLAUDE.md").exists()


def test_status_is_quiet_once_everything_is_briefed(tmp_path):
    fake_home = tmp_path / "home"
    (fake_home / ".claude").mkdir(parents=True)
    env = {**os.environ, "HIVE_HOME": str(tmp_path / "hive"), "HOME": str(fake_home),
           "USERPROFILE": str(fake_home), "PYTHONPATH": str(SRC)}
    subprocess.run([sys.executable, "-m", "passbook_cli", "brief", "install"],
                   capture_output=True, text=True, cwd=str(REPO), env=env)
    done = subprocess.run([sys.executable, "-m", "passbook_cli", "status"],
                          capture_output=True, text=True, cwd=str(REPO), env=env)
    assert "not briefed" not in done.stdout, done.stdout


def test_the_app_briefs_on_launch():
    """The desktop app never runs `passbook install`, so it does this itself in
    its setup hook. Asserted against the source because the alternative is
    building and launching a Tauri app in a unit test."""
    source = (REPO / "app/src-tauri/src/main.rs").read_text(encoding="utf-8")
    setup = source[source.index("fn main()"):]
    assert '.arg("brief")' in setup and '.arg("install")' in setup
    assert "std::thread::spawn" in setup, "must not delay the window"
