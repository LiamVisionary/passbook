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
