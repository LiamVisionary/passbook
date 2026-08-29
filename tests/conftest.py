# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Keep the suite off the machine it is running on.

`passbook install` writes OUTSIDE its own prefix now: it briefs the coding
agents it finds under HOME and registers an MCP server in their config files.
So overriding `HIVE_HOME` stopped being enough isolation, and two tests that
looked fine wrote into the developer's own ~/.claude/CLAUDE.md and
~/.claude.json — one of them through `install.sh`, where the missing variable
was three layers down.

Both were fixed where they were, and both were found by noticing a changed file
rather than by anything failing. This makes the next one fail instead. It is
deliberately a check rather than a sandbox: forcing HOME for every test would
hide the bug, and the bug is a test that forgot to.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

BEGIN = "<!-- BEGIN PASSBOOK -->"
END = "<!-- END PASSBOOK -->"


# The files a PassBook install touches outside its prefix.
def _watched() -> list[tuple[Path, str]]:
    home = Path(os.environ.get("HOME") or os.environ.get("USERPROFILE") or "~").expanduser()
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    try:
        import passbook_brief
    except ImportError:  # the module is optional to the rest of the suite
        return []
    seen = []
    for runtime in passbook_brief.RUNTIMES:
        seen.append((home / runtime.context, "context"))
        if runtime.mcp:
            seen.append((home / runtime.mcp, runtime.mcp_format or "json"))
    return seen


def _fingerprint(paths_and_kinds: list[tuple[Path, str]]) -> dict[str, str]:
    """PassBook's own footprint in each file — not the file's bytes.

    These files belong to running applications that write to them constantly:
    `~/.claude.json` holds session state and Claude Code updates it while the
    suite runs. Hashing the whole file therefore fails random tests for changes
    nothing here made, which is worse than no guard at all — a check that cries
    wolf gets deleted, and then the real leak ships.

    So this reads only the part PassBook would have written: the delimited block
    in a context file, and the `passbook` server in an MCP config.
    """
    import json as _json

    found = {}
    for path, kind in paths_and_kinds:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            found[str(path)] = "absent"
            continue
        if kind == "context":
            start, end = text.find(BEGIN), text.find(END)
            found[str(path)] = text[start:end] if start != -1 and end > start else "absent"
        elif kind == "toml":
            marker = "[mcp_servers.passbook]"
            at = text.find(marker)
            found[str(path)] = text[at:at + 200] if at != -1 else "absent"
        else:
            try:
                data = _json.loads(text) if text.strip() else {}
                entry = (data.get("mcpServers") or {}).get("passbook")
            except (ValueError, AttributeError):
                entry = None
            found[str(path)] = _json.dumps(entry, sort_keys=True) if entry else "absent"
    return found


@pytest.fixture(autouse=True)
def _no_briefing_from_the_suite(monkeypatch):
    """Every PassBook command now briefs on first run, so every test that runs
    one would write into the developer's own agent files.

    Off by default for the suite, and the briefing tests turn it back on for
    themselves inside a temporary home. Same shape as the check below: the
    default is safe, and asking for the real behaviour is explicit.
    """
    monkeypatch.setenv("PASSBOOK_NO_BRIEF", "1")


@pytest.fixture
def briefing_enabled(monkeypatch):
    """For tests that are ABOUT first-run briefing. Use only with a temp HOME."""
    monkeypatch.delenv("PASSBOOK_NO_BRIEF", raising=False)


@pytest.fixture(autouse=True)
def _the_real_machine_is_not_the_fixture():
    """Fail the test that wrote to a real agent's config, naming the file.

    Reported per test rather than once at the end, because "something in the
    suite touched your ~/.claude.json" costs an afternoon and "this test did"
    costs a minute.
    """
    watched = _watched()
    before = _fingerprint(watched)
    yield
    after = _fingerprint(watched)
    changed = [name for name, digest in after.items() if before.get(name) != digest]
    if changed:
        raise AssertionError(
            "this test wrote to a real agent config outside the test home:\n  "
            + "\n  ".join(changed)
            + "\n\n`passbook install` briefs the agents it finds under HOME, so a test "
              "that runs it must set HOME (and USERPROFILE) as well as HIVE_HOME."
        )
