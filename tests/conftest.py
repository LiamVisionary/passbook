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

import hashlib
import os
from pathlib import Path

import pytest

# The files a PassBook install touches outside its prefix.
def _watched() -> list[Path]:
    home = Path(os.environ.get("HOME") or os.environ.get("USERPROFILE") or "~").expanduser()
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    try:
        import passbook_brief
    except ImportError:  # the module is optional to the rest of the suite
        return []
    seen = []
    for runtime in passbook_brief.RUNTIMES:
        seen.append(home / runtime.context)
        if runtime.mcp:
            seen.append(home / runtime.mcp)
    return seen


def _fingerprint(paths: list[Path]) -> dict[str, str]:
    found = {}
    for path in paths:
        try:
            found[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            found[str(path)] = "absent"
    return found


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
