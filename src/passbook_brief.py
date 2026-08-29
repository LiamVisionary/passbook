# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Telling the agents on this machine that PassBook is here.

PassBook installed 46 commands and an MCP server and then told nobody. An agent
on a machine with PassBook knew only whatever some other installer happened to
teach it, which on a HivemindOS box meant `hive-env-check` and `hive-env-run` —
both of which work, and neither of which knows the word "sealed".

That gap has a specific symptom. On a sealed store `hive-env-run` correctly
drops the values it cannot open, so an agent asking after a key sees it as
MISSING, reports it missing, and sometimes helpfully offers to add it again. The
credential was there the whole time and the vault was shut. Nothing anywhere
told the agent that state existed, or that `passbook signin` is its repair.

So this writes a short brief into the context file each runtime already reads.

## Why a managed block rather than a file of our own

Every one of these files belongs to somebody else, and several already carry a
HivemindOS block. Appending would duplicate on every install; rewriting the file
would delete a person's own notes. So the text lives between two markers, and
install rewrites exactly what is between them and never touches a byte outside.

## There is no ~/AGENTS.md

Worth stating because it is the obvious guess. AGENTS.md is a real standard —
Google, OpenAI, Factory, Sourcegraph and Cursor, tens of thousands of
repositories — but it is PROJECT scoped: the root of a repo, with nested files
for subprojects, and the nearest one wins. It defines no user-level file.

Global context is per-runtime convention instead, which is why the table below
is a table and not a constant. The closest thing to a universal one is Amp's
`~/.config/AGENTS.md`, which is Amp's convention rather than the standard's.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, NamedTuple

BEGIN = "<!-- BEGIN PASSBOOK -->"
END = "<!-- END PASSBOOK -->"


class Runtime(NamedTuple):
    """A coding agent, and the file it reads before it does anything."""

    id: str
    label: str
    # Present-on-this-machine evidence: any of these existing means it is here.
    marks: tuple[str, ...]
    # Where its global instructions live, relative to home.
    context: str


# Ordered for a readable listing, not by preference — every detected runtime is
# briefed. Paths are the documented global ones; a runtime that changes its mind
# about where it reads from is a one-line edit here rather than a rewrite.
RUNTIMES: tuple[Runtime, ...] = (
    Runtime("claude", "Claude Code", (".claude",), ".claude/CLAUDE.md"),
    Runtime("codex", "OpenAI Codex", (".codex",), ".codex/AGENTS.md"),
    Runtime("gemini", "Gemini CLI", (".gemini",), ".gemini/GEMINI.md"),
    Runtime("amp", "Sourcegraph Amp", (".config/amp", ".amp"), ".config/AGENTS.md"),
    Runtime("opencode", "opencode", (".config/opencode", ".opencode"),
            ".config/opencode/AGENTS.md"),
    Runtime("cursor", "Cursor", (".cursor",), ".cursor/rules/passbook.md"),
    Runtime("windsurf", "Windsurf", (".codeium/windsurf", ".windsurf"),
            ".codeium/windsurf/memories/global_rules.md"),
    Runtime("cline", "Cline", (".cline", "Documents/Cline/Rules"),
            "Documents/Cline/Rules/passbook.md"),
    Runtime("qwen", "Qwen Code", (".qwen",), ".qwen/QWEN.md"),
    Runtime("continue", "Continue", (".continue",), ".continue/rules/passbook.md"),
    Runtime("goose", "Goose", (".config/goose",), ".config/goose/.goosehints"),
    Runtime("crush", "Crush", (".config/crush", ".crush"), ".config/crush/CRUSH.md"),
    # HivemindOS's own runtimes. It briefs them about the hive env; this adds
    # what that brief cannot say, because those commands predate sealing.
    Runtime("hermes", "Hermes", (".hermes",), ".hermes/AGENTS.md"),
    Runtime("openclaw", "OpenClaw", (".openclaw",), ".openclaw/AGENTS.md"),
    Runtime("aeon", "AEON", (".aeon",), ".aeon/AGENTS.md"),
)


def home(environ: dict[str, str] | None = None) -> Path:
    source = os.environ if environ is None else environ
    return Path(source.get("HOME") or source.get("USERPROFILE") or "~").expanduser()


def detected(root: Path | None = None) -> list[Runtime]:
    """Every runtime with a footprint on this machine.

    Presence is a directory the runtime made, not a command on PATH: an agent
    can be installed anywhere and invoked by an editor that never puts it there,
    and briefing a runtime that is absent costs a file nobody reads.
    """
    base = root or home()
    return [r for r in RUNTIMES if any((base / m).exists() for m in r.marks)]


def context_path(runtime: Runtime, root: Path | None = None) -> Path:
    return (root or home()) / runtime.context


def block() -> str:
    """What every agent on this machine should know about credentials here.

    Short on purpose. It goes into the context of every agent for every prompt,
    so each line has to earn the tokens it costs, and the three states are the
    part that actually stops the failure this exists for.

    Deliberately not parameterised by this machine's store path. The RULE is
    what an agent needs — and an agent should be reaching for the commands, not
    for a path. Keeping the text byte-identical everywhere is also what lets
    `status` say whether a brief is current instead of only whether one exists.
    """
    return """## PassBook credentials

This machine keeps ONE credential store, shared by every app that opts in:
`$HIVE_HOME`, else `~/.hivemindos/.env`. PassBook owns it. `hive-env-check` and
`hive-env-run` still work and are the same store seen through older commands.

Never print, echo, log or paste a secret value. Refer to credentials by NAME and
by set/missing status. `passbook list` and `passbook check` are safe to show;
`passbook get` returns a value and its output is not.

```bash
passbook check OPENAI_API_KEY     # is it here, and can I read it
passbook list                     # every name, no values
passbook run -- <command>         # run something with the store loaded
passbook get OPENAI_API_KEY       # the value, recorded against your app name
```

**A key you cannot read is not necessarily missing.** There are three states and
they have different repairs, so do not treat them alike:

- **absent** — genuinely not in the store. `passbook add NAME` is the fix.
- **sealed, and the vault is locked** — it IS here, encrypted, and this machine
  cannot open it until somebody signs in. `passbook check` says so. The fix is
  `passbook signin`, and adding the key again would write a second copy.
- **refused** — present and readable, but this project or app is not allowed it.
  The refusal names the reason. `passbook umbrella` and `passbook projects` show
  what governs it. Adding it again fixes nothing.

Reporting a sealed or refused key as missing is the specific mistake this note
exists to prevent.

An agent that speaks MCP can use the server instead: `passbook mcp` on stdio
lists names and groups, and returns exactly one value per approved request."""


def _rewrite(text: str, body: str) -> str:
    """Replace the managed block, or append one. Everything else is untouched."""
    managed = f"{BEGIN}\n{body}\n{END}"
    start = text.find(BEGIN)
    end = text.find(END)
    if start != -1 and end != -1 and end > start:
        return text[:start] + managed + text[end + len(END):]
    if not text.strip():
        return managed + "\n"
    return text.rstrip("\n") + "\n\n" + managed + "\n"


def install(runtimes: Iterable[Runtime], *, root: Path | None = None) -> list[dict[str, str]]:
    """Write the brief into each runtime's context file. Idempotent."""
    body = block()
    written = []
    for runtime in runtimes:
        path = context_path(runtime, root)
        try:
            existing = path.read_text(encoding="utf-8") if path.is_file() else ""
        except (OSError, UnicodeDecodeError) as error:
            written.append({"id": runtime.id, "path": str(path), "state": f"unreadable: {error}"})
            continue
        updated = _rewrite(existing, body)
        if updated == existing:
            written.append({"id": runtime.id, "path": str(path), "state": "already current"})
            continue
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(updated, encoding="utf-8")
        except OSError as error:
            written.append({"id": runtime.id, "path": str(path), "state": f"not written: {error}"})
            continue
        written.append({
            "id": runtime.id, "path": str(path),
            "state": "updated" if BEGIN in existing else "briefed",
        })
    return written


def remove(runtimes: Iterable[Runtime], *, root: Path | None = None) -> list[dict[str, str]]:
    """Take the block back out, leaving everything around it as it was."""
    removed = []
    for runtime in runtimes:
        path = context_path(runtime, root)
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        start, end = text.find(BEGIN), text.find(END)
        if start == -1 or end == -1 or end < start:
            continue
        cleaned = (text[:start].rstrip("\n") + "\n" + text[end + len(END):].lstrip("\n")).strip()
        try:
            path.write_text(cleaned + "\n" if cleaned else "", encoding="utf-8")
        except OSError:
            continue
        removed.append({"id": runtime.id, "path": str(path), "state": "removed"})
    return removed


def status(root: Path | None = None) -> list[dict[str, object]]:
    """Which runtimes are here, and whether each carries a current brief."""
    body = block()
    found = []
    for runtime in detected(root):
        path = context_path(runtime, root)
        text = ""
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                text = ""
        has = BEGIN in text and END in text
        found.append({
            "id": runtime.id, "label": runtime.label, "path": str(path),
            "briefed": has, "current": has and body in text,
        })
    return found
