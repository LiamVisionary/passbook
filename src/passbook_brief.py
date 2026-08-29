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
    """A coding agent, the file it reads, and where it keeps its MCP servers."""

    id: str
    label: str
    # Present-on-this-machine evidence: any of these existing means it is here.
    marks: tuple[str, ...]
    # Where its global instructions live, relative to home.
    context: str
    # Where its MCP server list lives, and in what shape. Empty means this
    # runtime either speaks no MCP or keeps the list somewhere this cannot
    # safely edit — a VS Code extension's settings, say. Briefing still works
    # for those; only the tools do not.
    mcp: str = ""
    mcp_format: str = ""


# Ordered for a readable listing, not by preference — every detected runtime is
# briefed. Paths are the documented global ones; a runtime that changes its mind
# about where it reads from is a one-line edit here rather than a rewrite.
RUNTIMES: tuple[Runtime, ...] = (
    Runtime("claude", "Claude Code", (".claude",), ".claude/CLAUDE.md",
            ".claude.json", "json"),
    Runtime("codex", "OpenAI Codex", (".codex",), ".codex/AGENTS.md",
            ".codex/config.toml", "toml"),
    Runtime("gemini", "Gemini CLI", (".gemini",), ".gemini/GEMINI.md",
            ".gemini/settings.json", "json"),
    Runtime("amp", "Sourcegraph Amp", (".config/amp", ".amp"), ".config/AGENTS.md",
            ".config/amp/settings.json", "json"),
    Runtime("opencode", "opencode", (".config/opencode", ".opencode"),
            ".config/opencode/AGENTS.md", ".config/opencode/opencode.json", "json"),
    Runtime("cursor", "Cursor", (".cursor",), ".cursor/rules/passbook.md",
            ".cursor/mcp.json", "json"),
    Runtime("windsurf", "Windsurf", (".codeium/windsurf", ".windsurf"),
            ".codeium/windsurf/memories/global_rules.md",
            ".codeium/windsurf/mcp_config.json", "json"),
    # Cline keeps its servers inside a VS Code extension's storage, which is not
    # a file to hand-edit. It gets the brief and not the tools.
    Runtime("cline", "Cline", (".cline", "Documents/Cline/Rules"),
            "Documents/Cline/Rules/passbook.md"),
    Runtime("qwen", "Qwen Code", (".qwen",), ".qwen/QWEN.md",
            ".qwen/settings.json", "json"),
    Runtime("continue", "Continue", (".continue",), ".continue/rules/passbook.md"),
    Runtime("goose", "Goose", (".config/goose",), ".config/goose/.goosehints"),
    Runtime("crush", "Crush", (".config/crush", ".crush"), ".config/crush/CRUSH.md",
            ".config/crush/crush.json", "json"),
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
            "mcp_possible": bool(runtime.mcp),
            "mcp": registered(runtime, root),
        })
    return found


# ── MCP servers ─────────────────────────────────────────────────────────────
#
# The brief tells an agent which commands exist. Registering the MCP server
# gives it tools instead: `list_credentials` returns names and groups and never
# a value, `get_credential` returns exactly one and leaves a receipt. An agent
# that has the tools does not have to shell out, and cannot accidentally print a
# value into a transcript by running `passbook get` and reading the output.
#
# Every one of these files belongs to a runtime that is probably running, and
# several hold state well beyond MCP — `~/.claude.json` is 70KB of session
# history. So: only the one key is ever written, a backup is taken first, the
# write is atomic, and the file's existing indentation is matched rather than
# reformatted.

SERVER_NAME = "passbook"
BACKUP_SUFFIX = ".passbook-bak"


def server_entry(command: str = "") -> dict[str, object]:
    """The stdio server every runtime is told about.

    An absolute path when one can be found: an agent is often launched by an
    editor whose PATH is not a login shell's, and `passbook` resolving for the
    person and not for the process is a confusing way to fail.
    """
    import shutil

    resolved = command or shutil.which("passbook") or "passbook"
    return {"command": resolved, "args": ["mcp"]}


def _atomic_write(path: Path, text: str) -> None:
    temporary = path.with_suffix(path.suffix + ".passbook-tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def _json_register(path: Path, entry: dict[str, object], *, remove: bool) -> str:
    import json

    try:
        original = path.read_text(encoding="utf-8") if path.is_file() else ""
        data = json.loads(original) if original.strip() else {}
    except (OSError, UnicodeDecodeError, ValueError) as error:
        return f"left alone: {error}"
    if not isinstance(data, dict):
        return "left alone: not a JSON object"

    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        if remove:
            return "not registered"
        servers = {}

    if remove:
        if SERVER_NAME not in servers:
            return "not registered"
        del servers[SERVER_NAME]
    else:
        if servers.get(SERVER_NAME) == entry:
            return "already registered"
        servers[SERVER_NAME] = entry
    data["mcpServers"] = servers

    # Match what is there rather than reformatting somebody's file into a diff
    # they did not ask for.
    indent = 2 if "\n  " in original or original.count("\n") > 3 else None
    rendered = json.dumps(data, indent=indent, ensure_ascii=False)
    try:
        if original:
            path.with_suffix(path.suffix + BACKUP_SUFFIX).write_text(original, encoding="utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, rendered + ("\n" if original.endswith("\n") or not original else ""))
    except OSError as error:
        return f"not written: {error}"
    return "unregistered" if remove else "registered"


_TOML_BEGIN = "# BEGIN PASSBOOK MCP"
_TOML_END = "# END PASSBOOK MCP"


def _toml_register(path: Path, entry: dict[str, object], *, remove: bool) -> str:
    """Codex keeps its servers in TOML, which the standard library can read and
    cannot write. Rather than take a dependency to emit six lines, the block is
    delimited and rewritten as text — the same trick the brief uses, for the
    same reason: everything outside the markers is left exactly as it was.
    """
    import json

    try:
        original = path.read_text(encoding="utf-8") if path.is_file() else ""
    except (OSError, UnicodeDecodeError) as error:
        return f"left alone: {error}"

    args = ", ".join(json.dumps(a) for a in entry["args"])  # type: ignore[index]
    block = (f"{_TOML_BEGIN}\n"
             f"[mcp_servers.{SERVER_NAME}]\n"
             f"command = {json.dumps(entry['command'])}\n"
             f"args = [{args}]\n"
             f"{_TOML_END}")

    start, end = original.find(_TOML_BEGIN), original.find(_TOML_END)
    has = start != -1 and end != -1 and end > start
    if remove:
        if not has:
            return "not registered"
        updated = (original[:start].rstrip("\n") + "\n"
                   + original[end + len(_TOML_END):].lstrip("\n"))
    elif has:
        if original[start:end + len(_TOML_END)] == block:
            return "already registered"
        updated = original[:start] + block + original[end + len(_TOML_END):]
    else:
        # A bare `[mcp_servers.passbook]` appended after another table's keys
        # would be fine, but appended INSIDE one would silently become that
        # table's key. Ending with a newline and starting a fresh table is what
        # keeps it a sibling.
        updated = (original.rstrip("\n") + "\n\n" + block + "\n") if original.strip() else block + "\n"

    try:
        if original:
            path.with_suffix(path.suffix + BACKUP_SUFFIX).write_text(original, encoding="utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, updated)
    except OSError as error:
        return f"not written: {error}"
    return "unregistered" if remove else "registered"


def register(runtimes: Iterable[Runtime], *, root: Path | None = None,
             command: str = "", remove: bool = False) -> list[dict[str, str]]:
    """Add (or take out) PassBook's MCP server for each runtime that has a place
    to put it. A runtime with no `mcp` is reported, not silently skipped."""
    entry = server_entry(command)
    done = []
    for runtime in runtimes:
        if not runtime.mcp:
            done.append({"id": runtime.id, "path": "", "state": "no MCP config to edit"})
            continue
        path = (root or home()) / runtime.mcp
        if runtime.mcp_format == "toml":
            state = _toml_register(path, entry, remove=remove)
        else:
            state = _json_register(path, entry, remove=remove)
        done.append({"id": runtime.id, "path": str(path), "state": state})
    return done


def registered(runtime: Runtime, root: Path | None = None) -> bool:
    """Is PassBook's server in this runtime's list right now?"""
    if not runtime.mcp:
        return False
    path = (root or home()) / runtime.mcp
    if not path.is_file():
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    if runtime.mcp_format == "toml":
        return f"[mcp_servers.{SERVER_NAME}]" in text
    import json

    try:
        data = json.loads(text) if text.strip() else {}
    except ValueError:
        return False
    return isinstance(data, dict) and SERVER_NAME in (data.get("mcpServers") or {})


# ── the first time PassBook runs at all ─────────────────────────────────────

MARKER = "agents-briefed"


def _marker(root: Path | None = None) -> Path:
    """Beside the store, because that is the thing this machine already has."""
    import passbook

    return (root or Path(passbook.root())) / MARKER


def brief_once(*, root: Path | None = None, store_root: Path | None = None) -> list[dict[str, str]]:
    """Brief the agents if this machine has not been briefed with THIS text.

    `uv tool install` puts the commands on PATH and executes nothing, so there
    is no install step to hang this on — the first command somebody types is the
    first moment PassBook runs at all, and it is the only honest hook left.

    Keyed on a hash of the brief rather than a bare flag, so a machine that was
    briefed with older wording picks up the new one and a machine that is
    current does one small file read and stops. Returns what it did, or `[]`.
    """
    import hashlib

    digest = hashlib.sha256(block().encode("utf-8")).hexdigest()[:16]
    marker = _marker(store_root)
    try:
        if marker.is_file() and marker.read_text(encoding="utf-8").strip() == digest:
            return []
    except OSError:
        pass

    runtimes = detected(root)
    written = install(runtimes, root=root) if runtimes else []
    if runtimes:
        register(runtimes, root=root)
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(digest + "\n", encoding="utf-8")
    except OSError:
        # Not being able to record it means doing it again next time, which is
        # idempotent and cheap. It is not a reason to fail somebody's command.
        pass
    return [entry for entry in written if entry["state"] in ("briefed", "updated")]
