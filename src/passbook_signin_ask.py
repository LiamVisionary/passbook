# SPDX-License-Identifier: Apache-2.0
"""Ask the person to open the vault, in PassBook's own window.

An agent that found the vault locked could only stop and tell its owner to go
and type `passbook signin` in a terminal. This lets it ask instead: it opens
`passbook://signin?by=…&reason=…&workspace=…`, PassBook's window comes forward
on its sign-in card with who is asking and why, the person approves there
(Touch ID or the password, typed into PassBook), and the caller waits until the
vault is open.

Nothing secret passes through the caller. The link carries a label, a reason
and a workspace name; the only thing read back is whether the vault is open.
That is the whole design: a password typed into an agent's chat, or handed to
it on stdin, has been written into its transcript.

Who is asking is the caller's own word. Any program can open a link, so the
window says who the request *says* it is from; what protects the vault is the
person choosing Not now. `passbook signin --ask` and the MCP server's
`request_signin` both come through here.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import unicodedata
from typing import Any, Callable, Mapping
from urllib.parse import quote

# The app's parser (app/src-tauri/src/signin.rs) holds the same limits and
# refuses a link that breaks them; tests/test_passbook_signin_ask.py reads them
# from there so the two cannot drift.
MAX_BY = 60
MAX_REASON = 200
MAX_WORKSPACE = 64
DEFAULT_WAIT = 300.0
MAX_WAIT = 3600.0

# What the environment says is running this. Only a label for the window; it is
# never used to decide anything.
_RUNTIMES = (
    ("CLAUDECODE", "Claude Code"),
    ("CODEX_SANDBOX", "Codex"),
    ("CODEX_HOME", "Codex"),
    ("CURSOR_TRACE_ID", "Cursor"),
    ("GEMINI_CLI", "Gemini CLI"),
)


def clean(text: Any, limit: int) -> str:
    """One line a person can read: no control characters, no runs of spaces, capped."""
    kept = "".join(" " if unicodedata.category(c).startswith("C") else c for c in str(text or ""))
    words = " ".join(kept.split())
    return words if len(words) <= limit else words[: limit - 1].rstrip() + "…"


def asker_label(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    for variable, label in _RUNTIMES:
        if env.get(variable):
            return label
    return "A program on this computer"


def workspace_ok(workspace: str) -> bool:
    return 0 < len(workspace) <= MAX_WORKSPACE and all(c.isascii() and (c.isalnum() or c in "._-") for c in workspace)


def signin_link(*, by: str, reason: str, workspace: str = "") -> str:
    """The link, with each part already cleaned and capped the way the app reads it."""
    parts = [("by", clean(by, MAX_BY)), ("reason", clean(reason, MAX_REASON))]
    if workspace:
        if not workspace_ok(workspace):
            raise ValueError(f"Not a workspace name: {workspace!r}")
        parts.append(("workspace", workspace))
    return "passbook://signin?" + "&".join(f"{key}={quote(value, safe='')}" for key, value in parts if value)


def open_link(url: str) -> bool:
    """Hand the link to the OS, which starts PassBook or brings it forward."""
    try:
        if sys.platform == "darwin":
            return subprocess.run(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=15).returncode == 0
        if os.name == "nt":
            os.startfile(url)  # type: ignore[attr-defined]  # noqa: S606 — a passbook:// link, built above
            return True
        return subprocess.run(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def is_open(live: Mapping[str, Any], workspace: str) -> bool:
    """The test `passbook signin` itself uses for "Already signed in"."""
    return bool(live.get("unlocked")) and live.get("workspace") == workspace


def ask(
    *,
    workspace: str,
    reason: str,
    by: str = "",
    wait: float = DEFAULT_WAIT,
    status: Callable[[str], Mapping[str, Any]] | None = None,
    opener: Callable[[str], bool] = open_link,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    on_asked: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Ask, then wait until the vault is open or `wait` seconds pass.

    Answers {"ok": True, "already": bool} or {"ok": False, "error": str, "asked": bool}.
    """
    if status is None:
        import passbook_broker

        def status(name: str) -> Mapping[str, Any]:
            return passbook_broker.vault_status(workspace=name)

    def opened() -> bool:
        try:
            return is_open(status(workspace), workspace)
        except Exception:  # noqa: BLE001 — no broker yet is the normal locked machine
            return False

    if opened():
        return {"ok": True, "already": True}
    if not clean(reason, MAX_REASON):
        return {"ok": False, "asked": False,
                "error": "Say why you need the vault open: the window shows it to the person deciding."}
    link = signin_link(by=by or asker_label(), reason=reason, workspace=workspace)
    if not opener(link):
        return {"ok": False, "asked": False,
                "error": "PassBook's window could not be opened. Is the PassBook app installed? "
                         "Otherwise the owner can run `passbook signin` in a terminal."}
    if on_asked:
        on_asked(link)
    wait = max(1.0, min(float(wait), MAX_WAIT))
    deadline = clock() + wait
    while clock() < deadline:
        sleep(1.0)
        if opened():
            return {"ok": True, "already": False}
    minutes = wait / 60
    span = f"{int(wait)} seconds" if wait < 120 else f"{minutes:g} minutes"
    return {"ok": False, "asked": True,
            "error": f"Not signed in within {span}. The request may still be on screen in PassBook; "
                     "ask again once the owner is there."}
