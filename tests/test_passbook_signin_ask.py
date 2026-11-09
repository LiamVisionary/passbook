# SPDX-License-Identifier: Apache-2.0
"""An agent asks the person to open the vault, and never holds the password.

`passbook signin --ask WHY` and the MCP server's `request_signin` open
passbook://signin, PassBook's window shows its sign-in card with who asks and
why, and the caller waits for the vault to open. What is tested here is the
caller's half: the link carries only a label, a reason and a workspace, the
limits match the app's parser, and the wait ends the moment the vault opens.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import passbook  # noqa: E402
import passbook_cli as cli  # noqa: E402
import passbook_mcp as mcp  # noqa: E402
import passbook_signin_ask as ask  # noqa: E402

RUST = (ROOT / "app/src-tauri/src/signin.rs").read_text(encoding="utf-8")


def _fields(link: str) -> dict[str, str]:
    parts = urlsplit(link)
    assert f"{parts.scheme}://{parts.netloc}" == "passbook://signin"
    return {key: values[0] for key, values in parse_qs(parts.query, strict_parsing=True).items()}


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


# ── the link ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", ["MAX_BY", "MAX_REASON", "MAX_WORKSPACE"])
def test_the_limits_are_the_apps(name):
    found = re.search(rf"const {name}: usize = (\d+);", RUST)
    assert found, f"{name} is gone from signin.rs"
    assert int(found.group(1)) == getattr(ask, name)


def test_the_link_names_who_why_and_where_and_nothing_else():
    link = ask.signin_link(by="Claude Code", reason="read the copy-trading state", workspace="main")
    assert _fields(link) == {"by": "Claude Code", "reason": "read the copy-trading state", "workspace": "main"}


def test_a_reason_is_one_plain_line_within_the_apps_limit():
    reason = "line one\n\nline two‮evil " + "x" * 400
    fields = _fields(ask.signin_link(by="a", reason=reason))
    assert "\n" not in fields["reason"] and "‮" not in fields["reason"]
    assert fields["reason"].startswith("line one line two evil")
    assert len(fields["reason"]) == ask.MAX_REASON


def test_a_workspace_that_is_not_a_name_is_refused():
    with pytest.raises(ValueError):
        ask.signin_link(by="a", reason="b", workspace="../etc")


def test_the_asker_is_named_from_the_environment():
    assert ask.asker_label({"CLAUDECODE": "1"}) == "Claude Code"
    assert ask.asker_label({}) == "A program on this computer"


# ── asking and waiting ─────────────────────────────────────────────────────


def test_already_open_asks_nothing():
    opened = []
    answer = ask.ask(workspace="main", reason="why", status=lambda _w: {"unlocked": True, "workspace": "main"},
                     opener=lambda link: opened.append(link) or True)
    assert answer == {"ok": True, "already": True}
    assert opened == []


def test_open_for_another_workspace_still_asks():
    opened = []
    clock = Clock()
    answer = ask.ask(workspace="main", reason="why", wait=3,
                     status=lambda _w: {"unlocked": True, "workspace": "other"},
                     opener=lambda link: opened.append(link) or True, sleep=clock.sleep, clock=clock)
    assert len(opened) == 1 and not answer["ok"] and answer["asked"]


def test_it_returns_the_moment_the_person_approves():
    clock = Clock()
    states = iter([{"unlocked": False}, {"unlocked": False}, {"unlocked": False},
                   {"unlocked": True, "workspace": "main"}])
    opened, told = [], []
    answer = ask.ask(workspace="main", reason="read the operator state", by="Claude Code", wait=300,
                     status=lambda _w: next(states), opener=lambda link: opened.append(link) or True,
                     sleep=clock.sleep, clock=clock, on_asked=told.append)
    assert answer == {"ok": True, "already": False}
    assert clock.now == 3
    assert told == opened and _fields(opened[0])["by"] == "Claude Code"


def test_no_approval_ends_with_a_reason_not_a_hang():
    clock = Clock()
    answer = ask.ask(workspace="main", reason="why", wait=5, status=lambda _w: {"unlocked": False},
                     opener=lambda _link: True, sleep=clock.sleep, clock=clock)
    assert not answer["ok"] and answer["asked"] and "5 seconds" in answer["error"]
    assert clock.now == 5


def test_a_missing_broker_is_just_still_locked():
    clock = Clock()

    def status(_w):
        raise ConnectionRefusedError

    answer = ask.ask(workspace="main", reason="why", wait=2, status=status, opener=lambda _link: True,
                     sleep=clock.sleep, clock=clock)
    assert not answer["ok"] and answer["asked"]


def test_no_reason_is_not_asked():
    answer = ask.ask(workspace="main", reason="  \n ", status=lambda _w: {}, opener=lambda _link: True)
    assert not answer["ok"] and not answer["asked"]


def test_a_window_that_cannot_open_says_what_to_do_instead():
    answer = ask.ask(workspace="main", reason="why", status=lambda _w: {}, opener=lambda _link: False)
    assert not answer["ok"] and "passbook signin" in answer["error"]


# ── the command line ───────────────────────────────────────────────────────


def test_the_flags_parse():
    args = cli.build_parser().parse_args(["signin", "--ask", "read the state", "--wait", "60"])
    assert (args.ask, args.wait, args.by) == ("read the state", 60.0, "")
    plain = cli.build_parser().parse_args(["signin"])
    assert plain.ask is None


def test_ask_refuses_to_be_given_a_factor(capsys):
    args = cli.build_parser().parse_args(["signin", "--ask", "why", "--password-stdin"])
    assert cli._signin_by_asking(args, workspace="main", has_profiles=True) == 1
    assert "--ask" in capsys.readouterr().err


def test_ask_waits_on_the_shared_helper(monkeypatch, capsys):
    seen = {}

    def fake(**kwargs):
        seen.update(kwargs)
        kwargs["on_asked"]("passbook://signin?reason=why")
        return {"ok": True, "already": False}

    monkeypatch.setattr(ask, "ask", fake)
    args = cli.build_parser().parse_args(["signin", "--ask", "why", "--by", "Codex"])
    assert cli._signin_by_asking(args, workspace="main", has_profiles=True) == 0
    out = capsys.readouterr()
    assert "approved it in PassBook" in out.out and "Waiting" in out.err
    assert (seen["workspace"], seen["reason"], seen["by"]) == ("main", "why", "Codex")


# ── the MCP tool ───────────────────────────────────────────────────────────


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    for leaked in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "APP_SANDBOX_CONTAINER_ID"):
        monkeypatch.delenv(leaked, raising=False)
    passbook.ensure(app="test")
    return tmp_path / "hive"


def _call(tool, arguments, agent="claude-code"):
    state: dict = {"root": None}
    mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": agent}}}, state)
    reply = mcp.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                        "params": {"name": tool, "arguments": arguments}}, state)
    return reply["result"].get("structuredContent", reply["result"])


def test_the_tool_is_offered_and_asks_for_a_reason():
    tool = next(t for t in mcp.TOOLS if t["name"] == "request_signin")
    assert tool["inputSchema"]["required"] == ["reason"]
    assert "request_signin" in mcp.HANDLERS


def test_an_unencrypted_store_needs_no_asking(machine, monkeypatch):
    monkeypatch.setattr(ask, "ask", lambda **_: pytest.fail("asked for nothing"))
    payload = _call("request_signin", {"reason": "why"})
    assert payload["unlocked"] is True


def test_a_sealed_store_asks_as_the_named_agent(machine, monkeypatch):
    import passbook_vault

    monkeypatch.setattr(passbook_vault, "status", lambda **_: {"sealed": True})
    seen = {}

    def fake(**kwargs):
        seen.update(kwargs)
        return {"ok": False, "asked": True, "error": "Not signed in within 30 seconds."}

    monkeypatch.setattr(ask, "ask", fake)
    payload = _call("request_signin", {"reason": "read the state", "wait_seconds": 30}, agent="codex")
    assert payload == {"unlocked": False, "asked": True, "detail": "Not signed in within 30 seconds."}
    assert (seen["by"], seen["reason"], seen["wait"]) == ("codex", "read the state", 30.0)


def test_vault_status_now_points_at_request_signin(machine, monkeypatch):
    import passbook_vault

    monkeypatch.setattr(passbook_vault, "status", lambda **_: {"sealed": True, "detail": "sealed"})
    payload = _call("vault_status", {})
    assert payload["unlocked"] is False and "request_signin" in payload["advice"]
