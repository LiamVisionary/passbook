# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""What an agent may and may not get out of the MCP server.

The claim being tested is narrow: an agent learns what exists without spending
an approval, gets exactly the one value it asks for, and cannot reach a key the
owner marked as none of its business — including when no broker is running,
which is the case that shipped broken.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import passbook  # noqa: E402
import passbook_access as access  # noqa: E402
import passbook_mcp as mcp  # noqa: E402


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    for leaked in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "APP_SANDBOX_CONTAINER_ID"):
        monkeypatch.delenv(leaked, raising=False)
    passbook.ensure(app="test")
    passbook.set_values({"OPENAI_API_KEY": "sk-the-real-thing",
                         "OPENAI_BASE_URL": "https://api.example",
                         "ADMIN_TOKEN": "admin-secret"})
    return tmp_path / "hive"


def _session(agent: str = "claude-code"):
    state: dict = {"root": None}
    mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18",
                           "clientInfo": {"name": agent}}}, state)
    return state


def _call(state, tool, arguments=None):
    reply = mcp.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                        "params": {"name": tool, "arguments": arguments or {}}}, state)
    return reply["result"].get("structuredContent", reply["result"])


# ── the handshake ──────────────────────────────────────────────────────────


def test_it_introduces_itself_and_says_how_to_behave(machine):
    state: dict = {"root": None}
    reply = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18",
                                   "clientInfo": {"name": "claude-code"}}}, state)
    result = reply["result"]
    assert result["serverInfo"]["name"] == "passbook"
    assert result["protocolVersion"] == "2025-06-18"
    # The agent must learn the etiquette without being asked.
    assert "list_credentials" in result["instructions"]
    assert "never print a value" in result["instructions"].lower()


def test_an_unknown_protocol_version_gets_ours_rather_than_a_refusal(machine):
    state: dict = {"root": None}
    reply = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "1999-01-01",
                                   "clientInfo": {"name": "x"}}}, state)
    assert reply["result"]["protocolVersion"] == mcp.PROTOCOL_VERSION


def test_a_notification_gets_no_reply(machine):
    assert mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, {}) is None


def test_an_unknown_method_is_an_error_not_a_crash(machine):
    reply = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "nope"}, {"root": None})
    assert reply["error"]["code"] == -32601


# ── listing never leaks ────────────────────────────────────────────────────


def test_listing_returns_names_and_never_values(machine):
    payload = _call(_session(), "list_credentials")
    names = [c["name"] for c in payload["credentials"]]
    assert names == ["ADMIN_TOKEN", "OPENAI_API_KEY", "OPENAI_BASE_URL"]
    assert "sk-the-real-thing" not in json.dumps(payload)
    assert "admin-secret" not in json.dumps(payload)


def test_listing_says_what_this_agent_may_actually_read(machine):
    policy = access.read_policy()
    access.set_audience("ADMIN_TOKEN", "exclude", ["claude-code"], policy)
    access.write_policy(policy)

    payload = _call(_session("claude-code"), "list_credentials")
    by_name = {c["name"]: c for c in payload["credentials"]}
    assert by_name["ADMIN_TOKEN"]["access"] == "refuse"
    assert by_name["OPENAI_API_KEY"]["access"] == "grant"
    assert payload["readable_now"] == 2 and payload["total"] == 3


def test_listing_groups_what_it_returns(machine):
    payload = _call(_session(), "list_credentials")
    assert payload["groups"]["OpenAI"] == ["OPENAI_API_KEY", "OPENAI_BASE_URL"]


def test_listing_can_be_narrowed(machine):
    payload = _call(_session(), "list_credentials", {"search": "openai"})
    assert [c["name"] for c in payload["credentials"]] == ["OPENAI_API_KEY", "OPENAI_BASE_URL"]


# ── reading is bounded ─────────────────────────────────────────────────────


def test_one_named_credential_comes_back(machine):
    payload = _call(_session(), "get_credential", {"name": "OPENAI_API_KEY"})
    assert payload["value"] == "sk-the-real-thing"


def test_an_excluded_key_is_refused_with_no_broker_running(machine):
    """The hole this test exists for: `passbook.request()` falls back to reading
    the file when no broker is running, which would have handed over a key the
    owner had excluded. The audience is enforced at this door too."""
    policy = access.read_policy()
    access.set_audience("ADMIN_TOKEN", "exclude", ["claude-code"], policy)
    access.write_policy(policy)

    payload = _call(_session("claude-code"), "get_credential", {"name": "ADMIN_TOKEN"})
    assert payload["refused"] and payload["value"] is None
    assert "excluded" in payload["why"]


def test_another_agent_still_gets_it(machine):
    policy = access.read_policy()
    access.set_audience("ADMIN_TOKEN", "exclude", ["claude-code"], policy)
    access.write_policy(policy)
    assert _call(_session("ci"), "get_credential", {"name": "ADMIN_TOKEN"})["value"] == "admin-secret"


def test_a_missing_key_says_so_rather_than_pretending(machine):
    payload = _call(_session(), "get_credential", {"name": "NOT_HERE"})
    assert payload["refused"] and "does not hold" in payload["why"]


def test_every_read_leaves_a_receipt_naming_the_agent(machine):
    import passbook_stamp

    policy = access.read_policy()
    access.set_audience("ADMIN_TOKEN", "exclude", ["claude-code"], policy)
    access.write_policy(policy)
    state = _session("claude-code")
    _call(state, "get_credential", {"name": "OPENAI_API_KEY"})
    _call(state, "get_credential", {"name": "ADMIN_TOKEN"})

    rows = passbook_stamp.read_stamps(limit=20)
    assert [r["app"] for r in rows] == ["claude-code", "claude-code"]
    assert {r["granted"] for r in rows} == {True, False}
    assert "sk-the-real-thing" not in repr(rows)


def test_checking_presence_never_returns_a_value(machine):
    payload = _call(_session(), "check_credentials",
                    {"names": ["OPENAI_API_KEY", "NOT_HERE"]})
    assert payload == {"present": ["OPENAI_API_KEY"], "missing": ["NOT_HERE"]}


def test_vault_status_tells_an_agent_to_stop_retrying(machine):
    payload = _call(_session(), "vault_status")
    assert payload["unlocked"] is True
    assert "readable" in payload["advice"].lower()


# ── the resource ───────────────────────────────────────────────────────────


def test_the_catalogue_is_offered_as_a_resource(machine):
    reply = mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}, _session())
    assert [r["uri"] for r in reply["result"]["resources"]] == [mcp.CATALOG_URI]


def test_reading_the_catalogue_carries_no_values(machine):
    reply = mcp.handle({"jsonrpc": "2.0", "id": 4, "method": "resources/read",
                        "params": {"uri": mcp.CATALOG_URI}}, _session())
    text = reply["result"]["contents"][0]["text"]
    assert "OPENAI_API_KEY" in text and "sk-the-real-thing" not in text


# ── the loop ───────────────────────────────────────────────────────────────


def test_serve_speaks_line_delimited_json_over_stdio(machine):
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18",
                               "clientInfo": {"name": "claude-code"}}}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]
    out = io.StringIO()
    mcp.serve(stdin=io.StringIO("\n".join(lines) + "\n"), stdout=out)
    replies = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    # The notification must not produce a reply.
    assert [r["id"] for r in replies] == [1, 2]
    # Against the real list, not a number — a hardcoded count breaks every
    # time a tool is added and says nothing about the loop being tested.
    assert [t["name"] for t in replies[1]["result"]["tools"]] == [t["name"] for t in mcp.TOOLS]


def test_malformed_json_is_answered_not_fatal(machine):
    out = io.StringIO()
    mcp.serve(stdin=io.StringIO("{not json\n"), stdout=out)
    assert json.loads(out.getvalue())["error"]["code"] == -32700


def test_listing_does_not_promise_what_a_locked_vault_cannot_give(machine, monkeypatch):
    """`readable_now` counted policy grants while the vault was shut, so an agent
    was told a key was readable and then refused it."""
    monkeypatch.setattr(mcp, "_store_is_locked", lambda root: True)
    payload = _call(_session(), "list_credentials")
    assert payload["readable_now"] == 0
    assert {c["access"] for c in payload["credentials"]} == {"locked"}
    assert all("sign in" in c["why"] for c in payload["credentials"])
    # The names are still there — that is the point of a locked store.
    assert len(payload["credentials"]) == 3
