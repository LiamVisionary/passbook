# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""End to end: an agent asks for a dead token and gets a live one.

This is the claim the whole feature exists for. A real broker subprocess, a real
OAuth provider on a real socket, a genuinely expired token in the store — and an
ordinary `passbook.request()` comes back with something that works.

The broker being a separate process matters here. It is what makes the token
stay alive when whatever created the grant is not running, so testing it in
process would test the wrong thing.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import passbook  # noqa: E402
import passbook_broker  # noqa: E402
import passbook_oauth as oauth  # noqa: E402
import passbook_stamp  # noqa: E402
from fake_provider import FakeProvider  # noqa: E402

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="the broker needs AF_UNIX")


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    for leaked in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "APP_SANDBOX_CONTAINER_ID"):
        monkeypatch.delenv(leaked, raising=False)
    monkeypatch.setenv("PASSBOOK_APPROVAL_TIMEOUT", "2")
    passbook.ensure(app="test")
    return tmp_path / "hive"


class _Machine:
    def __init__(self, provider, grant, keys):
        self.provider, self.grant, self.keys = provider, grant, keys


@pytest.fixture
def connected(machine):
    """A sign-in whose access token expired ten seconds ago."""
    with FakeProvider(expires_in=3600) as provider:
        oauth.add_grant("custom", "work", client_id="client-abc",
                        authorize_url="https://example.test/authorize",
                        token_url=provider.token_url, scope="offline_access")
        grant = oauth.find_grant("custom:work")
        keys = oauth.grant_keys(grant)
        passbook.set_values({
            keys["access_token"]: "expired-token",
            keys["refresh_token"]: "refresh-1",
            keys["expires_at"]: str(int(time.time()) - 10),
        }, overwrite=True)
        started = passbook_broker.start()
        if not started.get("ok"):
            pytest.skip(f"the broker would not start here: {started.get('detail')}")
        try:
            yield _Machine(provider, grant, keys)
        finally:
            passbook_broker.stop()


# ── the headline ───────────────────────────────────────────────────────────


def test_an_agent_asking_for_a_dead_token_gets_a_live_one(connected):
    granted = passbook.request([connected.keys["access_token"]], app="claude-code")

    assert granted[connected.keys["access_token"]] == "access-1", "the token was not renewed"
    assert connected.provider.calls, "the broker never called the provider"
    assert connected.provider.calls[-1]["grant_type"] == "refresh_token"


def test_the_renewal_is_written_back_so_the_next_read_is_free(connected):
    passbook.request([connected.keys["access_token"]], app="claude-code")
    assert connected.provider.issued == 1

    passbook.request([connected.keys["access_token"]], app="claude-code")
    assert connected.provider.issued == 1, "a healthy token was renewed again"

    stored = passbook.parse_env_text(passbook.env_path().read_text(encoding="utf-8"))
    assert stored[connected.keys["access_token"]] == "access-1"
    assert int(stored[connected.keys["expires_at"]]) > time.time() + 3000


def test_a_healthy_token_is_never_sent_to_the_provider(connected):
    passbook.set_values({connected.keys["expires_at"]: str(int(time.time()) + 3600)},
                        overwrite=True)
    granted = passbook.request([connected.keys["access_token"]], app="claude-code")

    assert granted[connected.keys["access_token"]] == "expired-token"
    assert connected.provider.calls == [], "an unexpired token was refreshed anyway"


def test_asking_for_an_unrelated_key_refreshes_nothing(connected):
    passbook.set_values({"SOMETHING_ELSE": "value"}, overwrite=True)
    passbook.request(["SOMETHING_ELSE"], app="claude-code")
    assert connected.provider.calls == []


def test_the_renewal_is_recorded(connected):
    passbook.request([connected.keys["access_token"]], app="claude-code")
    rows = passbook_stamp.read_stamps(limit=20)
    refreshes = [r for r in rows if r.get("op") == "refresh"]

    assert refreshes, "a renewal left no trace"
    assert refreshes[-1]["granted"] and "custom:work" in refreshes[-1]["reason"]
    assert "access-1" not in repr(rows) and "refresh-1" not in repr(rows)


# ── the ways it can go wrong ───────────────────────────────────────────────


def test_a_dead_grant_does_not_fail_the_read(machine):
    """A revoked sign-in must not take down a request that also wants other
    keys. The caller gets what is stored and the ledger says what happened."""
    with FakeProvider(fail_with=400) as provider:
        oauth.add_grant("custom", "work", client_id="c",
                        authorize_url="https://example.test/a", token_url=provider.token_url)
        grant = oauth.find_grant("custom:work")
        keys = oauth.grant_keys(grant)
        passbook.set_values({
            keys["access_token"]: "stale", keys["refresh_token"]: "refresh-1",
            keys["expires_at"]: str(int(time.time()) - 10), "OTHER_KEY": "fine",
        }, overwrite=True)
        started = passbook_broker.start()
        if not started.get("ok"):
            pytest.skip("no broker here")
        try:
            granted = passbook.request([keys["access_token"], "OTHER_KEY"], app="claude-code")
            assert granted["OTHER_KEY"] == "fine", "one dead grant broke the whole read"
            assert granted[keys["access_token"]] == "stale"

            failed = [r for r in passbook_stamp.read_stamps(limit=20)
                      if r.get("op") == "refresh" and not r.get("granted")]
            assert failed and "custom:work" in failed[-1]["reason"]
        finally:
            passbook_broker.stop()


def test_two_agents_at_once_do_not_burn_a_rotating_refresh_token(machine):
    """Both would spend refresh-1; a rotating provider invalidates the loser and
    the grant that worked a moment ago is disconnected. One renewal per grant."""
    with FakeProvider(rotate=True, expires_in=3600) as provider:
        provider.delay = 0.4
        oauth.add_grant("custom", "work", client_id="c",
                        authorize_url="https://example.test/a", token_url=provider.token_url)
        grant = oauth.find_grant("custom:work")
        keys = oauth.grant_keys(grant)
        passbook.set_values({
            keys["access_token"]: "stale", keys["refresh_token"]: "refresh-1",
            keys["expires_at"]: str(int(time.time()) - 10),
        }, overwrite=True)
        started = passbook_broker.start()
        if not started.get("ok"):
            pytest.skip("no broker here")
        try:
            results = []
            def ask(name):
                results.append(passbook.request([keys["access_token"]], app=name))
            threads = [threading.Thread(target=ask, args=(f"agent-{i}",)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            assert provider.issued == 1, f"the refresh token was spent {provider.issued} times"
            errors = [c for c in provider.calls if c.get("refresh_token") != "refresh-1"]
            assert not errors, "a stale refresh token was replayed"
            stored = passbook.parse_env_text(passbook.env_path().read_text(encoding="utf-8"))
            assert stored[keys["refresh_token"]] == "refresh-2", "the rotated token was not kept"
        finally:
            passbook_broker.stop()


def test_a_key_the_agent_may_not_have_is_not_refreshed_for_it(connected):
    """An audience is a bound. It must hold before anything is spent on the
    caller's behalf, not just before the value is handed over."""
    import passbook_access as access

    policy = access.read_policy()
    access.set_audience(connected.keys["access_token"], "exclude", ["claude-code"], policy)
    access.write_policy(policy)

    granted = passbook.request([connected.keys["access_token"]], app="claude-code")
    assert granted == {}
    assert connected.provider.calls == [], "a refused key was still renewed"


# ── through MCP, which is how an agent actually arrives ────────────────────


def test_the_mcp_tool_hands_back_a_live_token(connected):
    import passbook_mcp as mcp

    state: dict = {"root": None}
    mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18",
                           "clientInfo": {"name": "claude-code"}}}, state)
    reply = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "get_oauth_token",
                                   "arguments": {"id": "custom:work", "reason": "calling the API"}}},
                       state)
    payload = reply["result"]["structuredContent"]

    assert payload["token"] == "access-1"
    assert payload["state"] == "connected" and payload["expires_in"] > 3000


def test_the_mcp_listing_names_states_and_no_tokens(connected):
    import json

    import passbook_mcp as mcp

    state: dict = {"root": None}
    mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"clientInfo": {"name": "claude-code"}}}, state)
    reply = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "list_sign_ins", "arguments": {}}}, state)
    payload = reply["result"]["structuredContent"]

    assert [s["id"] for s in payload["sign_ins"]] == ["custom:work"]
    assert "expired-token" not in json.dumps(payload)
    assert "refresh-1" not in json.dumps(payload)


def test_an_excluded_agent_is_refused_the_token_through_mcp(connected):
    import passbook_access as access
    import passbook_mcp as mcp

    policy = access.read_policy()
    access.set_audience(connected.keys["access_token"], "exclude", ["claude-code"], policy)
    access.write_policy(policy)

    state: dict = {"root": None}
    mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"clientInfo": {"name": "claude-code"}}}, state)
    reply = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "get_oauth_token", "arguments": {"id": "custom:work"}}},
                       state)
    payload = reply["result"]["structuredContent"]

    assert payload["refused"] and payload["token"] is None
    assert "excluded" in payload["why"]


def test_an_unknown_sign_in_is_refused_clearly(connected):
    import passbook_mcp as mcp

    state: dict = {"root": None}
    mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"clientInfo": {"name": "claude-code"}}}, state)
    reply = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "get_oauth_token", "arguments": {"id": "nope:nope"}}},
                       state)
    payload = reply["result"]["structuredContent"]
    assert payload["refused"] and "No such sign-in" in payload["why"]


def test_a_successful_token_fetch_records_no_denial(connected):
    """It asked for all four key names, `account` is optional and absent, and
    `request` reports a batch denied when anything in it is missing — so every
    successful fetch left an audit row that read like a refusal."""
    import passbook_mcp as mcp

    state: dict = {"root": None}
    mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"clientInfo": {"name": "claude-code"}}}, state)
    reply = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "get_oauth_token", "arguments": {"id": "custom:work"}}},
                       state)
    assert reply["result"]["structuredContent"]["token"] == "access-1"

    denials = [r for r in passbook_stamp.read_stamps(limit=50)
               if r.get("op") == "read" and not r.get("granted")]
    assert denials == [], f"a working fetch logged a refusal: {denials}"


def test_the_token_fetch_asks_for_one_batch_only(connected):
    """Two requests per fetch doubled the ledger rows for one event."""
    import passbook_mcp as mcp

    before = len([r for r in passbook_stamp.read_stamps(limit=200) if r.get("op") == "read"])
    state: dict = {"root": None}
    mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"clientInfo": {"name": "claude-code"}}}, state)
    mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "get_oauth_token", "arguments": {"id": "custom:work"}}}, state)

    after = len([r for r in passbook_stamp.read_stamps(limit=200) if r.get("op") == "read"])
    assert after - before == 1, "one token fetch should be one read row"
