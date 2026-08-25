# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Broker tests — what it is for, and what it is honestly not.

The broker's claim is narrow and these tests hold it to exactly that: reads
become recorded and narrow. Unauthorised reads do not become impossible, and
the last tests here assert that limit rather than paper over it.
"""

from __future__ import annotations

import json
import stat
import socket
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import passbook  # noqa: E402
import passbook_broker  # noqa: E402

# The broker speaks over a Unix socket, which Windows does not have. Skipping
# the file beats an import-time AttributeError that reads like a real failure.
pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="the broker needs AF_UNIX")
import passbook_stamp  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1]


@pytest.fixture
def broker(tmp_path, monkeypatch):
    """A machine with a store and a broker running over it."""
    home = tmp_path / "hive"
    monkeypatch.setenv("HIVE_HOME", str(home))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    monkeypatch.delenv("HIVE_WORKSPACE", raising=False)
    # The broker inherits its environment when it starts, so a per-test override
    # after that point would be read by nobody. Two seconds keeps the unanswered
    # cases from parking the suite for a minute each.
    monkeypatch.setenv("PASSBOOK_APPROVAL_TIMEOUT", "2")
    passbook.ensure(app="test")
    passbook.set_values({"ALPHA": "a-value", "BETA": "b-value", "GAMMA": "c-value"})

    started = passbook_broker.start()
    if not started.get("ok"):
        pytest.skip(f"the broker would not start here: {started.get('detail')}")
    try:
        yield home
    finally:
        passbook_broker.stop()


def _policy(home: Path, default: str, apps: dict) -> None:
    """Write a policy in the current shape: a mode per key, per app."""
    passbook_broker.write_policy({"default": {"mode": default}, "apps": apps})


def _keys(**modes) -> dict:
    return {"keys": {key: {"mode": mode} for key, mode in modes.items()}}


# ── the record stops being voluntary ───────────────────────────────────────


def test_a_read_is_recorded_even_though_the_app_never_set_up_stamping(broker):
    """The hole the broker exists to close.

    Without one, an app has to opt into stamping its own reads — so the ledger
    is missing exactly the apps least likely to bother.
    """
    passbook.set_recorder(None)

    passbook.request(["ALPHA"], app="a-careless-app", reason="a job")

    rows = [row for row in passbook_stamp.read_stamps(limit=50) if row.get("app") == "a-careless-app"]
    assert rows, "the broker records what the client did not"
    assert rows[-1]["keys"] == ["ALPHA"]
    assert rows[-1]["op"] == "read"


def test_the_record_never_holds_a_value(broker):
    passbook.request(["ALPHA", "BETA"], app="an-app", reason="a job")

    written = passbook_stamp.proof_path().read_text(encoding="utf-8")
    assert "a-value" not in written
    assert "b-value" not in written
    assert "ALPHA" in written


def test_the_chain_still_verifies_with_the_broker_writing_to_it(broker):
    for index in range(5):
        passbook.request(["ALPHA"], app=f"app-{index}")

    assert passbook_broker.running()
    assert passbook_stamp.verify_chain()["ok"]


# ── least privilege for honest code ────────────────────────────────────────


def test_the_permissive_default_grants_everything_and_records_it(broker):
    _policy(broker, "always", {})

    granted = passbook.request(["ALPHA", "BETA", "GAMMA"], app="anything")

    assert sorted(granted) == ["ALPHA", "BETA", "GAMMA"]
    assert passbook_broker.read_policy()["default"]["mode"] == "always"


def test_deny_mode_hands_over_only_what_the_policy_names(broker):
    _policy(broker, "never", {"narrow-app": _keys(ALPHA="always")})

    granted = passbook.request(["ALPHA", "BETA", "GAMMA"], app="narrow-app")

    assert sorted(granted) == ["ALPHA"]
    assert "BETA" not in granted, "a refused key must never enter the process"
    assert "b-value" not in json.dumps(granted)


def test_a_refusal_is_recorded_as_its_own_kind_of_row(broker):
    _policy(broker, "never", {"narrow-app": _keys(ALPHA="always")})

    passbook.request(["ALPHA", "BETA"], app="narrow-app", reason="a job")

    refusals = [row for row in passbook_stamp.read_stamps(limit=50) if row.get("op") == "denied"]
    assert refusals, "a refusal has to be visible or the policy teaches you nothing"
    assert refusals[-1]["keys"] == ["BETA"]
    assert refusals[-1]["granted"] is False


def test_an_app_with_no_entry_gets_nothing_under_deny(broker):
    _policy(broker, "never", {"known-app": _keys(ALPHA="always")})

    assert passbook.request(["ALPHA"], app="a-stranger") == {}


def test_a_wildcard_entry_covers_apps_without_their_own(broker):
    _policy(broker, "never", {"*": _keys(ALPHA="always")})

    assert sorted(passbook.request(["ALPHA", "BETA"], app="anyone")) == ["ALPHA"]


def test_a_policy_can_be_derived_from_what_apps_actually_asked_for(broker):
    """Writing one from imagination is how a machine stays in audit mode forever."""
    _policy(broker, "always", {})
    passbook.request(["ALPHA"], app="modest-app")
    passbook.request(["ALPHA", "BETA"], app="greedy-app")

    learned = passbook_broker.learn_policy(mode="always")

    assert learned["default"]["mode"] == "never"
    assert sorted(learned["apps"]["modest-app"]["keys"]) == ["ALPHA"]
    assert sorted(learned["apps"]["greedy-app"]["keys"]) == ["ALPHA", "BETA"]


# ── it must never be able to break the machine ─────────────────────────────


def test_a_corrupt_policy_grants_rather_than_denies(broker):
    """A parse error that silently denied everything would take the machine down
    and look like a credential problem the whole time."""
    passbook_broker.policy_path().write_text("{ not json at all", encoding="utf-8")

    assert sorted(passbook.request(["ALPHA", "BETA"], app="anything")) == ["ALPHA", "BETA"]


def test_stopping_the_broker_leaves_every_app_working(broker):
    """Fail-open is deliberate, and it is also the limit — see the tests below."""
    _policy(broker, "never", {"narrow-app": _keys(ALPHA="always")})
    assert sorted(passbook.request(["ALPHA", "BETA"], app="narrow-app")) == ["ALPHA"]

    passbook_broker.stop()

    assert sorted(passbook.request(["ALPHA", "BETA"], app="narrow-app")) == ["ALPHA", "BETA"]


def test_an_explicit_store_list_never_reaches_the_broker(broker, tmp_path):
    """`stores=` is how a test or a sandbox isolates itself. Routing that to a
    live broker would be exactly the leak the parameter exists to prevent."""
    elsewhere = tmp_path / "other.env"
    elsewhere.write_text("ONLY_HERE=value\n", encoding="utf-8")

    granted = passbook.request(["ONLY_HERE", "ALPHA"], app="an-app", stores=[elsewhere])

    assert sorted(granted) == ["ONLY_HERE"]
    assert "ALPHA" not in granted, "the machine store must not leak in through the broker"


def test_hive_env_files_also_bypasses_the_broker(broker, monkeypatch):
    """Belt and braces beside `stores=`.

    `HIVE_ENV_FILES` is how the hosting app says "this process was pointed
    somewhere else on purpose". The standard's own file resolution does not read
    it — that is the adapter's job — but reaching a live broker from such a
    process would still be wrong, so the bypass is checked here by its absence
    from the record rather than by what came back.
    """
    passbook.set_recorder(None)
    monkeypatch.setenv("HIVE_ENV_FILES", "/nonexistent/passbook.env")

    passbook.request(["ALPHA"], app="a-redirected-process")

    assert not [row for row in passbook_stamp.read_stamps(limit=50)
                if row.get("app") == "a-redirected-process"], "the broker was consulted anyway"


# ── the limits, asserted rather than described ─────────────────────────────


def test_anything_running_as_you_can_claim_to_be_any_app(broker):
    """The headline limit. There is nothing in a request that proves who sent it,
    so a policy is a blast-radius limiter, not a boundary against an attacker."""
    _policy(broker, "never", {"trusted-app": _keys(ALPHA="always", BETA="always")})

    impostor = passbook_broker.request_through_broker(["ALPHA", "BETA"], app="trusted-app")

    assert sorted(impostor) == ["ALPHA", "BETA"], "documented, not defended against"


def test_the_store_is_still_readable_without_the_broker(broker):
    """The other half of the same limit: the file is still there."""
    direct = passbook.parse_env_text(passbook.env_path().read_text(encoding="utf-8"))
    assert direct["ALPHA"] == "a-value"


def test_status_reports_the_limit_so_it_reaches_a_ui_too(broker):
    state = passbook_broker.status()

    assert state["running"] is True
    assert "claim to be any app" in state["limits"]
    assert "a-value" not in json.dumps(state), "status is names only, like everything else"


# ── the files it opens ─────────────────────────────────────────────────────


def test_the_socket_is_reachable_only_by_this_user(broker):
    assert stat.S_IMODE(passbook_broker.socket_path().stat().st_mode) == 0o600


def test_the_policy_is_written_unreadable_to_anyone_else(broker):
    passbook_broker.write_policy({"mode": "audit", "apps": {}})
    assert stat.S_IMODE(passbook_broker.policy_path().stat().st_mode) == 0o600


def test_a_deep_home_still_binds(tmp_path, monkeypatch):
    """AF_UNIX paths cap around 104 bytes, and it is the path that has to fit —
    a deep HIVE_HOME failed at bind with nothing pointing at the socket."""
    deep = tmp_path.joinpath(*[f"a-fairly-long-directory-name-{index}" for index in range(4)])
    deep.mkdir(parents=True)
    monkeypatch.setenv("HIVE_HOME", str(deep))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    assert len(str(passbook_broker.socket_path()).encode()) > 96, "not actually testing the long path"

    passbook.ensure(app="test")
    passbook.set_values({"ALPHA": "a-value"})
    started = passbook_broker.start()
    try:
        assert started.get("ok"), started.get("detail")
        assert sorted(passbook.request(["ALPHA"], app="an-app")) == ["ALPHA"]
    finally:
        passbook_broker.stop()


def test_a_stale_socket_does_not_block_a_restart(broker):
    passbook_broker.stop()
    passbook_broker.socket_path().write_text("", encoding="utf-8")  # a corpse

    started = passbook_broker.start()

    assert started.get("ok"), started.get("detail")
    assert passbook_broker.running()


# ── holding a request open while a person answers ──────────────────────────
#
# The queue lives in the broker's memory, and the broker is another process — so
# these go over the socket. Calling `passbook_broker.pending()` here would read
# this process's own empty queue and quietly assert nothing.

import threading  # noqa: E402

import passbook_access as access  # noqa: E402


def _in_background(call):
    """Run a blocking request off-thread so the test can answer it."""
    box: dict = {}
    thread = threading.Thread(target=lambda: box.update(result=call()), daemon=True)
    thread.start()
    return box, thread


def _wait_for_pending(timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        answer = passbook_broker._ask({"op": "pending"}) or {}
        if answer.get("pending"):
            return answer["pending"][0]
        time.sleep(0.02)
    raise AssertionError("nothing ever queued for approval")


def _answer(request_id: str, *, approve: bool, remember: str = ""):
    return passbook_broker._ask({"op": "resolve", "id": request_id,
                                 "approve": approve, "remember": remember})


def _ask_policy(mode: str = "ask", **rule):
    access.write_policy({"default": {"mode": "always"},
                         "apps": {"agent": {"keys": {"ALPHA": {"mode": mode, **rule}}}}})


def test_an_ask_request_waits_and_an_approval_releases_it(broker):
    _ask_policy()

    box, thread = _in_background(
        lambda: passbook.request(["ALPHA"], app="agent", reason="a job"))
    waiting = _wait_for_pending()
    assert waiting["app"] == "agent" and waiting["keys"] == ["ALPHA"]
    assert "a-value" not in json.dumps(waiting), "a pending request names keys, never values"

    _answer(waiting["id"], approve=True)
    thread.join(timeout=10)

    assert sorted(box["result"]) == ["ALPHA"]


def test_declining_a_request_hands_over_nothing(broker):
    _ask_policy()

    box, thread = _in_background(lambda: passbook.request(["ALPHA"], app="agent"))
    _answer(_wait_for_pending()["id"], approve=False)
    thread.join(timeout=10)

    assert box["result"] == {}


def test_an_unanswered_request_gives_up_rather_than_hanging(broker):
    """A read that hangs forever the moment you step away from the keyboard is a
    policy nobody keeps switched on."""
    _ask_policy()

    started = time.monotonic()
    box, thread = _in_background(lambda: passbook.request(["ALPHA"], app="agent"))
    thread.join(timeout=60)
    elapsed = time.monotonic() - started

    assert box.get("result") == {}
    assert elapsed < 30, "it waited past its own patience"


def test_approving_can_hold_the_door_open_afterwards(broker):
    _ask_policy()

    box, thread = _in_background(lambda: passbook.request(["ALPHA"], app="agent"))
    _answer(_wait_for_pending()["id"], approve=True, remember="1h")
    thread.join(timeout=10)

    # The second read must not ask again — that is the whole point of remembering.
    assert sorted(passbook.request(["ALPHA"], app="agent")) == ["ALPHA"]
    assert access.sessions(), "approving with a duration opens an unlock"


def test_an_unlock_is_recorded_as_an_unlock(broker):
    """The record has to make an unlock legible later, not look like ordinary use."""
    passbook_broker._ask({"op": "unlock", "duration": "15m", "reason": "batch"})

    rows = [row for row in passbook_stamp.read_stamps(limit=50) if row.get("op") == "unlock"]
    assert rows, "an op missing from passbook_stamp.OPERATIONS is silently dropped"
    assert "15m" in rows[-1].get("reason", "")


def test_asking_is_recorded_even_when_nobody_answers(broker):
    _ask_policy()

    box, thread = _in_background(lambda: passbook.request(["ALPHA"], app="agent"))
    thread.join(timeout=60)

    ops = [row.get("op") for row in passbook_stamp.read_stamps(limit=50)]
    assert "ask" in ops and "denied" in ops


def test_a_window_refusal_says_which_window(broker):
    _ask_policy("window", window={"from": "00:00", "to": "00:01"})

    answer = passbook_broker._ask({"op": "request", "app": "agent", "keys": ["ALPHA"]})

    assert answer["granted"] == {}
    assert "outside" in answer["why"]["ALPHA"]


def test_a_wrongly_shaped_policy_is_survivable(broker):
    """A policy can be malformed in shape, not only in syntax.

    A hand-edited or older-format `keys` list made the request handler raise,
    and the handler used to end without replying — so the client sat out its
    entire two-minute timeout on a bug it could not see. Failing to answer is
    strictly worse than answering badly: the client already knows how to carry
    on when no broker replies.
    """
    passbook_broker.policy_path().write_text(
        json.dumps({"version": 2, "default": {"mode": "never"},
                    "apps": {"agent": {"keys": ["ALPHA"]}}}),  # a list, not a mapping
        encoding="utf-8")

    started = time.monotonic()
    answer = passbook_broker._ask({"op": "request", "app": "agent", "keys": ["ALPHA"]})
    elapsed = time.monotonic() - started

    assert elapsed < 10, "the broker left the client waiting"
    assert answer is not None and answer.get("ok"), "a bad shape must not become no answer"


def test_a_handler_failure_is_reported_rather_than_dropped(monkeypatch):
    """Whatever goes wrong in there, the client gets a reply it can act on.

    Exercised against `_serve_one` directly over a socket pair: the point is the
    guard around the handler, not any particular way of provoking it, and a test
    that leans on one provocation stops testing the guard the moment that
    provocation is fixed somewhere else.
    """
    import socket as socket_module

    def explode(*_args, **_kwargs):
        raise RuntimeError("something the handler did not expect")

    monkeypatch.setattr(passbook_broker, "_handle", explode)
    server, client = socket_module.socketpair()
    try:
        client.sendall(b'{"op":"request","app":"a","keys":["K"]}\n')
        passbook_broker._serve_one(server, None)
        client.settimeout(5)
        reply = client.recv(4096).decode("utf-8").strip()
    finally:
        client.close()

    assert reply, "the connection was dropped instead of answered"
    answer = json.loads(reply)
    assert answer["ok"] is False
    assert "RuntimeError" in answer["error"], "the reply should name what went wrong"
