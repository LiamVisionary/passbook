# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""The promise, end to end, on a machine shaped like a real one.

An encrypted store, sealed reads, a broker running over it. The claim being
held up is one sentence: **a credential is used freely and never seen.** These
tests are the four ways that sentence can be false.

The one that matters most is the second. Sealing used to carry an exemption for
apps on an approved list, so that a machine could be sealed today rather than
after every app had been rewritten. It was documented as a migration path and
not a boundary, and it was still wrong: an app NAME is a claim. An agent refused
a key under its own name received the same key by asking again as an approved
app — six lines, no privilege, no warning. A list anything can join is not a
list.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import passbook  # noqa: E402
import passbook_access as access  # noqa: E402
import passbook_broker  # noqa: E402
import passbook_vault as vault  # noqa: E402
from _platform import broker_marker, needs_a_posix_shell  # noqa: E402

pytestmark = broker_marker()

PASSWORD = "a properly long vault password"
SECRET = "sk-live-not-for-your-transcript"


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """Encrypted store, sealed reads, broker up — a real machine's shape."""
    home = tmp_path / "hive"
    monkeypatch.setenv("HIVE_HOME", str(home))
    for leaked in ("HIVE_ENV_FILES", "APP_SANDBOX_CONTAINER_ID", "HIVE_WORKSPACE"):
        monkeypatch.delenv(leaked, raising=False)
    monkeypatch.setenv("PASSBOOK_APPROVAL_TIMEOUT", "2")
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)

    passbook.ensure(app="test")
    passbook.set_values({"OPENAI_API_KEY": SECRET, "PUBLIC_URL": "https://example.com"})
    profile = vault.create_profile("Owner", password=PASSWORD, root=home)["id"]
    dek = vault.unlock_with_password(profile, PASSWORD, root=home)
    vault.seal_store(dek, profile_id=profile, root=home)

    started = passbook_broker.start()
    if not started.get("ok"):
        pytest.skip(f"the broker would not start here: {started.get('detail')}")
    passbook_broker.signin(profile=profile, password=PASSWORD, duration="always")

    policy = passbook_broker.read_policy()
    policy["reads"] = "sealed"
    access.approve_agent("an-approved-app", policy)   # the list still exists…
    passbook_broker.write_policy(policy)
    try:
        yield home
    finally:
        passbook_broker.stop()


def test_the_store_really_is_encrypted_at_rest(machine):
    """Otherwise the rest of this file proves nothing about a real machine."""
    text = passbook.env_path().read_text(encoding="utf-8")
    assert SECRET not in text
    assert any(vault.is_sealed(line.split("=", 1)[1].strip().strip('"'))
               for line in text.splitlines() if "=" in line and not line.startswith("#"))


def test_an_agent_cannot_read_a_value(machine):
    answer = passbook.request(["OPENAI_API_KEY"], app="claude-code", reason="e2e")
    assert answer.get("OPENAI_API_KEY") is None


def test_an_agent_cannot_read_it_by_claiming_an_approved_name(machine):
    """…and being on the list buys nothing, which is the whole point.

    This is the exact six lines that worked against the live machine before the
    exemption was removed: same process, same key, different string.
    """
    assert "an-approved-app" in access.approved_agents(passbook_broker.read_policy())
    for name in ("an-approved-app", "passbook-sync", "hivemindos", "passbook-cli"):
        answer = passbook.request(["OPENAI_API_KEY"], app=name, reason="e2e")
        assert answer.get("OPENAI_API_KEY") is None, f"{name} was handed plaintext"


@needs_a_posix_shell
def test_an_agent_can_still_use_the_key_without_seeing_it(machine):
    """The other half. A guarantee that also stops the work is not adopted."""
    answer = passbook_broker._ask({
        "op": "spawn", "app": "claude-code", "keys": ["OPENAI_API_KEY"],
        "command": ["sh", "-c", 'test "$OPENAI_API_KEY" = "%s" && echo AUTHENTICATED; '
                                'echo "$OPENAI_API_KEY"' % SECRET],
    }, timeout=30)
    assert answer["ok"], answer
    assert "AUTHENTICATED" in answer["stdout"], "the child did not receive the real value"
    assert SECRET not in answer["stdout"], "the value came back to the caller"
    assert "[redacted:OPENAI_API_KEY]" in answer["stdout"]


@needs_a_posix_shell
def test_replication_can_still_open_encrypted_values_under_a_grant(machine):
    """The one job that genuinely needs plaintext: copying a key to another
    machine means reading it. 287 of the 305 values on the machine this was
    written for are encrypted at rest, so replication cannot work without
    asking the broker to open them.

    It used to be allowed by putting `passbook-sync` on the approved list, which
    made the exemption a decryption oracle any caller could invoke by typing the
    name. A grant cannot be typed, so sync asks to be STARTED instead of trusted.
    """
    answer = passbook_broker._ask({
        "op": "spawn", "app": "passbook-sync", "keys": ["OPENAI_API_KEY", "PUBLIC_URL"],
        "command": ["sh", "-c", 'test "$OPENAI_API_KEY" = "%s" && echo OPENED' % SECRET],
    }, timeout=30)
    assert answer["ok"] and "OPENED" in answer["stdout"], (
        "replication cannot open encrypted values under a grant")


@needs_a_posix_shell
def test_a_grant_is_not_a_key_to_the_whole_store(machine):
    """With the exemption gone, a grant is the ONLY road to plaintext — which
    makes this the property everything else now rests on. If a token reached
    past the key set it was minted for, it would just be the exemption again,
    with a random string instead of a name."""
    started = passbook_broker._ask({
        "op": "spawn", "app": "narrow", "keys": ["PUBLIC_URL"],
        "command": ["sh", "-c", "sleep 5"], "detach": True}, timeout=30)
    assert started["ok"] and started.get("grant"), started
    token = started["grant"]

    within = passbook_broker._ask({"op": "request", "app": "narrow", "grant": token,
                                   "keys": ["PUBLIC_URL"]})
    assert within["granted"].get("PUBLIC_URL"), "a grant did not cover its own key"

    beyond = passbook_broker._ask({"op": "request", "app": "narrow", "grant": token,
                                   "keys": ["OPENAI_API_KEY"]})
    assert beyond["granted"] == {}, "a grant reached beyond the keys it was started with"
    assert "OPENAI_API_KEY" in beyond["denied"]
