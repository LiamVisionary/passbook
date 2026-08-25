# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Access modes: always, ask, window, never — and the unlock that suspends asking.

The decision logic is deliberately free of the daemon, so these tests are about
what the rules mean rather than about sockets. The broker's half — holding a
request open while a person answers — is in test_passbook_broker.py.
"""

from __future__ import annotations

import json
import stat
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import passbook  # noqa: E402
import passbook_access as access  # noqa: E402


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    passbook.ensure(app="test")
    return tmp_path / "hive"


def _rules(**apps) -> dict:
    return {"version": access.POLICY_VERSION, "default": {"mode": "always"}, "apps": apps}


# ── durations ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text,seconds", [
    ("30m", 1800), ("1h", 3600), ("4h", 14400), ("1d", 86400), ("90", 90), (" 2h ", 7200),
])
def test_durations_people_actually_type(text, seconds):
    assert access.parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "soon", "-1h", "0", "9d", "1w", "abc"])
def test_a_duration_that_is_not_one_is_refused(text):
    """Silently defaulting a typo to some duration is how a door stays open."""
    with pytest.raises(ValueError):
        access.parse_duration(text)


def test_a_countdown_reads_as_words():
    assert access.describe_duration(45) == "45s"
    assert access.describe_duration(1800) == "30m"
    assert access.describe_duration(5400) == "1h 30m"
    assert access.describe_duration(7200) == "2h"


# ── which rule applies ─────────────────────────────────────────────────────


def test_a_machine_that_configured_nothing_still_grants(machine):
    """The modes are opt-in. Arriving at `never` by default would break a machine
    the moment this shipped."""
    assert access.decide_key("any-app", "ANY_KEY", access.read_policy())["outcome"] == "grant"


def test_the_most_specific_rule_wins(machine):
    policy = _rules(agent={
        "default": {"mode": "ask"},
        "keys": {"OPEN_KEY": {"mode": "always"}, "*": {"mode": "never"}},
    })

    assert access.mode_for("agent", "OPEN_KEY", policy)["mode"] == "always"
    assert access.mode_for("agent", "OTHER_KEY", policy)["mode"] == "never", "the app wildcard beats its default"
    assert access.mode_for("stranger", "OPEN_KEY", policy)["mode"] == "always", "no entry falls to the machine default"


def test_an_app_wildcard_covers_apps_without_their_own_entry(machine):
    policy = _rules(**{"*": {"default": {"mode": "never"}}})
    assert access.mode_for("nobody", "ANY", policy)["mode"] == "never"


def test_never_means_never_even_while_unlocked(machine):
    """An unlock suspends *asking*. It is not a master key, or the mode would be
    a suggestion."""
    policy = _rules(agent={"keys": {"SECRET": {"mode": "never"}}})
    access.open_session(duration="1h")

    assert access.decide_key("agent", "SECRET", policy)["outcome"] == "refuse"


# ── windows ────────────────────────────────────────────────────────────────


def _at(hour: int, day: int = 25) -> datetime:
    """A local-time moment, because a person setting office hours means their clock."""
    return datetime(2026, 8, day, hour, 0).astimezone()


def test_a_window_opens_and_shuts_on_the_local_clock():
    rule = {"mode": "window", "window": {"from": "09:00", "to": "18:00"}}
    assert access.within_window(rule, _at(12))
    assert not access.within_window(rule, _at(3))
    assert not access.within_window(rule, _at(22))


def test_a_window_can_wrap_midnight():
    rule = {"mode": "window", "window": {"from": "22:00", "to": "06:00"}}
    assert access.within_window(rule, _at(23))
    assert access.within_window(rule, _at(2))
    assert not access.within_window(rule, _at(12))


def test_a_window_can_name_days():
    rule = {"mode": "window", "window": {"from": "09:00", "to": "18:00",
                                         "days": ["mon", "tue", "wed", "thu", "fri"]}}
    assert access.within_window(rule, _at(12, day=25)), "2026-08-25 is a Tuesday"
    assert not access.within_window(rule, _at(12, day=23)), "2026-08-23 is a Sunday"


def test_an_unreadable_window_is_open_rather_than_shut():
    """The failure mode of a malformed schedule has to be a working machine."""
    assert access.within_window({"mode": "window", "window": {"from": "nonsense", "to": "??"}})
    assert access.within_window({"mode": "window"})


def test_a_window_decision_says_which_window(machine):
    policy = _rules(agent={"keys": {"K": {"mode": "window",
                                          "window": {"from": "00:00", "to": "23:59"}}}})
    verdict = access.decide_key("agent", "K", policy)
    assert verdict["outcome"] == "grant"
    assert "00:00" in verdict["why"], "a refusal with no cause is what makes people switch policies off"


# ── unlocks ────────────────────────────────────────────────────────────────


def test_an_unlock_suspends_asking_for_its_duration(machine):
    policy = _rules(agent={"keys": {"K": {"mode": "ask"}}})
    assert access.decide_key("agent", "K", policy)["outcome"] == "ask"

    access.open_session(duration="1h", reason="batch run")

    verdict = access.decide_key("agent", "K", policy)
    assert verdict["outcome"] == "grant"
    assert "unlocked for" in verdict["why"]


def test_an_unlock_can_be_narrowed_to_keys(machine):
    policy = _rules(agent={"default": {"mode": "ask"}})
    access.open_session(duration="1h", keys=["ONLY_THIS"])

    assert access.decide_key("agent", "ONLY_THIS", policy)["outcome"] == "grant"
    assert access.decide_key("agent", "SOMETHING_ELSE", policy)["outcome"] == "ask"


def test_an_unlock_can_be_narrowed_to_one_app(machine):
    policy = _rules(**{"*": {"default": {"mode": "ask"}}})
    access.open_session(duration="1h", app="trusted-app")

    assert access.decide_key("trusted-app", "K", policy)["outcome"] == "grant"
    assert access.decide_key("other-app", "K", policy)["outcome"] == "ask"


def test_an_expired_unlock_stops_covering_anything(machine, monkeypatch):
    """Expiry is checked on read, not on a timer — a slept laptop or a moved
    clock must not leave a door open."""
    policy = _rules(agent={"keys": {"K": {"mode": "ask"}}})
    access.open_session(duration="15m")
    assert access.decide_key("agent", "K", policy)["outcome"] == "grant"

    later = access._now() + timedelta(minutes=20)
    monkeypatch.setattr(access, "_now", lambda: later)

    assert access.decide_key("agent", "K", policy)["outcome"] == "ask"
    assert access.sessions() == []


def test_an_unlock_longer_than_a_week_is_refused(machine):
    """An unlock that outlives its reason is just `always` with a worse record."""
    with pytest.raises(ValueError):
        access.open_session(duration="8d")


def test_locking_ends_unlocks(machine):
    access.open_session(duration="1h")
    access.open_session(duration="1h", keys=["OTHER"])

    assert access.close_session()["closed"] == 2
    assert access.sessions() == []


def test_locking_one_unlock_leaves_the_others(machine):
    first = access.open_session(duration="1h")
    access.open_session(duration="1h", keys=["OTHER"])

    result = access.close_session(first["id"])

    assert result["closed"] == 1 and result["remaining"] == 1


def test_an_unlock_records_who_and_why_but_never_a_value(machine):
    unlock = access.open_session(duration="1h", reason="batch render", approved_by="owner")

    written = access.sessions_path().read_text(encoding="utf-8")
    assert unlock["reason"] == "batch render"
    assert unlock["approved_by"] == "owner"
    assert "passbook" not in written.lower() or "value" not in written.lower()
    assert stat.S_IMODE(access.sessions_path().stat().st_mode) == 0o600


# ── the policy file ────────────────────────────────────────────────────────


def test_a_corrupt_policy_grants_rather_than_refuses(machine):
    access.policy_path().write_text("{ not json", encoding="utf-8")
    assert access.read_policy()["default"]["mode"] == "always"


def test_the_policy_is_written_unreadable_to_anyone_else(machine):
    access.write_policy(_rules())
    assert stat.S_IMODE(access.policy_path().stat().st_mode) == 0o600


def test_a_version_one_policy_still_reads(machine):
    """Translated on read, not migrated on disk — an older PassBook may still be
    running against this same store."""
    legacy = {"version": 1, "mode": "deny",
              "apps": {"studio": {"keys": ["ALLOWED_KEY"]}}}
    access.policy_path().write_text(json.dumps(legacy), encoding="utf-8")

    policy = access.read_policy()

    assert policy["version"] == 2
    assert policy["default"]["mode"] == "never", "v1 deny meant: only what is listed"
    assert access.mode_for("studio", "ALLOWED_KEY", policy)["mode"] == "always"
    assert access.mode_for("studio", "OTHER_KEY", policy)["mode"] == "never"


def test_a_version_one_audit_policy_becomes_permissive(machine):
    legacy = {"version": 1, "mode": "audit", "apps": {}}
    access.policy_path().write_text(json.dumps(legacy), encoding="utf-8")

    assert access.read_policy()["default"]["mode"] == "always"


def test_reading_a_v1_policy_does_not_rewrite_it(machine):
    legacy = json.dumps({"version": 1, "mode": "audit", "apps": {}})
    access.policy_path().write_text(legacy, encoding="utf-8")

    access.read_policy()

    assert access.policy_path().read_text(encoding="utf-8") == legacy
