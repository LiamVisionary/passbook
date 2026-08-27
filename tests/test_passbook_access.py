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
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _platform import assert_private  # noqa: E402

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
    assert_private(access.sessions_path(), 0o600)


# ── the policy file ────────────────────────────────────────────────────────


def test_a_corrupt_policy_grants_rather_than_refuses(machine):
    access.policy_path().write_text("{ not json", encoding="utf-8")
    assert access.read_policy()["default"]["mode"] == "always"


def test_the_policy_is_written_unreadable_to_anyone_else(machine):
    access.write_policy(_rules())
    assert_private(access.policy_path(), 0o600)


def test_a_version_one_policy_still_reads(machine):
    """Translated on read, not migrated on disk — an older PassBook may still be
    running against this same store."""
    legacy = {"version": 1, "mode": "deny",
              "apps": {"studio": {"keys": ["ALLOWED_KEY"]}}}
    access.policy_path().write_text(json.dumps(legacy), encoding="utf-8")

    policy = access.read_policy()

    assert policy["version"] == access.POLICY_VERSION
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


# ── projects: a third bound, beside scope and audience ─────────────────────

def test_a_key_with_no_project_rule_is_readable_from_everywhere():
    policy = access.upgrade_policy({})
    assert access.project_for("ANY_KEY", policy) == {"mode": "all", "projects": []}
    assert access.project_allows("anything", "ANY_KEY", policy)["allowed"] is True
    assert access.project_allows("", "ANY_KEY", policy)["allowed"] is True


def test_include_limits_a_key_to_named_projects():
    policy = access.upgrade_policy({})
    access.set_projects("DEPLOY_KEY", "include", ["acme-site"], policy)
    assert access.project_allows("acme-site", "DEPLOY_KEY", policy)["allowed"] is True
    assert access.project_allows("other-repo", "DEPLOY_KEY", policy)["allowed"] is False


def test_a_caller_that_names_no_project_is_not_on_an_include_list():
    """An `include` list says the key belongs to named projects. A caller that
    names none is not one of them — the alternative is that running outside any
    checkout is the way around every project rule."""
    policy = access.upgrade_policy({})
    access.set_projects("DEPLOY_KEY", "include", ["acme-site"], policy)
    verdict = access.project_allows("", "DEPLOY_KEY", policy)
    assert verdict["allowed"] is False
    assert "named no project" in verdict["why"]


def test_exclude_keeps_everyone_but_the_named():
    policy = access.upgrade_policy({})
    access.set_projects("PROD_KEY", "exclude", ["scratch"], policy)
    assert access.project_allows("scratch", "PROD_KEY", policy)["allowed"] is False
    assert access.project_allows("anything-else", "PROD_KEY", policy)["allowed"] is True
    # No project named is not the excluded one.
    assert access.project_allows("", "PROD_KEY", policy)["allowed"] is True


def test_a_project_rule_refuses_whatever_the_mode_says():
    """The bound is not a preference: `always` does not get past it."""
    policy = access.upgrade_policy({})
    access.set_projects("DEPLOY_KEY", "include", ["acme-site"], policy)
    # The most permissive mode there is, set the way the policy file stores it.
    policy.setdefault("apps", {}).setdefault("some-agent", {}) \
          .setdefault("keys", {})["DEPLOY_KEY"] = {"mode": "always"}
    verdict = access.decide_key("some-agent", "DEPLOY_KEY", policy,
                                workspace="", project="other-repo")
    assert verdict["outcome"] == "refuse"
    assert verdict.get("project") is True


def test_a_project_rule_does_not_disturb_a_key_it_does_not_name():
    policy = access.upgrade_policy({})
    access.set_projects("DEPLOY_KEY", "include", ["acme-site"], policy)
    verdict = access.decide_key("some-agent", "OTHER_KEY", policy,
                                workspace="", project="other-repo")
    assert verdict["outcome"] == "grant"


def test_an_empty_project_list_is_refused_rather_than_locking_everything_out():
    policy = access.upgrade_policy({})
    with pytest.raises(ValueError, match="needs at least one project"):
        access.set_projects("DEPLOY_KEY", "include", [], policy)
    with pytest.raises(ValueError, match="must be one of"):
        access.set_projects("DEPLOY_KEY", "sometimes", ["x"], policy)


def test_a_corrupt_project_entry_degrades_open_not_shut():
    """Same reasoning as the audience: a hand-edited entry must not silently
    cut every project off from a credential."""
    policy = access.upgrade_policy({})
    policy.setdefault("keys", {})["ODD_KEY"] = {"projects": {"include": []}}
    assert access.project_for("ODD_KEY", policy)["mode"] == "all"
    policy["keys"]["WORSE_KEY"] = {"projects": 17}
    assert access.project_for("WORSE_KEY", policy)["mode"] == "all"


def test_setting_projects_back_to_every_clears_the_rule():
    policy = access.upgrade_policy({})
    access.set_projects("DEPLOY_KEY", "include", ["acme-site"], policy)
    access.set_projects("DEPLOY_KEY", "all", [], policy)
    assert access.project_for("DEPLOY_KEY", policy)["mode"] == "all"
    assert access.project_allows("anything", "DEPLOY_KEY", policy)["allowed"] is True


def test_projects_seen_gathers_every_name_any_key_mentions():
    policy = access.upgrade_policy({})
    access.set_projects("A_KEY", "include", ["acme-site", "beta"], policy)
    access.set_projects("B_KEY", "exclude", ["scratch"], policy)
    assert access.projects_seen(policy) == ["acme-site", "beta", "scratch"]


def test_projects_survive_a_policy_write(tmp_path):
    policy = access.upgrade_policy({})
    access.set_projects("DEPLOY_KEY", "include", ["acme-site"], policy)
    access.write_policy(policy, root=tmp_path)
    again = access.read_policy(tmp_path)
    assert access.project_for("DEPLOY_KEY", again)["projects"] == ["acme-site"]


# ── confirmations: the toggles that stop a CHANGE ──────────────────────────

def test_nothing_asks_by_default():
    """A machine where every `passbook add` waits on a dialog is one where
    people stop using `passbook add`."""
    policy = access.upgrade_policy({})
    assert access.confirmations(policy) == {"add": False, "modify": False, "delete": False}
    assert access.needs_confirmation("delete", policy) is False


def test_one_toggle_can_be_turned_on_without_the_others():
    policy = access.upgrade_policy({})
    access.set_confirmation("delete", True, policy)
    current = access.confirmations(policy)
    assert current == {"add": False, "modify": False, "delete": True}
    assert access.needs_confirmation("delete", policy) is True
    assert access.needs_confirmation("add", policy) is False


def test_a_toggle_can_be_turned_back_off():
    policy = access.upgrade_policy({})
    access.set_confirmation("modify", True, policy)
    access.set_confirmation("modify", False, policy)
    assert access.needs_confirmation("modify", policy) is False


def test_an_unknown_change_is_refused():
    policy = access.upgrade_policy({})
    with pytest.raises(ValueError, match="must be one of"):
        access.set_confirmation("rename", True, policy)


def test_a_corrupt_confirm_section_reads_as_off():
    """Degrading OFF here, where audiences degrade OPEN, points the same
    instinct the same way: neither should turn a damaged policy file into a
    machine that has locked its owner out of their own store."""
    policy = access.upgrade_policy({})
    policy["confirm"] = "yes please"
    assert access.confirmations(policy) == {"add": False, "modify": False, "delete": False}
    policy["confirm"] = {"delete": "sometimes"}
    assert access.confirmations(policy)["delete"] is True  # truthy string
    policy["confirm"] = {"delete": ""}
    assert access.confirmations(policy)["delete"] is False


def test_confirmations_survive_a_policy_write(tmp_path):
    """`write_policy` lists its sections literally and has dropped a new one
    before; this is the test that would have caught it."""
    policy = access.upgrade_policy({})
    access.set_confirmation("delete", True, policy)
    access.write_policy(policy, root=tmp_path)
    again = access.read_policy(tmp_path)
    assert access.needs_confirmation("delete", again) is True
