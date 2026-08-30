# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Approved agents: a default of ask, with a named set that does not have to.

`always` for everything is what people actually run, because `ask` for
everything asks forty times a day and gets switched off within a week. The
useful middle is a default of ask plus a list — and the list has to be honest
about being organisation rather than authentication.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook  # noqa: E402
import passbook_access as access  # noqa: E402


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    passbook.ensure(app="test")
    return tmp_path


def test_a_fresh_machine_lets_everything_through(machine):
    """The default has to stay what it was, or upgrading turns every agent on
    the box into a prompt nobody was expecting."""
    assert access.default_mode(access.read_policy()) == "always"
    assert access.approved_agents(access.read_policy()) == []


def test_approving_an_agent_and_closing_the_default(machine):
    policy = access.read_policy()
    access.approve_agent("automation", policy)
    access.set_default_mode("ask", policy)
    access.write_policy(policy)

    again = access.read_policy()
    assert access.approved_agents(again) == ["automation"]
    assert access.default_mode(again) == "ask"
    # And the decision point agrees, which is the part that actually matters.
    assert access.decide_key("automation", "K", again)["outcome"] == "grant"
    assert access.decide_key("anything-else", "K", again)["outcome"] == "ask"


def test_unapproving_removes_the_rule_rather_than_pinning_it_to_ask(machine):
    """Setting `ask` instead would leave the agent asking on a machine somebody
    later opened up, and nobody would remember why."""
    policy = access.read_policy()
    access.approve_agent("automation", policy)
    assert access.unapprove_agent("automation", policy) is True
    access.set_default_mode("always", policy)
    assert access.decide_key("automation", "K", policy)["outcome"] == "grant"
    assert access.approved_agents(policy) == []


def test_unapproving_something_that_was_never_approved_says_so(machine):
    assert access.unapprove_agent("ghost", access.read_policy()) is False


def test_the_star_entry_outranks_the_machine_default(machine):
    """`policy --app '*'` is where lookups start, so reporting the machine
    default would show one thing and enforce another."""
    policy = {"default": {"mode": "always"},
              "apps": {"*": {"default": {"mode": "ask"}}}}
    assert access.default_mode(policy) == "ask"


def test_a_bad_mode_is_refused_rather_than_written(machine):
    with pytest.raises(ValueError):
        access.set_default_mode("sometimes", access.read_policy())


def test_star_cannot_be_approved_as_though_it_were_an_agent(machine):
    """`*` is the default. Approving it would silently open the machine while
    reading like one more entry on a list."""
    with pytest.raises(ValueError):
        access.approve_agent("*", access.read_policy())


def test_known_agents_merges_three_sources_and_says_which(machine):
    """Installed is what could ask tomorrow; the ledger is what actually has;
    the fleet is somebody else's machine. Each knows something the others do
    not, so the report names where each agent came from."""
    policy = {"apps": {"*": {"default": {"mode": "ask"}},
                       "automation": {"default": {"mode": "always"}}}}
    found = access.known_agents(
        policy, seen=["automation", "claude"],
        installed=[{"id": "codex"}], peers=["laptop"])
    by_name = {row["name"]: row for row in found}

    assert by_name["automation"]["approved"] is True
    assert by_name["automation"]["mode"] == "always"
    assert "has asked" in by_name["automation"]["where"]
    assert by_name["claude"]["mode"] == "ask"
    assert by_name["codex"]["where"] == ["installed"]
    assert by_name["laptop"]["where"] == ["fleet"]


def test_it_works_with_no_fleet_no_runtimes_and_an_empty_ledger(machine):
    """The difference between a feature and a dependency. A machine with no
    Tailscale, nothing installed and nothing recorded gets an empty list and a
    command that still runs."""
    assert access.known_agents({"apps": {}}, seen=[], installed=[], peers=[]) == []


def test_an_approved_agent_appears_even_if_nothing_discovered_it(machine):
    """Otherwise removing Tailscale would make an approval invisible while it
    was still in force."""
    policy = {"apps": {"ghost-automation": {"default": {"mode": "always"}}}}
    names = [row["name"] for row in access.known_agents(policy)]
    assert names == ["ghost-automation"]


def test_discovery_never_fails_the_command(monkeypatch):
    """Every source is optional. One of them raising must not take down a
    command whose whole job is showing text."""
    import passbook_cli

    for module in ("passbook_brief", "passbook_stamp", "passbook_fleet"):
        monkeypatch.setitem(sys.modules, module, None)
    installed, seen, peers = passbook_cli._discovered_agents()
    assert (installed, seen, peers) == ([], [], [])


def test_the_mode_is_written_where_the_decision_point_reads_it(machine):
    """The bug this file caught. An app's mode lives at
    `apps[name]["default"]["mode"]`, and the first version wrote
    `apps[name]["mode"]` — one level up, a place `mode_for` never looks. Every
    approval was decoration, and a live check passed only because an earlier
    `passbook policy` call had written the real key.

    So this asserts the STORAGE and the BEHAVIOUR, not just the reader agreeing
    with the writer — which it did, wrongly, the whole time.
    """
    policy = access.read_policy()
    access.approve_agent("automation", policy)
    access.set_default_mode("ask", policy)

    assert policy["apps"]["automation"]["default"]["mode"] == "always"
    assert policy["apps"]["*"]["default"]["mode"] == "ask"
    assert access.mode_for("automation", "ANY", policy)["mode"] == "always"
    assert access.mode_for("stranger", "ANY", policy)["mode"] == "ask"


def test_unapproving_leaves_unrelated_per_key_rules_alone(machine):
    """Undoing an approval is not a licence to discard policy somebody set for
    a different reason."""
    policy = access.read_policy()
    access.approve_agent("automation", policy)
    policy["apps"]["automation"].setdefault("keys", {})["SPECIAL"] = {"mode": "never"}
    access.unapprove_agent("automation", policy)
    assert policy["apps"]["automation"]["keys"]["SPECIAL"] == {"mode": "never"}


def test_it_says_when_the_list_is_written_but_not_in_the_path(machine, monkeypatch, capsys):
    """The trap this catches, found by testing the live behaviour rather than
    the policy file: on a plaintext store with reads open, `passbook run`
    resolves values from the file and never asks the broker. The approved list
    was written correctly, read back correctly, and changed nothing — an
    unapproved agent ran unattended anyway.

    A correct policy that is not in the path is worse than no policy, because
    somebody is relying on it.
    """
    import passbook_cli

    policy = access.read_policy()
    access.approve_agent("automation", policy)
    access.set_default_mode("ask", policy)
    access.write_policy(policy)

    monkeypatch.setattr(passbook_cli, "_approvals_are_enforced",
                        lambda: (False, "values can be read straight from the store file"))
    passbook_cli.cmd_approved(
        __import__("argparse").Namespace(add=[], remove=[], only=False,
                                         everyone=False, json=False))
    out = capsys.readouterr().out
    assert "NOT ENFORCED" in out
    assert "--reads sealed" in out


def test_it_stays_quiet_once_the_broker_is_in_the_path(machine, monkeypatch, capsys):
    """The other half. A warning that never goes away is one people stop
    reading, including on the machine where it matters."""
    import passbook_cli

    policy = access.read_policy()
    access.approve_agent("automation", policy)
    access.set_default_mode("ask", policy)
    access.write_policy(policy)

    monkeypatch.setattr(passbook_cli, "_approvals_are_enforced", lambda: (True, ""))
    passbook_cli.cmd_approved(
        __import__("argparse").Namespace(add=[], remove=[], only=False,
                                         everyone=False, json=False))
    assert "NOT ENFORCED" not in capsys.readouterr().out
