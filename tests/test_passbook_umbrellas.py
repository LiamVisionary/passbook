# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Umbrellas: one set of keys covering several projects.

Three things in this project sound alike and decide different questions, and
most of this file exists to keep them apart.

  * a GROUP is inferred from a key's own name so a store of three hundred keys
    can be read. Every key falls into one, so it must never gate anything.
  * an UMBRELLA is created on purpose. It covers projects, holds keys, and
    bounds a read.
  * a WORKSPACE decides which store a key lives in at all.

The last two compose — both must say yes — and the interesting failure is not
either of them being wrong but the two DISAGREEING, where an umbrella reads as a
grant and behaves as a refusal.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

import passbook  # noqa: E402
import passbook_access as access  # noqa: E402
import passbook_catalog as catalog  # noqa: E402


@pytest.fixture
def policy():
    return {"keys": {}}


@pytest.fixture
def covered(policy):
    """An umbrella over three checkouts, holding one key."""
    access.create_umbrella("ai apps", policy, tags=["llm", "media"], note="shared")
    access.put_under_umbrella("ai-apps", ["OPENAI_API_KEY"], policy)
    access.add_umbrella_projects("ai-apps", ["ami", "hivemindos", "ansem"], policy)
    return policy


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    monkeypatch.delenv("PASSBOOK_PROJECT", raising=False)
    passbook.ensure(app="test")
    passbook.set_values({"OPENAI_API_KEY": "not-real", "STRIPE_SECRET_KEY": "also-not-real"})
    return tmp_path


def cli(*args, home: Path):
    return subprocess.run(
        [sys.executable, "-m", "passbook_cli", *args],
        capture_output=True, text=True, cwd=str(REPO),
        env={**os.environ, "HIVE_HOME": str(home / "hive"), "PYTHONPATH": str(SRC)},
    )


# ── an umbrella is not a group ──────────────────────────────────────────────


def test_an_inferred_group_never_bounds_a_key(policy):
    """If it did, one umbrella anywhere would put the whole store behind rules
    nobody wrote."""
    assert catalog.infer_group("OPENAI_API_KEY") == "OpenAI"
    assert access.project_allows("any-project", "OPENAI_API_KEY", policy)["allowed"]


def test_a_display_group_is_not_consulted_even_when_it_shares_a_name(policy):
    """`group set` arranges a listing. It must not be able to govern by
    accident just because somebody used the same word twice."""
    access.create_umbrella("ai apps", policy)
    access.add_umbrella_projects("ai-apps", ["ami"], policy)
    catalog.set_group("OPENAI_API_KEY", "ai apps", policy)   # display only
    assert access.umbrella_for_key("OPENAI_API_KEY", policy) == {}
    assert access.project_allows("anywhere", "OPENAI_API_KEY", policy)["allowed"]


def test_a_key_is_governed_only_by_being_put_under_one(policy):
    access.create_umbrella("ai apps", policy)
    access.add_umbrella_projects("ai-apps", ["ami"], policy)
    access.put_under_umbrella("ai-apps", ["OPENAI_API_KEY"], policy)
    assert access.umbrella_for_key("OPENAI_API_KEY", policy)["id"] == "ai-apps"
    assert not access.project_allows("elsewhere", "OPENAI_API_KEY", policy)["allowed"]


# ── closed from the start ───────────────────────────────────────────────────


def test_a_new_umbrella_covers_nothing_and_so_grants_nothing(policy):
    access.create_umbrella("ai apps", policy)
    access.put_under_umbrella("ai-apps", ["OPENAI_API_KEY"], policy)
    for project in ("ami", "", "anything"):
        assert not access.project_allows(project, "OPENAI_API_KEY", policy)["allowed"], project
    why = access.project_allows("ami", "OPENAI_API_KEY", policy)["why"]
    assert "ai apps" in why and "covers no projects" in why, why


def test_covering_projects_admits_exactly_those(covered):
    for project in ("ami", "hivemindos", "ansem"):
        assert access.project_allows(project, "OPENAI_API_KEY", covered)["allowed"], project
    for project in ("other-repo", ""):
        assert not access.project_allows(project, "OPENAI_API_KEY", covered)["allowed"], project


def test_uncovering_the_last_project_shuts_it_again(covered):
    access.set_umbrella_projects("ai-apps", [], covered)
    assert not access.project_allows("ami", "OPENAI_API_KEY", covered)["allowed"]


# ── reach and visibility are two switches ───────────────────────────────────


def test_reach_everyone_admits_every_project(covered):
    access.set_umbrella_reach("ai-apps", "everyone", covered)
    assert access.project_allows("anything-at-all", "OPENAI_API_KEY", covered)["allowed"]


def test_visible_but_not_usable_is_reachable(covered):
    """The combination one boolean could not express: an agent learns the
    umbrella exists and that it is not for them, instead of learning nothing."""
    access.set_umbrella_listed("ai-apps", True, covered)
    seen = access.listed_umbrellas(covered, project="a-stranger")
    assert seen == [{"name": "ai apps", "id": "ai-apps", "tags": ["llm", "media"],
                     "note": "shared", "usable_here": False}]
    assert not access.project_allows("a-stranger", "OPENAI_API_KEY", covered)["allowed"]


def test_usable_here_is_answered_for_the_caller_not_in_the_abstract(covered):
    """Reported from reach alone, this told a MEMBER it could not use the very
    umbrella that was granting it keys."""
    access.set_umbrella_listed("ai-apps", True, covered)
    assert access.listed_umbrellas(covered, project="ami")[0]["usable_here"] is True
    assert access.listed_umbrellas(covered, project="stranger")[0]["usable_here"] is False


def test_usable_without_being_visible_is_also_reachable(covered):
    access.set_umbrella_reach("ai-apps", "everyone", covered)
    assert access.listed_umbrellas(covered) == []
    assert access.project_allows("anyone", "OPENAI_API_KEY", covered)["allowed"]


def test_open_and_close_are_the_two_common_corners(covered):
    access.set_umbrella_reach("ai-apps", "everyone", covered)
    access.set_umbrella_listed("ai-apps", True, covered)
    record = access.umbrella_record("ai-apps", covered)
    assert record["reach"] == "everyone" and record["listed"] is True


def test_an_unreadable_posture_is_the_closed_corner(policy):
    """Degrading open would hand an umbrella's keys to every project the first
    time something writes this file wrongly."""
    policy["umbrellas"] = {"ai-apps": {"label": "ai apps", "reach": "yes please",
                                       "listed": "sure", "projects": []}}
    record = access.read_umbrellas(policy)["ai-apps"]
    assert record["reach"] == "members" and record["listed"] is False


# ── composing with the bounds that were already there ───────────────────────


def test_a_rule_on_the_key_itself_outranks_its_umbrella(covered):
    access.set_projects("OPENAI_API_KEY", "include", ["somewhere-else"], covered)
    assert not access.project_allows("ami", "OPENAI_API_KEY", covered)["allowed"]
    assert access.project_allows("somewhere-else", "OPENAI_API_KEY", covered)["allowed"]


def test_a_project_under_two_umbrellas_sees_the_union(policy):
    for name in ("one", "two"):
        access.create_umbrella(name, policy)
        access.add_umbrella_projects(name, ["ami"], policy)
    access.put_under_umbrella("one", ["A_KEY"], policy)
    access.put_under_umbrella("two", ["B_KEY"], policy)
    assert access.project_allows("ami", "A_KEY", policy)["allowed"]
    assert access.project_allows("ami", "B_KEY", policy)["allowed"]
    assert not access.project_allows("elsewhere", "A_KEY", policy)["allowed"]


def test_workspace_scope_and_an_umbrella_both_have_to_say_yes(covered):
    """They are different axes — which store, and which projects within it — so
    they compose. A member of the umbrella still cannot reach a key that lives
    in a workspace it is not in."""
    access.set_scope("OPENAI_API_KEY", "workspace", covered, workspace="acme")
    assert not access.scope_allows("main", "OPENAI_API_KEY", covered)["allowed"]
    assert access.scope_allows("acme", "OPENAI_API_KEY", covered)["allowed"]
    # And the umbrella is still what decides the project question.
    assert access.project_allows("ami", "OPENAI_API_KEY", covered)["allowed"]


def test_a_contradiction_between_the_two_is_reported_rather_than_silent(covered):
    """The real hazard of two bounds is not either being wrong. It is a rule
    that READS like a grant and BEHAVES like a refusal."""
    access.set_scope("OPENAI_API_KEY", "workspace", covered, workspace="acme")
    assert access.umbrella_conflicts("ai-apps", covered, workspace="acme") == []
    clashes = access.umbrella_conflicts("ai-apps", covered, workspace="main")
    assert len(clashes) == 1
    assert "acme workspace" in clashes[0]["why"], clashes


def test_a_per_key_rule_that_overrides_the_umbrella_is_also_reported(covered):
    access.set_projects("OPENAI_API_KEY", "include", ["acme"], covered)
    clashes = access.umbrella_conflicts("ai-apps", covered)
    assert len(clashes) == 1 and "outranks this umbrella" in clashes[0]["why"]


def test_an_umbrella_with_no_contradictions_reports_none(covered):
    assert access.umbrella_conflicts("ai-apps", covered) == []


# ── the single decision point ───────────────────────────────────────────────


def test_decide_key_is_where_this_is_resolved(covered):
    """Not a fourth place that must remember to ask — the broker, the MCP
    server and the matrix all inherit this without knowing it exists."""
    refused = access.decide_key("some-app", "OPENAI_API_KEY", covered, project="elsewhere")
    assert refused["outcome"] == "refuse" and refused.get("project") is True
    assert access.decide_key("some-app", "OPENAI_API_KEY", covered,
                             project="ami")["outcome"] != "refuse"


def test_deleting_an_umbrella_frees_its_keys(covered):
    assert not access.project_allows("elsewhere", "OPENAI_API_KEY", covered)["allowed"]
    assert access.delete_umbrella("ai-apps", covered)
    assert access.project_allows("elsewhere", "OPENAI_API_KEY", covered)["allowed"]
    assert access.umbrella_for_key("OPENAI_API_KEY", covered) == {}


def test_taking_a_key_out_frees_only_that_key(covered):
    access.put_under_umbrella("ai-apps", ["SECOND_KEY"], covered)
    assert access.take_from_umbrella(["SECOND_KEY"], covered) == ["SECOND_KEY"]
    assert access.project_allows("elsewhere", "SECOND_KEY", covered)["allowed"]
    assert not access.project_allows("elsewhere", "OPENAI_API_KEY", covered)["allowed"]


# ── names ───────────────────────────────────────────────────────────────────


def test_a_label_and_its_handle_are_the_same_umbrella():
    assert access.umbrella_id("ai apps") == access.umbrella_id("AI  Apps") == "ai-apps"


def test_a_name_that_cannot_be_a_handle_is_refused(policy):
    with pytest.raises(ValueError):
        access.create_umbrella("   ", policy)


# ── through the command line ────────────────────────────────────────────────


def test_the_whole_flow_from_the_command_line(store):
    assert cli("umbrella", "new", "ai apps", "--tag", "llm", home=store).returncode == 0
    assert cli("umbrella", "add", "ai-apps", "OPENAI_API_KEY", home=store).returncode == 0
    assert cli("umbrella", "cover", "ai-apps", "ami", "hivemindos", home=store).returncode == 0

    listed = json.loads(cli("umbrella", "--json", home=store).stdout)
    assert [u["id"] for u in listed] == ["ai-apps"]
    assert listed[0]["projects"] == ["ami", "hivemindos"]
    assert listed[0]["keys"] == ["OPENAI_API_KEY"]
    assert listed[0]["reach"] == "members" and listed[0]["listed"] is False


def test_putting_keys_under_one_says_what_it_did_to_them(store):
    cli("umbrella", "new", "ai apps", home=store)
    done = cli("umbrella", "add", "ai-apps", "OPENAI_API_KEY", home=store)
    assert "NOTHING can read them" in done.stdout, done.stdout
    assert "umbrella cover" in done.stdout


def test_group_set_stays_the_harmless_thing_it_was(store):
    """It arranges a listing. It is not an access change and must not report
    itself as one — a store where every arrangement shouts is a store where
    nobody reads the shouting."""
    done = cli("group", "set", "Payments", "STRIPE_SECRET_KEY", home=store)
    assert done.returncode == 0
    assert "access" not in done.stdout.lower(), done.stdout
    listed = json.loads(cli("umbrella", "--json", home=store).stdout)
    assert listed == []


def test_a_contradiction_is_surfaced_at_the_moment_the_rule_is_written(store):
    cli("umbrella", "new", "ai apps", home=store)
    cli("umbrella", "cover", "ai-apps", "ami", home=store)
    cli("projects", "set", "OPENAI_API_KEY", "--only", "acme", home=store)
    done = cli("umbrella", "add", "ai-apps", "OPENAI_API_KEY", home=store)
    assert "will not do what this umbrella says" in done.stderr, done.stderr
    assert "outranks this umbrella" in done.stderr


def test_reach_and_visibility_move_independently_from_the_command_line(store):
    cli("umbrella", "new", "ai apps", home=store)
    cli("umbrella", "show-agents", "ai-apps", home=store)
    seen = json.loads(cli("umbrella", "--json", home=store).stdout)[0]
    assert seen["listed"] is True and seen["reach"] == "members"
    cli("umbrella", "reach", "ai-apps", "everyone", home=store)
    seen = json.loads(cli("umbrella", "--json", home=store).stdout)[0]
    assert seen["listed"] is True and seen["reach"] == "everyone"


def test_naming_one_that_does_not_exist_says_so(store):
    done = cli("umbrella", "cover", "no-such-thing", "ami", home=store)
    assert done.returncode != 0 and "no umbrella called" in done.stderr


def test_an_umbrella_never_carries_a_value(store):
    cli("umbrella", "new", "ai apps", home=store)
    cli("umbrella", "add", "ai-apps", "OPENAI_API_KEY", home=store)
    assert "not-real" not in cli("umbrella", "--json", home=store).stdout
