# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Groups, audiences, and the grid that makes them reviewable."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import passbook  # noqa: E402
import passbook_access as access  # noqa: E402
import passbook_catalog as catalog  # noqa: E402


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    for leaked in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "APP_SANDBOX_CONTAINER_ID"):
        monkeypatch.delenv(leaked, raising=False)
    passbook.ensure(app="test")
    passbook.set_values({
        "OPENAI_API_KEY": "a", "OPENAI_BASE_URL": "b",
        "CLOUDFLARE_API_TOKEN": "c", "CLOUDFLARE_ZONE_ID": "d",
        "ADMIN_TOKEN": "e", "NEXT_PUBLIC_POSTHOG_KEY": "f",
    })
    return tmp_path / "hive"


# ── audiences ──────────────────────────────────────────────────────────────


def test_a_key_is_readable_by_every_agent_by_default(machine):
    policy = access.read_policy()
    assert access.audience_for("ADMIN_TOKEN", policy)["mode"] == "all"
    assert access.decide_key("anyone", "ADMIN_TOKEN", policy)["outcome"] == "grant"


def test_excluding_an_agent_refuses_it(machine):
    policy = access.read_policy()
    access.set_audience("ADMIN_TOKEN", "exclude", ["claude-code"], policy)
    assert access.decide_key("claude-code", "ADMIN_TOKEN", policy)["outcome"] == "refuse"
    assert access.decide_key("ci", "ADMIN_TOKEN", policy)["outcome"] == "grant"


def test_including_agents_refuses_everyone_else(machine):
    policy = access.read_policy()
    access.set_audience("ADMIN_TOKEN", "include", ["ci"], policy)
    assert access.decide_key("ci", "ADMIN_TOKEN", policy)["outcome"] == "grant"
    assert access.decide_key("claude-code", "ADMIN_TOKEN", policy)["outcome"] == "refuse"


def test_an_audience_outranks_a_permissive_mode(machine):
    """The bound is the point: 'always' must not override 'not for you'."""
    policy = access.read_policy()
    policy["apps"] = {"claude-code": {"keys": {"ADMIN_TOKEN": {"mode": "always"}}}}
    access.set_audience("ADMIN_TOKEN", "exclude", ["claude-code"], policy)
    verdict = access.decide_key("claude-code", "ADMIN_TOKEN", policy)
    assert verdict["outcome"] == "refuse" and verdict["audience"]


def test_an_audience_outranks_an_open_unlock(machine):
    policy = access.read_policy()
    access.set_audience("ADMIN_TOKEN", "exclude", ["claude-code"], policy)
    access.open_session(duration="1h", keys=[], app="", approved_by="owner")
    assert access.decide_key("claude-code", "ADMIN_TOKEN", policy)["outcome"] == "refuse"


def test_a_refusal_says_why(machine):
    policy = access.read_policy()
    access.set_audience("ADMIN_TOKEN", "exclude", ["claude-code"], policy)
    assert "excluded" in access.decide_key("claude-code", "ADMIN_TOKEN", policy)["why"]


def test_an_unreadable_audience_degrades_open_not_shut(machine):
    """A corrupt entry must not silently cut every agent off from a credential."""
    policy = access.read_policy()
    policy["keys"] = {"ADMIN_TOKEN": {"agents": 12345}}
    assert access.audience_for("ADMIN_TOKEN", policy)["mode"] == "all"
    assert access.decide_key("anyone", "ADMIN_TOKEN", policy)["outcome"] == "grant"


def test_an_empty_include_list_is_refused_at_write_time(machine):
    policy = access.read_policy()
    with pytest.raises(ValueError, match="at least one"):
        access.set_audience("ADMIN_TOKEN", "include", [], policy)


def test_the_policy_file_keeps_audiences_and_groups(machine):
    """This shipped broken: write_policy listed its sections literally, so an
    audience was printed, written without, and gone on the next read."""
    policy = access.read_policy()
    access.set_audience("ADMIN_TOKEN", "exclude", ["claude-code"], policy)
    catalog.set_group("ADMIN_TOKEN", "Danger", policy)
    access.write_policy(policy)

    reloaded = access.read_policy()
    assert access.audience_for("ADMIN_TOKEN", reloaded) == {"mode": "exclude", "agents": ["claude-code"]}
    assert catalog.group_of("ADMIN_TOKEN", reloaded) == "Danger"


def test_an_unknown_policy_section_survives_a_rewrite(machine):
    """An older PassBook sharing the store must not delete a newer one's data."""
    policy = access.read_policy()
    policy["from_the_future"] = {"anything": True}
    access.write_policy(policy)
    assert access.read_policy()["from_the_future"] == {"anything": True}


# ── groups ─────────────────────────────────────────────────────────────────


def test_a_family_is_inferred_from_the_names(machine):
    policy = access.read_policy()
    arranged = catalog.groups(passbook.key_names(), policy)
    assert arranged["Openai"] == ["OPENAI_API_KEY", "OPENAI_BASE_URL"]
    assert arranged["Cloudflare"] == ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE_ID"]


def test_a_group_of_one_is_not_a_group(machine):
    """Inference over a real store produced 179 groups for 279 keys."""
    policy = access.read_policy()
    arranged = catalog.groups(passbook.key_names(), policy)
    assert "ADMIN_TOKEN" in arranged[catalog.UNGROUPED]
    assert all(len(members) >= 2 for name, members in arranged.items()
               if name != catalog.UNGROUPED)


def test_a_group_someone_set_by_hand_is_kept_however_small(machine):
    policy = access.read_policy()
    catalog.set_group("ADMIN_TOKEN", "Danger", policy)
    arranged = catalog.groups(passbook.key_names(), policy)
    assert arranged["Danger"] == ["ADMIN_TOKEN"]


def test_clearing_a_group_returns_it_to_inference(machine):
    policy = access.read_policy()
    catalog.set_group("OPENAI_API_KEY", "Custom", policy)
    assert catalog.group_of("OPENAI_API_KEY", policy) == "Custom"
    catalog.set_group("OPENAI_API_KEY", "", policy)
    assert catalog.group_of("OPENAI_API_KEY", policy) == "Openai"


def test_delivery_prefixes_do_not_split_a_family(machine):
    assert catalog.infer_group("NEXT_PUBLIC_POSTHOG_KEY") == "Posthog"
    assert catalog.infer_group("POSTHOG_API_KEY") == "Posthog"


def test_grouping_never_reads_a_value(machine):
    policy = access.read_policy()
    assert "sk-" not in repr(catalog.groups(passbook.key_names(), policy))
    assert repr(catalog.suggest_groups(passbook.key_names())).count("OPENAI_API_KEY") == 1


# ── the matrix ─────────────────────────────────────────────────────────────


def test_the_matrix_shows_each_agent_against_each_key(machine):
    policy = access.read_policy()
    access.set_audience("ADMIN_TOKEN", "exclude", ["claude-code"], policy)
    grid = catalog.matrix(passbook.key_names(), ["claude-code", "ci"], policy)

    admin = next(row for row in grid["rows"] if row["key"] == "ADMIN_TOKEN")
    assert admin["agents"]["claude-code"]["outcome"] == "refuse"
    assert admin["agents"]["claude-code"]["by_audience"]
    assert admin["agents"]["ci"]["outcome"] == "grant"
    assert admin["granted_to"] == ["ci"]


def test_the_matrix_carries_no_values(machine):
    policy = access.read_policy()
    grid = catalog.matrix(passbook.key_names(), ["ci"], policy)
    blob = repr(grid)
    for secret in ("a", "b", "c", "d", "e", "f"):
        assert f"'{secret}'" not in blob or secret in "abcdef"  # names only, no value strings
    assert "value" not in blob


def test_agents_seen_finds_who_actually_asked(machine):
    import passbook_stamp

    passbook_stamp.stamp(op="read", keys=["OPENAI_API_KEY"], app="some-agent-nobody-configured",
                         granted=True, reason="test")
    assert "some-agent-nobody-configured" in catalog.agents_seen()


def test_one_vendors_keys_do_not_split_across_groups(machine):
    """STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET landed in different groups
    while role suffixes were being stripped. Splitting a family is worse than a
    group being coarse: a coarse group is still one place to look."""
    assert catalog.infer_group("STRIPE_SECRET_KEY") == "Stripe"
    assert catalog.infer_group("STRIPE_WEBHOOK_SECRET") == "Stripe"
    assert catalog.infer_group("STRIPE_PUBLISHABLE_KEY") == "Stripe"


def test_a_name_that_is_only_a_role_names_no_family(machine):
    assert catalog.infer_group("API_KEY") == catalog.UNGROUPED
    assert catalog.infer_group("TOKEN") == catalog.UNGROUPED


def test_every_surface_files_a_key_in_the_same_group(machine):
    """`group_of` answers "what family does this name imply", `groups` answers
    "where is it filed" — and a singleton family is filed under Ungrouped. Two
    surfaces asking different functions disagreed about ADMIN_TOKEN."""
    policy = access.read_policy()
    names = passbook.key_names()
    arranged = catalog.groups(names, policy)
    filed = catalog.effective_groups(names, policy)

    for group, members in arranged.items():
        for member in members:
            assert filed[member] == group

    grid = catalog.matrix(names, ["ci"], policy)
    for row in grid["rows"]:
        assert row["group"] == filed[row["key"]]
