# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Importing a project's `.env`, one key at a time.

Dropping a `.env` on the window is the fastest way from "I have a project full
of keys" to "they are in the vault", and it is also the fastest way to
overwrite a credential somebody is still using. So the interesting behaviour is
all in what happens to a key that is already here.

The window is a front end for these flags and nothing else. It draws the list
from `--dry-run --json` and imports with `--only` and `--as`, which is why the
suggested replacement name is decided here rather than there: a name the window
invented would be a second opinion about what a key is called.
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
import passbook_cli  # noqa: E402

SAMPLE = """\
# A project's .env, the way they actually look
OPENAI_API_KEY=sk-proj-from-the-file
STRIPE_SECRET_KEY=sk_live_from_the_file
export DATABASE_URL="postgres://user:pw@localhost:5432/app"
THIS IS NOT A KEY LINE
EMPTY_VALUE=
RESEND_API_KEY=re_from_the_file
"""


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    monkeypatch.delenv("HIVE_ENV_FILES", raising=False)
    monkeypatch.delenv("HIVE_WORKSPACE", raising=False)
    passbook.ensure(app="test")
    passbook.set_values({"OPENAI_API_KEY": "the-one-already-here"})
    envfile = tmp_path / "project.env"
    envfile.write_text(SAMPLE, encoding="utf-8")
    return tmp_path


def cli(*args, home: Path):
    return subprocess.run(
        [sys.executable, "-m", "passbook_cli", *args],
        capture_output=True, text=True, cwd=str(REPO),
        env={**os.environ, "HIVE_HOME": str(home / "hive"), "PYTHONPATH": str(SRC)},
    )


# ── describing the file ─────────────────────────────────────────────────────


def test_the_json_says_what_is_in_the_file_and_what_clashes(machine):
    done = cli("import", str(machine / "project.env"), "--dry-run", "--json", home=machine)
    assert done.returncode == 0, done.stderr
    found = json.loads(done.stdout)

    assert found["shape"] == "plain"
    assert found["name"] == "project.env"
    names = [row["key"] for row in found["keys"]]
    # The comment, the malformed line and the empty value are not keys.
    assert names == ["DATABASE_URL", "OPENAI_API_KEY", "RESEND_API_KEY", "STRIPE_SECRET_KEY"]

    clashing = [row for row in found["keys"] if row["clashes"]]
    assert [row["key"] for row in clashing] == ["OPENAI_API_KEY"]
    assert clashing[0]["suggested"] == "OPENAI_API_KEY_2"


def test_describing_a_file_stores_nothing(machine):
    cli("import", str(machine / "project.env"), "--dry-run", "--json", home=machine)
    assert passbook.key_names() == ["OPENAI_API_KEY"]


def test_no_value_from_the_file_appears_in_the_description(machine):
    """The window draws its list from this. A file being imported is still a
    file full of credentials, and the window is a thing people screen-share."""
    done = cli("import", str(machine / "project.env"), "--dry-run", "--json", home=machine)
    for secret in ("sk-proj-from-the-file", "sk_live_from_the_file", "re_from_the_file"):
        assert secret not in done.stdout, "a value reached the description"


# ── choosing what comes in ──────────────────────────────────────────────────


def test_only_imports_what_was_asked_for(machine):
    done = cli("import", str(machine / "project.env"),
               "--only", "RESEND_API_KEY", "DATABASE_URL", home=machine)
    assert done.returncode == 0, done.stderr
    assert sorted(passbook.key_names()) == ["DATABASE_URL", "OPENAI_API_KEY", "RESEND_API_KEY"]
    # The one that was not chosen stayed out.
    assert "STRIPE_SECRET_KEY" not in passbook.key_names()


def test_a_key_that_is_not_in_the_file_is_refused_rather_than_ignored(machine):
    done = cli("import", str(machine / "project.env"), "--only", "NOT_IN_THERE", home=machine)
    assert done.returncode != 0
    assert "Not in that file" in done.stderr


def test_without_overwrite_a_key_already_here_is_kept(machine):
    cli("import", str(machine / "project.env"), "--only", "OPENAI_API_KEY", home=machine)
    assert passbook.load().get("OPENAI_API_KEY") == "the-one-already-here"


def test_with_overwrite_it_is_replaced(machine):
    done = cli("import", str(machine / "project.env"), "--only", "OPENAI_API_KEY",
               "--overwrite", home=machine)
    assert done.returncode == 0, done.stderr
    assert passbook.load().get("OPENAI_API_KEY") == "sk-proj-from-the-file"


# ── keeping both ────────────────────────────────────────────────────────────


def test_as_keeps_both_copies(machine):
    """The whole reason "add as new" exists. Neither value is lost."""
    done = cli("import", str(machine / "project.env"), "--only", "OPENAI_API_KEY",
               "--as", "OPENAI_API_KEY=OPENAI_API_KEY_2", home=machine)
    assert done.returncode == 0, done.stderr
    assert passbook.load().get("OPENAI_API_KEY") == "the-one-already-here"
    assert passbook.load().get("OPENAI_API_KEY_2") == "sk-proj-from-the-file"


def test_a_rename_must_be_a_usable_key_name(machine):
    done = cli("import", str(machine / "project.env"), "--only", "OPENAI_API_KEY",
               "--as", "OPENAI_API_KEY=not a key name", home=machine)
    assert done.returncode != 0
    assert "not a usable key name" in done.stderr


def test_a_rename_cannot_collide_with_something_else_in_the_same_file(machine):
    done = cli("import", str(machine / "project.env"),
               "--as", "OPENAI_API_KEY=RESEND_API_KEY", home=machine)
    assert done.returncode != 0
    assert "already coming in" in done.stderr


# ── the name it suggests ────────────────────────────────────────────────────


def test_the_suggestion_climbs_rather_than_nesting():
    """`X_2` taken should give `X_3`, not `X_2_2`. Importing the same file
    twice is the ordinary case, so this happens on the second go."""
    assert passbook_cli.free_name("KEY", {"KEY"}) == "KEY_2"
    assert passbook_cli.free_name("KEY", {"KEY", "KEY_2"}) == "KEY_3"
    assert passbook_cli.free_name("KEY_2", {"KEY", "KEY_2"}) == "KEY_3"
    assert passbook_cli.free_name("KEY", set()) == "KEY"


def test_a_name_that_ends_in_a_number_is_not_mangled():
    """`OAUTH2` is a name, not a numbered copy of `OAUTH`."""
    assert passbook_cli.free_name("OAUTH2", {"OAUTH2"}) == "OAUTH2_2"


def test_two_clashing_keys_are_offered_different_names(machine):
    """Both suggestions coming back as the same name would mean the second
    import silently overwrote the first."""
    passbook.set_values({"ALPHA": "here", "ALPHA_2": "also here"})
    envfile = machine / "two.env"
    envfile.write_text("ALPHA=from-file\nALPHA_2=also-from-file\n", encoding="utf-8")
    found = json.loads(cli("import", str(envfile), "--dry-run", "--json", home=machine).stdout)
    suggested = [row["suggested"] for row in found["keys"] if row["clashes"]]
    assert len(suggested) == len(set(suggested)), f"two keys were offered {suggested}"
