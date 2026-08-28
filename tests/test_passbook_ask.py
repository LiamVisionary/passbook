# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Add to PassBook — the button a platform puts on its API page.

The page that just minted your key hands it straight to your vault, so nobody
types a credential. That makes a web page an input to a credential manager,
which is only safe while four things stay true, and these tests keep them true:

  * values travel over loopback, never in a URL, because a URL becomes a
    command line on Windows and a log line everywhere else;
  * a value the page sent never reaches the window, which is a thing people
    screen-share;
  * nothing is stored without a person approving it and opening the vault;
  * who is asking comes from the browser, not from the page's own claim.

The parser itself is tested in Rust, next to the code, where a value in a link
can be asserted against the parsed struct. Those run in the `parser` CI job,
which has the system libraries a Tauri crate needs to build. Trying to run them
from here instead took down all six Python jobs, because a GUI crate does not
build on a runner that only installed Python.

What is checked here is the wiring around it: the window, the ACL, and the
documentation people will copy.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
UI = REPO / "app/ui/index.html"
MAIN = REPO / "app/src-tauri/src/main.rs"
ASK = REPO / "app/src-tauri/src/ask.rs"
CAPABILITY = REPO / "app/src-tauri/capabilities/default.json"

WINDOW = UI.read_text(encoding="utf-8")


# ── the link cannot carry a credential ──────────────────────────────────────


def test_a_link_still_cannot_carry_a_value():
    """Values go by loopback. The URL path exists to *start* the app, and must
    never become a second way in for a credential."""
    source = ASK.read_text(encoding="utf-8")
    assert "fn parse(" in source
    assert "a_value_in_the_link_is_refused_not_stored" in source, \
        "the test that proves a link cannot carry a value has gone"


def test_the_value_never_reaches_the_window():
    """A window gets screen-shared and gets devtools opened on it. It has no
    reason to hold a credential it is only going to hand straight back."""
    source = ASK.read_text(encoding="utf-8")
    assert "skip_serializing" in source, "the value is being serialised to the window"
    assert "the_value_never_reaches_the_window" in source, "the Rust proof has gone"
    # And the window must not try to send one back.
    assert "typed" in WINDOW and "askReq.keys.filter((k) => !k.has_value)" in WINDOW, \
        "the window is sending back values the app already holds"


def test_the_page_hands_the_value_over_on_loopback():
    """The whole point: nobody types a credential."""
    source = ASK.read_text(encoding="utf-8")
    assert "fn parse_page(" in source
    main = MAIN.read_text(encoding="utf-8")
    assert '"/ask"' in main, "there is no endpoint for a page to post to"
    assert "Access-Control-Allow-Origin" in main, "a button on someone else's page could not reach it"


def test_the_window_shows_a_preview_and_not_the_credential():
    """Enough to recognise which key it is, not enough to use."""
    review = WINDOW[WINDOW.index("function askReview()"):WINDOW.index("function askUnlock()")]
    assert "k.preview" in review
    source = ASK.read_text(encoding="utf-8")
    assert "fn preview_of" in source
    assert "a_short_value_previews_as_a_length_not_as_itself" in source, \
        "a short secret would be shown in full by a head-and-tail preview"


# ── nothing is stored without a decision ────────────────────────────────────


def test_storing_needs_an_approval_and_an_open_vault():
    """There is no path from a link to a stored key that skips either step."""
    assert "data-aadd" in WINDOW, "the approve button"
    assert 'askView.step = "unlock"' in WINDOW, "the vault step"
    # The unlock step is entered whenever the target workspace has a vault that
    # is not already open, which is the condition that makes it skippable.
    assert "target?.has_vault" in WINDOW
    assert "unlocked_workspaces" in WINDOW


def test_an_answer_cannot_be_applied_to_a_different_request():
    """A second link replaces the first. Approving the one you read must not
    store the one that arrived while you were reading it."""
    source = MAIN.read_text(encoding="utf-8")
    assert "current.id == id" in source, "apply_ask does not check which request it is answering"


def test_the_request_outranks_the_sign_in_sheet():
    """Otherwise a person signs in first and reads what they approved second."""
    assert "if (askShouldShow()) return false;" in WINDOW


# ── what the window shows about the asker ───────────────────────────────────


def test_only_a_real_origin_is_shown_as_one():
    """`javascript:` in a trust prompt is a lie with a padlock next to it."""
    source = ASK.read_text(encoding="utf-8")
    assert "fn origin_of" in source
    assert "only_http_origins_are_shown" in source


def test_the_asker_is_shown_as_a_claim_not_a_fact():
    """`app` is whatever the link said. The origin is the part that means
    something, so both are shown and the origin is not omitted."""
    review = WINDOW[WINDOW.index("function askReview()"):WINDOW.index("function askUnlock()")]
    assert "askReq.origin" in review
    assert "askReq.app" in review


# ── the plumbing ────────────────────────────────────────────────────────────


def test_the_window_may_call_the_commands_it_needs():
    """A remote origin gets nothing it is not granted, so a missing entry here
    is a feature that loads, looks right, and answers 'not allowed by ACL'."""
    granted = set(json.loads(CAPABILITY.read_text(encoding="utf-8"))["permissions"])
    for command in ("pending_ask", "dismiss_ask", "apply_ask"):
        # The generator writes these in kebab case, which is Tauri's spelling.
        entry = "allow-" + command.replace("_", "-")
        assert entry in granted, f"{command} is not in the window's ACL"


def test_the_scheme_is_registered():
    conf = json.loads((REPO / "app/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))
    schemes = conf["plugins"]["deep-link"]["desktop"]["schemes"]
    assert "passbook" in schemes


def test_a_link_that_arrives_before_the_window_is_not_lost():
    """A cold start fires the event before there is anything listening, so the
    window has to ask as well as listen."""
    assert 'invoke("pending_ask")' in WINDOW
    assert 'events.listen("passbook://ask"' in WINDOW
    assert "get_current()" in MAIN.read_text(encoding="utf-8")


# ── what people will copy ───────────────────────────────────────────────────


def test_the_readme_gives_an_embed_that_matches_what_the_app_accepts():
    """The snippet in the README is the one thing everybody copies. If it
    drifts from what the app accepts, every page that copied it is broken."""
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "Add to PassBook" in readme, "the README does not document the button"
    assert "/ask" in readme, "the embed does not post to the app"
    assert "17817" in readme, "the embed does not name the port the app prefers"
    # The app walks upward when 17817 is taken, so a snippet that only ever
    # tries one port works until somebody has two things listening.
    assert "17826" in readme or "17825" in readme, "the embed tries only one port"
    assert "passbook://add" in readme, "no fallback to start the app"
    link = re.search(r"passbook://add\?[^\s\"'<)]+", readme)
    assert link, "no example link in the README"
    # The example must never teach people to put a value in a URL.
    assert not re.search(r"key=[A-Za-z0-9_]+(=|%3D)", link.group(0)), \
        f"the README's example puts a value in a link: {link.group(0)}"
