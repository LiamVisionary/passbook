# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""The documentation site, held to what the software actually does.

Docs go wrong in one of two ways. They describe a command that was renamed, or
they point at a screenshot that was deleted. Both are cheap to check and neither
is ever caught by reading.

The prose is not tested and should not be. What is tested is every claim in it
that a machine can check.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SITE = REPO / "docs/index.html"

sys.path.insert(0, str(REPO))


@pytest.fixture(scope="module")
def page() -> str:
    return SITE.read_text(encoding="utf-8")


def test_the_site_is_published_as_written():
    """GitHub Pages runs Jekyll over a folder unless told not to, and Jekyll
    silently drops files it does not understand."""
    assert (REPO / "docs/.nojekyll").exists(), "Jekyll will process this folder"


def test_every_asset_it_points_at_is_there(page):
    missing = [
        target for target in re.findall(r'(?:src|href)="([^"#:]+)"', page)
        if not target.startswith("http") and not (REPO / "docs" / target).exists()
    ]
    assert not missing, f"the site points at files that are not there: {missing}"


def test_every_command_it_documents_exists(page):
    """A reference table is the part people trust most and the part that rots
    fastest. These are the real subcommands or the table is wrong."""
    import passbook_cli

    real = set(next(
        action.choices for action in passbook_cli.build_parser()._actions
        if getattr(action, "choices", None)
    ))
    table = page[page.index('<h2 id="reference">'):page.index('<h2 id="limits">')]
    documented = {
        name for cell in re.findall(r"<td>(.*?)</td>", table, re.S)
        for name in re.findall(r"<code>([a-z-]+)</code>", cell)
    }
    unknown = {name for name in documented if name not in real}
    assert not unknown, f"documented commands that do not exist: {sorted(unknown)}"


def test_the_nav_and_the_headings_agree(page):
    """Every link in the sidebar lands somewhere."""
    targets = set(re.findall(r'id="([a-z-]+)"', page))
    links = set(re.findall(r'href="#([a-z-]+)"', page))
    assert links <= targets, f"sidebar links with no section: {sorted(links - targets)}"


def test_it_does_not_oversell_what_the_tool_stops(page):
    """The README carries a section on what PassBook does not claim, because a
    credential tool that oversells gets trusted in situations it was not built
    for. The site has to carry it too."""
    assert 'id="limits"' in page
    assert "does not stop malware" in page


def test_the_embed_on_the_site_matches_the_one_in_the_readme(page):
    """Two copies of the same snippet is two things to keep right. If they ever
    disagree, somebody copies the wrong one."""
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    for claim in ("17817", "/ask", "passbook://add"):
        assert claim in page, f"the site's embed is missing {claim}"
        assert claim in readme, f"the README's embed is missing {claim}"
    # Neither may teach putting a value in a URL.
    for text, where in ((page, "the site"), (readme, "the README")):
        link = re.search(r"passbook://add\?[^\s\"'<)]+", text)
        assert link, f"no example link in {where}"
        assert not re.search(r"key=[A-Za-z0-9_]+(=|%3D|&#61;)", link.group(0)), \
            f"{where} puts a value in a link: {link.group(0)}"
