# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""The access ledger is archived in segments once it is large, and stays one chain.

One Mac's ledger reached 1.3GB in a month (2026-10-14), almost all of it the
desktop app's credential reads. These tests shrink ARCHIVE_AT_BYTES so a few rows
make a segment, then check that nothing the ledger promises was lost on the way:
the chain verifies across segments, an edit inside an archived segment is still
found, recent rows and per-key usage carry over, and only the newest segments stay.
"""

from __future__ import annotations

import gzip
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook_stamp  # noqa: E402


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    # About three rows per segment.
    monkeypatch.setattr(passbook_stamp, "ARCHIVE_AT_BYTES", 1000)
    return tmp_path


def _stamp(root: Path, count: int, key: str = "A_KEY") -> None:
    for _ in range(count):
        passbook_stamp.stamp(op="read", keys=[key], app="app", root=root)


def test_a_large_ledger_moves_into_the_archive_and_the_chain_runs_through_it(ledger):
    _stamp(ledger, 10)

    archives = passbook_stamp._archives(ledger / passbook_stamp.PROOF_FILENAME)
    assert len(archives) >= 2, "several segments were archived"
    assert archives[-1].name.endswith(".jsonl"), "the newest archive stays plain for cheap tail reads"
    assert all(item.name.endswith(".jsonl.gz") for item in archives[:-1]), "older ones are packed"
    result = passbook_stamp.verify_chain(root=ledger)
    assert result["ok"] is True, result["breaks"]
    assert result["rows"] == 10 and result["segments"] == len(archives) + 1


def test_an_edit_inside_an_archived_segment_is_still_found(ledger):
    _stamp(ledger, 10)
    packed = passbook_stamp._archives(ledger / passbook_stamp.PROOF_FILENAME)[0]
    with gzip.open(packed, "rt", encoding="utf-8") as stream:
        text = stream.read()
    with gzip.open(packed, "wt", encoding="utf-8") as stream:
        stream.write(text.replace("A_KEY", "B_KEY", 1))

    result = passbook_stamp.verify_chain(root=ledger)

    assert result["ok"] is False
    assert any("its own hash" in item["reason"] for item in result["breaks"])


def test_recent_rows_and_usage_counts_carry_over_an_archive(ledger):
    _stamp(ledger, 7, "A_KEY")
    _stamp(ledger, 2, "B_KEY")

    rows = passbook_stamp.read_stamps(limit=9, root=ledger)
    assert [row["keys"] for row in rows] == [["A_KEY"]] * 7 + [["B_KEY"]] * 2, "the newest nine, across segments"
    usage = passbook_stamp.usage_by_key(root=ledger)
    assert usage["A_KEY"]["count"] == 7 and usage["B_KEY"]["count"] == 2
    assert len(passbook_stamp.history_for_key("A_KEY", root=ledger)) == 7


def test_only_the_newest_segments_are_kept(ledger, monkeypatch):
    monkeypatch.setattr(passbook_stamp, "ARCHIVES_KEPT", 2)
    _stamp(ledger, 20)

    archives = passbook_stamp._archives(ledger / passbook_stamp.PROOF_FILENAME)
    assert len(archives) == 2
    # The oldest rows are gone, as if never written; what is left still verifies.
    result = passbook_stamp.verify_chain(root=ledger)
    assert result["ok"] is True and result["rows"] < 20
    # Usage counts were saved as each segment left, so they still count every read.
    assert passbook_stamp.usage_by_key(root=ledger)["A_KEY"]["count"] == 20


def test_a_small_ledger_is_never_archived(tmp_path):
    _stamp(tmp_path, 5)

    assert passbook_stamp._archives(tmp_path / passbook_stamp.PROOF_FILENAME) == []
    assert passbook_stamp.verify_chain(root=tmp_path)["segments"] == 1
