# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Exports: the three shapes, and the promises each one makes.

An export is the largest read anybody performs against a store — every value at
once, written somewhere the store's own protections do not reach. These pin the
parts that stop that being a quiet mistake.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import passbook_backup as backup  # noqa: E402

PASSPHRASE = "a-long-enough-passphrase"
VALUES = {"ALPHA_KEY": "one", "BETA_KEY": "two with spaces", "GAMMA_KEY": "three"}


def test_an_encrypted_export_round_trips():
    text = backup.encrypt(VALUES, PASSPHRASE, workspace="main", machine="test")
    assert backup.detect(text) == "encrypted"
    document = backup.decrypt(text, PASSPHRASE)
    assert backup.keys_of(document) == VALUES
    assert document["workspace"] == "main"
    assert document["count"] == 3


def test_the_wrong_passphrase_is_refused_without_saying_which_half_was_wrong():
    text = backup.encrypt(VALUES, PASSPHRASE)
    with pytest.raises(backup.BackupError) as raised:
        backup.decrypt(text, "not-the-passphrase")
    # Distinguishing "wrong passphrase" from "damaged file" would be an oracle.
    assert "wrong or the file is damaged" in str(raised.value)


def test_an_export_carries_no_key_material_in_the_clear():
    text = backup.encrypt(VALUES, PASSPHRASE)
    for value in VALUES.values():
        assert value not in text
    for name in VALUES:
        assert name not in text


def test_a_short_passphrase_is_refused():
    with pytest.raises(backup.BackupError, match="at least 8"):
        backup.encrypt(VALUES, "short")


def test_a_damaged_envelope_says_so_rather_than_crashing():
    text = backup.encrypt(VALUES, PASSPHRASE)
    head, _, _ = text.partition("\n")
    with pytest.raises(backup.BackupError, match="header is damaged"):
        backup.decrypt(head + "\nnot json at all", PASSPHRASE)


def test_a_truncated_body_says_so():
    envelope = json.loads(backup.encrypt(VALUES, PASSPHRASE).partition("\n")[2])
    envelope["body"] = backup._b64(b"tiny")
    text = backup.MARKER + "\n" + json.dumps(envelope)
    with pytest.raises(backup.BackupError, match="truncated"):
        backup.decrypt(text, PASSPHRASE)


# ── shape detection ────────────────────────────────────────────────────────

def test_detect_reads_the_content_not_the_filename():
    assert backup.detect(backup.encrypt(VALUES, PASSPHRASE)) == "encrypted"
    assert backup.detect("-----BEGIN PGP MESSAGE-----\nx\n") == "gpg"
    assert backup.detect("FOO=bar\n") == "plain"
    # Leading whitespace is not a different format.
    assert backup.detect("\n\n  " + backup.MARKER + "\n{}") == "encrypted"


def test_read_opens_any_shape_without_being_told_which():
    assert backup.keys_of(backup.read(backup.encrypt(VALUES, PASSPHRASE),
                                      passphrase=PASSPHRASE)) == VALUES
    assert backup.keys_of(backup.read(backup.plain(VALUES))) == VALUES


def test_an_encrypted_export_without_its_passphrase_says_so():
    with pytest.raises(backup.BackupError, match="needs its passphrase"):
        backup.read(backup.encrypt(VALUES, PASSPHRASE))


def test_a_file_that_is_not_an_export_at_all_is_refused():
    with pytest.raises(backup.BackupError, match="looked like a credential"):
        backup.read("just some prose, no equals signs here\n")


# ── plaintext ──────────────────────────────────────────────────────────────

def test_a_plaintext_export_leads_with_what_it_is():
    text = backup.plain(VALUES, path="/tmp/x.env")
    assert "EVERY VALUE BELOW IS IN THE CLEAR" in text.splitlines()[0]
    assert backup.keys_of(backup.read(text)) == VALUES


def test_a_plaintext_export_quotes_the_way_the_store_does():
    """Not a second answer to 'how is a value with a space written'."""
    text = backup.plain({"SPACED": "two with spaces"})
    assert backup.keys_of(backup.read(text))["SPACED"] == "two with spaces"


# ── the file on disk ───────────────────────────────────────────────────────

def test_an_export_is_written_private_and_leaves_no_readable_half(tmp_path):
    target = tmp_path / "store.pbx"
    backup.write_private(target, backup.encrypt(VALUES, PASSPHRASE))
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".*.partial"))


def test_a_failed_write_removes_its_own_temporary(tmp_path, monkeypatch):
    target = tmp_path / "store.pbx"

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", explode)
    with pytest.raises(OSError):
        backup.write_private(target, "x")
    assert not target.exists()
    assert not list(tmp_path.glob(".*.partial"))


# ── gpg, when the machine has it ───────────────────────────────────────────

needs_gpg = pytest.mark.skipif(shutil.which("gpg") is None, reason="no gpg on this machine")


@needs_gpg
def test_a_symmetric_gpg_export_round_trips():
    text = backup.gpg_encrypt(VALUES, passphrase=PASSPHRASE)
    assert backup.detect(text) == "gpg"
    assert backup.keys_of(backup.read(text, passphrase=PASSPHRASE)) == VALUES


@needs_gpg
def test_a_gpg_export_needs_a_recipient_or_a_passphrase():
    with pytest.raises(backup.BackupError, match="recipient or a passphrase"):
        backup.gpg_encrypt(VALUES)
