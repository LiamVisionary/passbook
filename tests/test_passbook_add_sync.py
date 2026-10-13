"""When an added key is sent to the other machines: typed always, piped only when asked.

The window's add is piped and says `--sync` (tests/test_passbook_app_contract.py). This pins what
that flag does, and that a peer applying a push (piped, no flag) does not send it round again.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import passbook  # noqa: E402
import passbook_cli as cli  # noqa: E402


@pytest.fixture
def sent(tmp_path, monkeypatch):
    for name in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "PASSBOOK_GRANT", "PASSBOOK_APP", "PASSBOOK_REASON"):
        monkeypatch.delenv(name, raising=False)
    for name in ("HIVE_HOME", "HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path))
    monkeypatch.setenv("PASSBOOK_KEYSTORE", "file")
    pushed: list[list[str]] = []
    monkeypatch.setattr(cli, "_replicate_write", lambda keys, values: pushed.append(sorted(keys)))
    monkeypatch.setattr(cli, "_offer_service_updates", lambda updated, values, args: 0)
    return pushed


def _pipe(monkeypatch, text):
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))


def test_a_piped_add_stays_here_unless_it_says_sync(sent, monkeypatch):
    _pipe(monkeypatch, "FROM_A_PEER=synthetic-value-one\n")
    assert cli.main(["add", "--stdin"]) == 0
    assert sent == [], "a peer applying a push must not push it back"
    _pipe(monkeypatch, "FROM_THE_WINDOW=synthetic-value-two\n")
    assert cli.main(["add", "--stdin", "--sync"]) == 0
    assert sent == [["FROM_THE_WINDOW"]]
    assert set(passbook.key_names()) >= {"FROM_A_PEER", "FROM_THE_WINDOW"}


def test_no_sync_wins_and_a_replaced_key_is_sent_too(sent, monkeypatch):
    _pipe(monkeypatch, "KEPT_LOCAL=synthetic-value-three\n")
    assert cli.main(["add", "--stdin", "--sync", "--no-sync"]) == 0
    assert sent == []
    _pipe(monkeypatch, "KEPT_LOCAL=synthetic-value-four\n")
    assert cli.main(["add", "--stdin", "--sync", "--replace"]) == 0
    assert sent == [["KEPT_LOCAL"]], "a changed value is what the other machines most need"
