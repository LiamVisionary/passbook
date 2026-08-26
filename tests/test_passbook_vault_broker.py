# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""The end-to-end claim: a sealed store is dark until somebody signs in.

`test_passbook_vault.py` proves the crypto in isolation. This proves the thing
that actually matters to a user — that with a real broker running over a real
store, the credentials are unreadable before sign-in, readable after it, and
unreadable again the moment the vault is locked.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import passbook  # noqa: E402
import passbook_broker  # noqa: E402
import passbook_vault as vault  # noqa: E402

# The broker speaks over a Unix socket, which Windows does not have.
pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="the broker needs AF_UNIX")

PASSWORD = "a properly long vault password"


@pytest.fixture
def sealed(tmp_path, monkeypatch):
    """A machine whose store is fully sealed, with a broker running over it."""
    home = tmp_path / "hive"
    monkeypatch.setenv("HIVE_HOME", str(home))
    for leaked in ("HIVE_ENV_FILES", "APP_SANDBOX_CONTAINER_ID", "HIVE_WORKSPACE"):
        monkeypatch.delenv(leaked, raising=False)
    monkeypatch.setenv("PASSBOOK_APPROVAL_TIMEOUT", "2")
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)

    passbook.ensure(app="test")
    passbook.set_values({"ALPHA": "a-value", "BETA": "b-value"})
    profile = vault.create_profile("Owner", password=PASSWORD, root=home)["id"]
    dek = vault.unlock_with_password(profile, PASSWORD, root=home)
    vault.seal_store(dek, profile_id=profile, root=home)

    started = passbook_broker.start()
    if not started.get("ok"):
        pytest.skip(f"the broker would not start here: {started.get('detail')}")
    try:
        yield home, profile
    finally:
        passbook_broker.stop()


def _read(app: str = "test") -> dict:
    return passbook.request(["ALPHA", "BETA"], app=app)


def test_the_store_is_dark_before_anyone_signs_in(sealed):
    home, _ = sealed
    assert "a-value" not in (home / ".env").read_text(encoding="utf-8")
    assert _read() == {}, "a locked vault handed out credentials"


def test_signing_in_opens_it_and_signing_out_shuts_it_again(sealed):
    home, profile = sealed

    assert _read() == {}
    opened = passbook_broker.signin(profile=profile, password=PASSWORD, duration="15m")
    assert opened["ok"], opened
    assert opened["factor"] == "password"

    assert _read() == {"ALPHA": "a-value", "BETA": "b-value"}

    locked = passbook_broker.signout()
    assert locked["ok"] and locked["was_unlocked"]
    assert _read() == {}, "the vault stayed open after sign-out"


def test_a_wrong_password_does_not_open_it(sealed):
    _, profile = sealed
    refused = passbook_broker.signin(profile=profile, password="not the password")
    assert not refused["ok"]
    assert _read() == {}


def test_the_status_surface_never_carries_the_key(sealed):
    _, profile = sealed
    passbook_broker.signin(profile=profile, password=PASSWORD)
    state = passbook_broker.vault_status()
    assert state["unlocked"] and state["profile"] == profile
    blob = repr(state)
    assert PASSWORD not in blob
    assert "dek" not in blob and "wrapped" not in blob
    # Names stay visible while values do not — a first-run screen still works.
    assert state["store"]["sealed"] == ["ALPHA", "BETA"]
    assert state["store"]["fully_sealed"]


def test_a_direct_file_read_gets_nothing_even_while_signed_in(sealed):
    """The broker holds the key; a process that helps itself does not.

    This is the property that makes sealing worth doing. `load()` is the call
    that reads the file directly, and it must not start working just because
    somebody signed in somewhere else.
    """
    home, profile = sealed
    passbook_broker.signin(profile=profile, password=PASSWORD)
    assert _read() == {"ALPHA": "a-value", "BETA": "b-value"}

    raw = passbook.parse_env_text((home / ".env").read_text(encoding="utf-8"))
    assert all(v.startswith(vault.PREFIX) for v in raw.values())
    assert vault.unseal_mapping(raw, None, profile_id=profile) == {}


def test_signing_in_is_recorded(sealed):
    import passbook_stamp

    _, profile = sealed
    passbook_broker.signin(profile=profile, password="wrong one")
    passbook_broker.signin(profile=profile, password=PASSWORD)
    rows = passbook_stamp.read_stamps(limit=50)
    operations = [row.get("op") for row in rows]
    assert "signin" in operations
    refused = [r for r in rows if r.get("op") == "signin" and not r.get("granted")]
    assert refused, "a refused sign-in left no trace"
    assert PASSWORD not in repr(rows)


# ── writing into a sealed store ────────────────────────────────────────────
#
# The gap these close cost 192 of 262 sealed keys on a real machine. Fleet env
# replication wrote peer values straight into the file, and because only the
# broker holds the key, every one of those writes landed as plaintext beside the
# ciphertext — unsealing the store one key at a time, with nothing about it
# looking like a failure.

def _raw(home: Path) -> dict[str, str]:
    """The file as it sits on disk, opened by nobody."""
    return passbook.parse_env_text((home / ".env").read_text(encoding="utf-8"))


def test_a_value_written_through_the_broker_lands_sealed(sealed):
    home, _ = sealed
    passbook_broker.signin(password=PASSWORD)

    answer = passbook_broker.seal_values({"GAMMA": "c-value"})

    assert answer["ok"] is True
    assert answer["sealed"] == ["GAMMA"]
    assert vault.is_sealed(_raw(home)["GAMMA"])
    # And it is the same secret, not merely something encrypted.
    assert passbook.request(["GAMMA"], app="test")["GAMMA"] == "c-value"


def test_the_store_does_not_end_up_half_encrypted(sealed):
    home, _ = sealed
    passbook_broker.signin(password=PASSWORD)

    passbook_broker.seal_values({"GAMMA": "c-value", "DELTA": "d-value"})

    on_disk = _raw(home)
    assert all(vault.is_sealed(value) for value in on_disk.values()), \
        "a sealed store that accepts a plaintext write is neither sealed nor not"


def test_a_shut_vault_refuses_rather_than_writing_plaintext(sealed):
    """The important half. Writing the plaintext instead would be 'helpful' and
    would silently undo the encryption the owner asked for."""
    home, _ = sealed
    before = _raw(home)

    answer = passbook_broker.seal_values({"GAMMA": "c-value"})

    assert answer["ok"] is False
    assert "shut" in answer["error"]
    assert _raw(home) == before
    assert "GAMMA" not in _raw(home)


def test_an_already_sealed_value_is_not_wrapped_twice(sealed):
    home, profile = sealed
    passbook_broker.signin(password=PASSWORD)
    already = _raw(home)["ALPHA"]

    answer = passbook_broker.seal_values({"ALPHA": already})

    assert answer["sealed"] == []
    assert _raw(home)["ALPHA"] == already
    assert passbook.request(["ALPHA"], app="test")["ALPHA"] == "a-value"


def test_sealing_a_write_is_recorded_by_name(sealed):
    home, _ = sealed
    passbook_broker.signin(password=PASSWORD)
    passbook_broker.seal_values({"GAMMA": "c-value"}, app="some-agent")

    import passbook_stamp

    rows = passbook_stamp.read_stamps(root=home)
    writes = [row for row in rows if row.get("op") == "write"]
    assert writes, "a value entering the store is worth a row"
    assert "GAMMA" in writes[-1]["keys"]
    # Names, never values.
    ledger = (home / passbook_stamp.PROOF_FILENAME).read_text(encoding="utf-8")
    assert "c-value" not in ledger
