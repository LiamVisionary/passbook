# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""Standing access: one app keeps one key while the vault is locked.

The claims, each proven against a real broker over a real sealed store:

  · a kept key reaches the app it was kept for with nobody signed in,
  · and no other app, and no other key,
  · a rotated key is refused rather than served stale, and a sign-in heals it,
  · a key removed from the store stops being served whatever the escrow holds,
  · the policy still decides first — standing access lifts the lock, nothing else.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from _platform import broker_marker

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook  # noqa: E402
import passbook_broker  # noqa: E402
import passbook_keystore  # noqa: E402
import passbook_standing as standing  # noqa: E402
import passbook_vault as vault  # noqa: E402

# The broker needs a transport; every supported platform now has one.
pytestmark = broker_marker()

PASSWORD = "a properly long vault password"


@pytest.fixture
def keystore(monkeypatch):
    """An escrow key that lives in this test, not in the developer's keychain.

    Supplied through the environment because the broker is another process, and
    a monkeypatched keystore would not reach it. The patched keystore underneath
    is a tripwire: nothing may fall through to the real one.
    """
    import base64
    import os

    monkeypatch.setenv(standing.KEY_ENV, base64.urlsafe_b64encode(os.urandom(32)).decode())
    held: dict[str, str] = {}
    monkeypatch.setattr(passbook_keystore, "available", lambda: True)
    monkeypatch.setattr(passbook_keystore, "describe", lambda: "a test keystore")
    monkeypatch.setattr(passbook_keystore, "fetch", lambda name: held.get(name, ""))

    def store(name, value):
        held[name] = value
        return {"ok": True, "backend": "test", "detail": "held in the test"}

    monkeypatch.setattr(passbook_keystore, "store", store)
    standing._reset_cache()
    yield held
    standing._reset_cache()


@pytest.fixture
def sealed(tmp_path, monkeypatch, keystore):
    """A sealed store, a broker over it, the vault shut, and a way to keep a key."""
    home = tmp_path / "hive"
    monkeypatch.setenv("HIVE_HOME", str(home))
    for leaked in ("HIVE_ENV_FILES", "APP_SANDBOX_CONTAINER_ID", "HIVE_WORKSPACE",
                   "HIVE_WORKSPACE_ID", "PASSBOOK_APP"):
        monkeypatch.delenv(leaked, raising=False)
    monkeypatch.setenv("PASSBOOK_NO_NOTIFY", "1")
    monkeypatch.setenv("PASSBOOK_APPROVAL_TIMEOUT", "2")
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)

    passbook.ensure(app="test")
    passbook.set_values({"ALPHA": "a-value", "BETA": "b-value"})
    profile = vault.create_profile("Owner", password=PASSWORD, root=home)["id"]
    dek = vault.unlock_with_password(profile, PASSWORD, root=home)
    vault.seal_store(dek, profile_id=profile, root=home)

    def keep(name: str, *apps: str) -> dict:
        stored = _raw(home)[name]
        value = vault.unseal_value(name, stored, dek, profile_id=profile)
        return standing.keep(name, value, stored, apps=apps, workspace="main", root=home)

    def rotate(name: str, value: str) -> None:
        passbook.set_values({name: vault.seal_value(name, value, dek, profile_id=profile)},
                            overwrite=True, exact=True)

    started = passbook_broker.start()
    if not started.get("ok"):
        pytest.skip(f"the broker would not start here: {started.get('detail')}")
    try:
        yield home, keep, rotate
    finally:
        passbook_broker.stop()


def _raw(home: Path) -> dict[str, str]:
    return passbook.parse_env_text((home / ".env").read_text(encoding="utf-8"))


# ── the module on its own ──────────────────────────────────────────────────


def test_a_generic_caller_name_cannot_be_given_standing_access(tmp_path, keystore):
    for generic in ("passbook-run", "unknown", "", "*"):
        with pytest.raises(standing.StandingError):
            standing.keep("ALPHA", "v", "hive-sealed:v2:x", apps=[generic],
                          workspace="main", root=tmp_path)
    assert not (tmp_path / standing.FILENAME).exists()


def test_the_file_never_holds_a_value(tmp_path, keystore):
    standing.keep("ALPHA", "plain-secret-value", "hive-sealed:v2:abc", apps=["watcher"],
                  workspace="main", root=tmp_path)
    text = (tmp_path / standing.FILENAME).read_text(encoding="utf-8")
    assert "plain-secret-value" not in text
    assert (tmp_path / standing.FILENAME).stat().st_mode & 0o077 == 0


def test_a_copy_cannot_be_moved_to_another_key(tmp_path, keystore):
    standing.keep("ALPHA", "a", "s-a", apps=["w"], workspace="main", root=tmp_path)
    standing.keep("BETA", "b", "s-b", apps=["w"], workspace="main", root=tmp_path)
    data = standing._read(tmp_path)
    space = data["workspaces"]["main"]
    space["BETA"]["sealed"] = space["ALPHA"]["sealed"]
    standing._write(tmp_path, data)
    opened, refused = standing.open_for("w", "main", {"BETA": "s-b"}, root=tmp_path)
    assert opened == {} and "BETA" in refused


def test_release_narrows_then_removes(tmp_path, keystore):
    standing.keep("ALPHA", "a", "s", apps=["one", "two"], workspace="main", root=tmp_path)
    assert standing.release("ALPHA", apps=["one"], workspace="main", root=tmp_path)["apps"] == ["two"]
    assert standing.kept_names("main", root=tmp_path) == {"ALPHA"}
    standing.release("ALPHA", workspace="main", root=tmp_path)
    assert standing.kept_names("main", root=tmp_path) == set()


# ── against a real broker ──────────────────────────────────────────────────


def test_a_kept_key_reaches_its_app_while_the_vault_is_locked(sealed):
    _, keep, _ = sealed
    assert passbook.request(["ALPHA"], app="watcher") == {}, "the fixture left the vault open"

    keep("ALPHA", "watcher")

    assert passbook.request(["ALPHA", "BETA"], app="watcher") == {"ALPHA": "a-value"}


def test_no_other_app_and_no_other_key(sealed):
    _, keep, _ = sealed
    keep("ALPHA", "watcher")

    assert passbook.request(["ALPHA", "BETA"], app="someone-else") == {}
    assert passbook.request(["BETA"], app="watcher") == {}


def test_a_spawned_command_gets_it_too(sealed):
    _, keep, _ = sealed
    keep("ALPHA", "watcher")
    out = io.StringIO()
    final = passbook_broker.spawn_streaming(
        [sys.executable, "-c", "import os; print(len(os.environ.get('ALPHA', '')))"],
        ["ALPHA"], app="watcher", out=out, err=io.StringIO())
    assert final and final.get("exit_code") == 0, final
    assert out.getvalue().strip() == str(len("a-value"))


def test_a_rotated_key_is_refused_until_a_sign_in_refreshes_it(sealed):
    home, keep, rotate = sealed
    keep("ALPHA", "watcher")
    rotate("ALPHA", "rotated-value")

    assert passbook.request(["ALPHA"], app="watcher") == {}, "served a rotated-away value"
    assert [row["state"] for row in standing.entries(root=home, stored={"main": _raw(home)})] == ["stale"]

    assert passbook_broker.signin(password=PASSWORD)["ok"]
    assert passbook_broker.signout()["ok"]

    assert passbook.request(["ALPHA"], app="watcher") == {"ALPHA": "rotated-value"}


def test_reading_with_the_vault_open_refreshes_the_copy(sealed):
    _, keep, rotate = sealed
    keep("ALPHA", "watcher")
    rotate("ALPHA", "second-value")
    assert passbook_broker.signin(password=PASSWORD)["ok"]
    # A read by anybody, with the vault open, is enough.
    assert passbook.request(["ALPHA"], app="watcher") == {"ALPHA": "second-value"}
    rotate("ALPHA", "third-value")
    assert passbook.request(["ALPHA"], app="other") == {"ALPHA": "third-value"}
    passbook_broker.signout()
    assert passbook.request(["ALPHA"], app="watcher") == {"ALPHA": "third-value"}


def test_a_removed_key_stops_being_served(sealed):
    _, keep, _ = sealed
    keep("ALPHA", "watcher")
    passbook.remove_values(["ALPHA"])
    assert passbook.request(["ALPHA"], app="watcher") == {}


def test_the_policy_still_decides_first(sealed):
    import passbook_access as access

    home, keep, _ = sealed
    keep("ALPHA", "watcher")
    policy = access.read_policy()
    access.set_audience("ALPHA", "include", ["somebody-else"], policy)
    access.write_policy(policy)

    assert passbook.request(["ALPHA"], app="watcher") == {}


def test_every_locked_use_is_recorded(sealed):
    import passbook_stamp

    home, keep, _ = sealed
    keep("ALPHA", "watcher")
    passbook.request(["ALPHA"], app="watcher")
    rows = [row for row in passbook_stamp.read_stamps(root=home) if row["op"] == "standing"]
    assert rows and rows[-1]["granted"] and rows[-1]["app"] == "watcher"
    assert rows[-1]["keys"] == ["ALPHA"]


# ── the command a person types ─────────────────────────────────────────────


def _cli(*args: str, stdin: str = ""):
    import os
    import subprocess

    source = Path(__file__).resolve().parents[1] / "src"
    return subprocess.run([sys.executable, "-m", "passbook_cli", *args],
                          capture_output=True, text=True, input=stdin,
                          env={**os.environ, "PYTHONPATH": str(source)})


def test_the_command_states_the_cost_before_it_asks_for_anything(sealed):
    done = _cli("standing", "add", "ALPHA", "--app", "watcher")
    assert done.returncode == 1
    assert "ANY program" in done.stdout
    assert passbook.request(["ALPHA"], app="watcher") == {}


def test_the_command_needs_the_password_and_then_it_works(sealed):
    wrong = _cli("standing", "add", "ALPHA", "--app", "watcher", "--yes", "--password-stdin",
                 stdin="not the password\n")
    assert wrong.returncode != 0
    assert passbook.request(["ALPHA"], app="watcher") == {}

    done = _cli("standing", "add", "ALPHA", "--app", "watcher", "--yes", "--password-stdin",
                stdin=PASSWORD + "\n")
    assert done.returncode == 0, done.stderr
    assert "a-value" not in done.stdout + done.stderr
    assert passbook.request(["ALPHA"], app="watcher") == {"ALPHA": "a-value"}

    listed = _cli("standing")
    assert "ALPHA: watcher" in listed.stdout

    taken = _cli("standing", "remove", "ALPHA", "--app", "watcher")
    assert taken.returncode == 0, taken.stderr
    assert passbook.request(["ALPHA"], app="watcher") == {}


def test_the_command_refuses_the_name_every_unnamed_caller_gets(sealed):
    done = _cli("standing", "add", "ALPHA", "--app", "passbook-run", "--yes", "--password-stdin",
                stdin=PASSWORD + "\n")
    assert done.returncode != 0
    assert "every caller" in done.stderr


def test_giving_and_taking_are_recorded_against_the_app(sealed):
    import passbook_stamp

    home, _, _ = sealed
    assert _cli("standing", "add", "ALPHA", "--app", "watcher", "--yes", "--password-stdin",
                stdin=PASSWORD + "\n").returncode == 0
    assert _cli("standing", "remove", "ALPHA").returncode == 0
    rows = [(row["op"], row["app"], row["keys"]) for row in passbook_stamp.read_stamps(root=home)
            if row["op"] in {"keep", "release"}]
    assert rows == [("keep", "watcher", ["ALPHA"]), ("release", "watcher", ["ALPHA"])]
