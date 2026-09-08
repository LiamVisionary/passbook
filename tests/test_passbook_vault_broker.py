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
import os
import sys
import time
from pathlib import Path

import pytest

from _platform import broker_marker

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import passbook  # noqa: E402
import passbook_broker  # noqa: E402
import passbook_vault as vault  # noqa: E402

# The broker needs a transport; every supported platform now has one.
pytestmark = broker_marker()

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


@pytest.fixture
def workspace_broker(tmp_path, monkeypatch):
    import json

    home = tmp_path / "workspace-broker"
    monkeypatch.setenv("HIVE_HOME", str(home))
    for name in ("HIVE_ENV_FILES", "APP_SANDBOX_CONTAINER_ID", "HIVE_WORKSPACE", "HIVE_WORKSPACE_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PASSBOOK_NO_NOTIFY", "1")
    monkeypatch.setenv("PASSBOOK_APPROVAL_TIMEOUT", "3")
    monkeypatch.setenv("AMBIENT_ONLY", "synthetic-daemon-environment")
    monkeypatch.setattr(vault, "SCRYPT_N", 1 << 12)
    home.mkdir()
    (home / "workspaces.json").write_text(json.dumps({
        "activeWorkspaceId": "main", "workspaces": [
            {"id": "main"}, {"id": "alpha", "inherit": False},
            {"id": "beta", "inherit": False}, {"id": "inheriting", "inherit": True}]}))
    for workspace in ("main", "alpha", "beta", "inheriting"):
        path = passbook.workspace_env_path(workspace)
        passbook.set_values({"SAME_KEY": f"synthetic-{workspace}",
                             f"{workspace.upper()}_ONLY": f"synthetic-{workspace}-only"},
                            workspace_id=workspace)
        profile = vault.create_profile("Owner", password=PASSWORD, root=path.parent)["id"]
        dek = vault.unlock_with_password(profile, PASSWORD, root=path.parent)
        vault.seal_store(dek, profile_id=profile, root=path.parent, path=path)
    assert passbook_broker.start()["ok"]
    try:
        for workspace in ("main", "alpha", "beta", "inheriting"):
            assert passbook_broker.signin(password=PASSWORD, workspace=workspace)["ok"]
        yield home
    finally:
        passbook_broker.stop(root=home)


def test_concurrent_requests_use_the_requested_workspace_key_and_store(workspace_broker):
    from concurrent.futures import ThreadPoolExecutor

    def read(workspace):
        answer = passbook_broker._ask({"op": "request", "app": "agent", "workspace": workspace,
            "keys": ["SAME_KEY", "MAIN_ONLY", "ALPHA_ONLY", "BETA_ONLY", "AMBIENT_ONLY"]})
        assert answer["granted"] == {
            "SAME_KEY": f"synthetic-{workspace}",
            f"{workspace.upper()}_ONLY": f"synthetic-{workspace}-only"}
        assert answer["workspace"] == workspace
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(read, ["alpha", "beta"] * 12))
    assert passbook.workspace() == "main"
    main = passbook_broker._ask({"op": "request", "app": "agent", "workspace": "main",
                                "keys": ["SAME_KEY", "AMBIENT_ONLY"]})
    assert main["granted"] == {"SAME_KEY": "synthetic-main", "AMBIENT_ONLY": "synthetic-daemon-environment"}


def test_an_inherited_store_uses_its_own_key_but_a_locked_override_stays_closed(workspace_broker):
    request = {"op": "request", "app": "agent", "workspace": "inheriting",
               "keys": ["SAME_KEY", "MAIN_ONLY", "INHERITING_ONLY"]}
    answer = passbook_broker._ask(request)
    assert answer["granted"] == {"SAME_KEY": "synthetic-inheriting",
        "MAIN_ONLY": "synthetic-main-only", "INHERITING_ONLY": "synthetic-inheriting-only"}
    assert passbook_broker.signout(workspace="inheriting")["ok"]
    answer = passbook_broker._ask(request)
    assert answer["granted"] == {"MAIN_ONLY": "synthetic-main-only"}
    assert "SAME_KEY" in answer["missing"]


def test_spawn_stream_and_status_keep_the_workspace_binding(workspace_broker):
    import io
    import passbook_stamp

    command = [sys.executable, "-c", "import os; "
        "assert os.environ['SAME_KEY'] == 'synthetic-alpha'; "
        "assert os.environ['HIVE_WORKSPACE'] == 'alpha'; "
        "assert os.environ['HIVE_WORKSPACE_ID'] == 'alpha'; "
        "print('WORKSPACE_OK')"]
    answer = passbook_broker._ask({"op": "spawn", "app": "agent", "workspace": "alpha",
        "keys": ["SAME_KEY"], "command": command}, timeout=30)
    assert answer["ok"] and answer["exit_code"] == 0, answer
    assert "WORKSPACE_OK" in answer["stdout"]
    out = io.StringIO()
    streamed = passbook_broker.spawn_streaming(command, ["SAME_KEY"], app="agent",
                                               workspace="alpha", out=out, err=io.StringIO())
    assert streamed["ok"] and streamed["exit_code"] == 0
    assert "WORKSPACE_OK" in out.getvalue()
    state = passbook_broker._ask({"op": "status", "workspace": "alpha"})
    assert state["workspace"] == "alpha"
    assert state["keys"] == ["ALPHA_ONLY", "SAME_KEY"]
    grants = passbook_broker._ask({"op": "grants"})["grants"]
    assert all(row["workspace"] == "alpha" for row in grants)
    rows = passbook_stamp.read_stamps(root=workspace_broker)
    assert all(row["workspace"] == "alpha" for row in rows if row["op"] == "use")


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


def test_signing_in_again_keeps_the_length_somebody_chose(sealed):
    """Omitting `--for` means "as it is", not "for ever".

    The duration defaulted to no-expiry whenever one was not named, so signing
    in a second time — to switch profile, or right after enrolling a passkey —
    silently promoted a session somebody had deliberately boxed to an hour into
    one that never ends. Nothing said so, and the only place it showed was a
    countdown that had quietly stopped counting.
    """
    _, profile = sealed

    boxed = passbook_broker.signin(profile=profile, password=PASSWORD, duration="15m")
    assert boxed["ok"] and boxed["expires_in"] == 15 * 60

    again = passbook_broker.signin(profile=profile, password=PASSWORD)
    assert again["ok"], again
    assert again["expires_in"] == 15 * 60, \
        "signing in again threw away the length that was chosen"

    # And naming one still wins over what is held.
    named = passbook_broker.signin(profile=profile, password=PASSWORD, duration="always")
    assert named["ok"] and named["expires_in"] == 0


def test_a_workspace_that_is_not_open_yet_still_defaults_to_always(sealed):
    """The inheritance must not cost the default the owner asked for."""
    _, profile = sealed
    first = passbook_broker.signin(profile=profile, password=PASSWORD)
    assert first["ok"] and first["expires_in"] == 0, \
        "a first sign-in should stay open until it is locked"


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


def test_app_replacement_advances_sync_age_only_after_encrypted_save(sealed):
    import subprocess
    import passbook_sync as sync

    home, _ = sealed
    store = home / ".env"
    sync.touch_meta(store, ["ALPHA", "BETA"], when=100)
    before = store.read_bytes()
    cli = Path(__file__).resolve().parents[1] / "bin" / "passbook"
    command = [sys.executable, str(cli), "add", "--stdin", "--replace"]
    refused = subprocess.run(command, input="ALPHA=synthetic-rotation\n",
                             text=True, capture_output=True, timeout=15)
    assert refused.returncode != 0
    assert store.read_bytes() == before
    assert sync.read_meta(store) == {"ALPHA": 100, "BETA": 100}
    assert passbook_broker.signin(password=PASSWORD)["ok"]
    saved = subprocess.run(command, input="ALPHA=synthetic-rotation\nGAMMA=synthetic-new\n",
                           text=True, capture_output=True, timeout=15)
    assert saved.returncode == 0, saved.stderr
    metadata = sync.read_meta(store)
    assert metadata["ALPHA"] > 100 and metadata["GAMMA"] > 100
    assert metadata["BETA"] == 100
    assert all(vault.is_sealed(value) for value in _raw(home).values())
    assert passbook.request(["ALPHA"], app="test")["ALPHA"] == "synthetic-rotation"
    plan = sync.plan_pull({"ALPHA": "a-value"}, {"ALPHA": 100},
        [("source", {"values": {"ALPHA": "synthetic-rotation"}, "updatedAt": metadata})])
    assert plan["apply"] == {"ALPHA": "synthetic-rotation"}
    assert "synthetic-rotation" not in saved.stdout + saved.stderr + store.read_text()


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


def test_a_sealed_key_can_still_be_deleted(sealed):
    """`remove_values` asked `_read` whether a key was there, and `_read`
    answers with VALUES — dropping every sealed one outside the broker, which
    is every process except the broker itself. So removal reported "not in the
    store" and left the key exactly where it was.

    Deleting a credential is the half you least want silently failing: you
    believe it is gone, and it is still readable by anything that signs in."""
    home, _ = sealed
    assert "ALPHA" in _raw(home)

    result = passbook.remove_values(["ALPHA"])

    assert result["removed"] == ["ALPHA"]
    assert result["absent"] == []
    assert "ALPHA" not in _raw(home)
    # The rest of the store is untouched and still sealed.
    assert vault.is_sealed(_raw(home)["BETA"])


def test_removing_a_key_that_really_is_absent_still_says_so(sealed):
    home, _ = sealed
    result = passbook.remove_values(["NEVER_EXISTED"])
    assert result["removed"] == []
    assert result["absent"] == ["NEVER_EXISTED"]


# ── how long a sign-in lasts ───────────────────────────────────────────────


def test_a_sign_in_does_not_expire_unless_a_length_is_asked_for(sealed):
    """Agents read credentials overnight, and the default used to be 8 hours.

    A vault that locks itself at four in the morning does not protect anything.
    It stops the work, and it teaches whoever owns the machine to leave the
    store unsealed — which is the outcome the timer was there to prevent.
    """
    _, profile = sealed

    opened = passbook_broker.signin(profile=profile, password=PASSWORD)

    assert opened["ok"], opened
    assert opened["expires_in"] == 0, "the default sign-in still runs out"
    assert passbook_broker.vault_status()["expires_in"] == 0
    assert _read() == {"ALPHA": "a-value", "BETA": "b-value"}


def test_no_expiry_can_be_asked_for_by_name(sealed):
    _, profile = sealed

    opened = passbook_broker.signin(profile=profile, password=PASSWORD, duration="always")

    assert opened["ok"] and opened["expires_in"] == 0
    assert _read()


def test_an_open_session_with_no_end_is_not_read_as_already_ended(sealed):
    """Zero meant "expired in 1970" to the check that hands out the key.

    The whole feature is one comparison: a session with no end has to survive
    the next read, not be swept by the guard that clears expired ones.
    """
    _, profile = sealed
    passbook_broker.signin(profile=profile, password=PASSWORD)

    for _ in range(3):
        assert _read() == {"ALPHA": "a-value", "BETA": "b-value"}
    assert passbook_broker.vault_status()["unlocked"] is True


def test_a_length_that_was_asked_for_is_still_honoured(sealed):
    """Removing the default must not remove the option."""
    _, profile = sealed

    opened = passbook_broker.signin(profile=profile, password=PASSWORD, duration="15m")

    assert opened["ok"]
    assert 0 < opened["expires_in"] <= 15 * 60
    assert passbook_broker.vault_status()["expires_in"] > 0


def test_a_session_that_has_run_out_hands_out_nothing(sealed):
    _, profile = sealed
    passbook_broker.signin(profile=profile, password=PASSWORD, duration="1s")
    assert _read()

    time.sleep(1.2)

    assert _read() == {}, "an expired session still opened the store"
    assert passbook_broker.vault_status()["unlocked"] is False


def test_the_record_says_how_long_the_sign_in_was_for(sealed):
    """A row saying "for 0s" would read as a refusal rather than a session."""
    home, profile = sealed
    import passbook_stamp

    passbook_broker.signin(profile=profile, password=PASSWORD)

    rows = [r for r in passbook_stamp.read_stamps(limit=40, root=home)
            if r["op"] == "signin" and r["granted"]]
    assert rows, "a sign-in went unrecorded"
    assert "until it is locked" in rows[-1]["reason"], rows[-1]["reason"]


def test_an_older_broker_is_named_as_the_problem_not_your_typing(monkeypatch):
    """The broker outlives the command that talks to it, so it can be older.

    `always` means no expiry to this CLI and is not a duration to a broker that
    started before that existed — and the message it comes back with reads as a
    typo, when the fix is to restart something you were not thinking about.
    """
    import argparse
    import passbook_cli

    import io
    import sys as _sys

    said = []
    monkeypatch.setattr(passbook_broker, "signin", lambda **kw: {
        "ok": False, "error": "'always' is not a duration — try 30m, 2h or 1d"})
    monkeypatch.setattr(passbook_broker, "running", lambda **kw: True)
    monkeypatch.setattr(passbook_broker, "vault_status", lambda **kw: {
        "ok": True, "supported": True, "unlocked": False})
    monkeypatch.setattr(_sys, "stdin", io.StringIO("a password\n"))
    monkeypatch.setattr(_sys, "stderr", io.StringIO())
    args = argparse.Namespace(profile="", workspace="", duration="always", passkey="",
                              device=False, recovery=False, password_stdin=True)

    code = passbook_cli.cmd_signin(args)
    said.append(_sys.stderr.getvalue())

    assert code != 0
    assert "broker restart" in said[0], said[0]


def test_the_words_for_no_expiry_are_defined_once():
    """Two copies of this list is one copy that goes stale."""
    import passbook_cli

    assert "always" in passbook_broker.FOREVER_WORDS
    source = Path(passbook_cli.__file__).read_text(encoding="utf-8")
    assert "_FOREVER_WORDS" not in source, "the CLI kept its own copy of the words"


def test_a_session_that_opens_nothing_does_not_report_a_readable_store(sealed):
    """Every profile has its own key, and "unlocked" only means one is held.

    Signing in to the wrong profile holds a perfectly good key that opens
    nothing, and the window said Open over a store where every value stayed
    unreadable — the same lie the vault screen already told once, from the
    other direction.
    """
    home, profile = sealed
    other = vault.create_profile("Other", password="a different password", root=home)
    assert not other["active"], "creating a profile switched to it"

    passbook_broker.signin(profile=other["id"], password="a different password")
    status = passbook_broker.vault_status()

    assert status["unlocked"] is True, "a key is held; that part is true"
    assert status["sealed_count"] > 0
    assert status["opens"] == 0, "this profile cannot open a single sealed value"
    assert _read() == {}, "it read values it has no key for"


def test_the_right_profile_opens_what_it_sealed(sealed):
    _, profile = sealed

    passbook_broker.signin(profile=profile, password=PASSWORD)
    status = passbook_broker.vault_status()

    assert status["opens"] == status["sealed_count"] > 0


def test_a_grant_cannot_move_to_a_sibling_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    passbook.set_values({"SAME_KEY": "synthetic-beta"}, workspace_id="beta")
    token = "synthetic-workspace-grant"
    passbook_broker._remember_grant(token, app="agent", keys=["SAME_KEY"], command=["test"],
                                    pid=None, workspace="alpha")
    try:
        answer = passbook_broker._handle({"op": "request", "app": "agent", "workspace": "beta",
            "keys": ["SAME_KEY"], "grant": token}, root=tmp_path)
        assert answer["granted"] == {}
        assert answer["denied"] == ["SAME_KEY"]
        assert "different workspace" in answer["why"]["SAME_KEY"]
    finally:
        passbook_broker._GRANTS.pop(token, None)


def test_pending_approval_remembers_only_its_request_workspace(workspace_broker):
    from concurrent.futures import ThreadPoolExecutor
    import passbook_access as access
    access.write_policy({"default": {"mode": "always"}, "apps": {
        "agent": {"keys": {"SAME_KEY": {"mode": "ask"}}}}}, root=workspace_broker)
    with ThreadPoolExecutor(max_workers=1) as pool:
        waiting = pool.submit(passbook_broker._ask, {"op": "request", "workspace": "alpha",
            "project": "example-project", "app": "agent", "keys": ["SAME_KEY"]})
        deadline = time.monotonic() + 3
        pending = []
        while time.monotonic() < deadline:
            pending = passbook_broker._ask({"op": "pending"})["pending"]
            if pending:
                break
            time.sleep(0.01)
        assert len(pending) == 1
        assert pending[0]["workspace"] == "alpha" and pending[0]["project"] == "example-project"
        assert "_root" not in pending[0]
        assert passbook_broker._ask({"op": "resolve", "id": pending[0]["id"],
            "approve": True, "remember": "1h"})["ok"]
        assert waiting.result(timeout=5)["granted"] == {"SAME_KEY": "synthetic-alpha"}
    assert access.session_covers("agent", "SAME_KEY", workspace="alpha", root=workspace_broker)
    assert access.session_covers("agent", "SAME_KEY", workspace="beta", root=workspace_broker) is None


def test_broker_refresh_uses_workspace_tokens_and_keeps_new_values_sealed(workspace_broker):
    import passbook_oauth as oauth
    from fake_provider import FakeProvider
    with FakeProvider(rotate=True) as provider:
        grant = {"id": "custom:work", "key_prefix": "SCOPED", "token_url": provider.token_url,
                 "client_id": "test-client", "client_secret_key": "SCOPED_CLIENT_SECRET"}
        keys = oauth.grant_keys(grant)
        alpha = passbook.workspace_env_path("alpha")
        oauth._write({"version": oauth.GRANTS_VERSION, "grants": [grant]}, root=alpha.parent)
        expired = {keys["access_token"]: "synthetic-expired", keys["refresh_token"]: "refresh-1",
                   keys["expires_at"]: str(int(time.time()) - 10), "SCOPED_CLIENT_SECRET": "synthetic-alpha-client"}
        assert passbook_broker.seal_values(expired, workspace_id="alpha")["ok"]
        assert passbook_broker.seal_values({"SCOPED_CLIENT_SECRET": "synthetic-main-client"}, workspace_id="main")["ok"]
        main_before = (workspace_broker / ".env").read_bytes()
        beta_before = passbook.workspace_env_path("beta").read_bytes()
        answer = passbook_broker._ask({"op": "request", "workspace": "alpha", "app": "agent",
                                       "keys": [keys["access_token"]]}, timeout=10)
        assert answer["granted"] == {keys["access_token"]: "access-1"}
        assert len(provider.calls) == 1
        assert provider.calls[0]["client_secret"] == "synthetic-alpha-client"
        assert all(value.startswith("hive-sealed:v2:") for value in passbook.parse_env_text(alpha.read_text()).values())
        assert (workspace_broker / ".env").read_bytes() == main_before
        assert passbook.workspace_env_path("beta").read_bytes() == beta_before
        assert passbook.workspace() == "main"


def test_proxy_uses_explicit_workspace_and_does_not_change_process_environment(tmp_path, monkeypatch):
    import passbook_grant
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    monkeypatch.setenv("HIVE_WORKSPACE", "main")
    passbook.set_values({"SAME_KEY": "synthetic-main"})
    passbook.set_values({"SAME_KEY": "synthetic-client"}, workspace_id="client")
    received = []
    monkeypatch.setattr(passbook_grant, "proxy", lambda request, values, **kwargs:
                        received.append(values) or {"ok": True})
    monkeypatch.setattr(passbook_grant, "host_allowed", lambda *args: {"allowed": True})
    original = dict(os.environ)
    answer = passbook_broker._handle({"op": "proxy", "workspace": "client", "app": "agent",
        "url": "https://example.test/", "headers": {"Authorization": "Bearer {{SAME_KEY}}"}}, root=tmp_path)
    assert answer["ok"] and answer["workspace"] == "client"
    assert received == [{"SAME_KEY": "synthetic-client"}]
    assert dict(os.environ) == original
    assert not passbook_broker._handle({"op": "request", "workspace": "../main", "keys": ["SAME_KEY"]}, root=tmp_path)["ok"]
