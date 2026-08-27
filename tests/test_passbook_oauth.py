# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""What a sign-in must guarantee.

The grant file is readable and holds no tokens; the tokens live in the store
like every other credential; a renewal actually renews; and a provider that
rotates its refresh token does not end up disconnecting a working grant.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
import urllib.parse
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _platform import assert_private  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))

import passbook  # noqa: E402
import passbook_oauth as oauth  # noqa: E402
from fake_provider import FakeProvider  # noqa: E402


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "hive"))
    for leaked in ("HIVE_ENV_FILES", "HIVE_WORKSPACE", "APP_SANDBOX_CONTAINER_ID"):
        monkeypatch.delenv(leaked, raising=False)
    passbook.ensure(app="test")
    return tmp_path / "hive"


def _grant(token_url: str, *, label: str = "work", **kw):
    oauth.add_grant("custom", label, client_id="client-abc",
                    authorize_url="https://example.test/authorize",
                    token_url=token_url, scope="offline_access", **kw)
    return oauth.find_grant(f"custom:{label}")


def _connect(grant, *, access="access-0", refresh="refresh-1", expires_at=None):
    keys = oauth.grant_keys(grant)
    values = {keys["access_token"]: access, keys["refresh_token"]: refresh}
    if expires_at is not None:
        values[keys["expires_at"]] = str(int(expires_at))
    passbook.set_values(values, overwrite=True)
    return keys


# ── describing a sign-in ───────────────────────────────────────────────────


def test_adding_a_sign_in_names_where_its_tokens_will_live(machine):
    made = oauth.add_grant("google", "work", client_id="client-abc")
    assert made["id"] == "google:work"
    assert made["keys"]["access_token"].endswith("_ACCESS_TOKEN")
    assert made["keys"]["refresh_token"].endswith("_REFRESH_TOKEN")
    # Describing is not connecting: nothing is in the store yet.
    assert passbook.key_names() == []


def test_the_grant_file_is_private_and_holds_no_tokens(machine):
    grant = _grant("https://example.test/token")
    _connect(grant, access="a-real-looking-token", refresh="a-real-refresh")
    text = oauth.grants_path().read_text(encoding="utf-8")

    assert_private(oauth.grants_path(), 0o600)
    assert "a-real-looking-token" not in text and "a-real-refresh" not in text
    # It should still be worth reading — that is why it is separate from the store.
    assert "example.test/token" in text and "client-abc" in text


def test_two_accounts_of_one_provider_coexist(machine):
    oauth.add_grant("google", "personal", client_id="c1")
    oauth.add_grant("google", "work", client_id="c2")
    ids = [g["id"] for g in oauth.grants()]
    assert ids == ["google:personal", "google:work"]
    prefixes = {g["key_prefix"] for g in oauth.grants()}
    assert len(prefixes) == 2, "two accounts must not share one set of store keys"


def test_a_duplicate_is_refused(machine):
    oauth.add_grant("google", "work", client_id="c1")
    with pytest.raises(oauth.GrantError, match="already exists"):
        oauth.add_grant("google", "work", client_id="c2")


def test_a_custom_provider_must_bring_its_own_urls(machine):
    with pytest.raises(oauth.GrantError, match="authorize-url"):
        oauth.add_grant("custom", "x", client_id="c1")


def test_a_sign_in_needs_a_client_id(machine):
    with pytest.raises(oauth.GrantError, match="client id"):
        oauth.add_grant("google", "x", client_id="")


def test_no_vendor_client_id_ships_in_the_provider_table():
    """Impersonating a vendor's own CLI client is a matter between the user and
    that vendor. The library must not decide it by baking one in."""
    for name, provider in oauth.PROVIDERS.items():
        assert "client_id" not in provider, name


# ── PKCE ───────────────────────────────────────────────────────────────────


def test_the_authorize_url_carries_a_correct_s256_challenge(machine):
    _grant("https://example.test/token")
    started = oauth.authorize_url("custom:work", redirect_uri="http://localhost:9999/auth/callback")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(started["url"]).query)

    assert query["code_challenge_method"] == ["S256"]
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(started["verifier"].encode("ascii")).digest()).decode().rstrip("=")
    assert query["code_challenge"] == [expected]
    assert query["state"] == [started["state"]]
    assert query["redirect_uri"] == ["http://localhost:9999/auth/callback"]


def test_each_login_gets_a_fresh_verifier_and_state(machine):
    _grant("https://example.test/token")
    a = oauth.authorize_url("custom:work", redirect_uri="http://localhost:1/cb")
    b = oauth.authorize_url("custom:work", redirect_uri="http://localhost:1/cb")
    assert a["verifier"] != b["verifier"] and a["state"] != b["state"]


# ── renewing, against a real server ────────────────────────────────────────


def test_a_refresh_actually_renews(machine):
    with FakeProvider(expires_in=3600) as provider:
        grant = _grant(provider.token_url)
        keys = _connect(grant, access="stale", expires_at=time.time() - 10)

        fresh = oauth.exchange_refresh(grant, "refresh-1")
        assert fresh[keys["access_token"]] == "access-1"
        assert int(fresh[keys["expires_at"]]) > time.time() + 3000
        assert provider.calls[-1]["grant_type"] == "refresh_token"
        assert provider.calls[-1]["client_id"] == "client-abc"


def test_a_rotating_provider_does_not_lose_the_grant(machine):
    """The provider issues a new refresh token and invalidates the old one. Two
    renewals in a row must both work, which they only do if the new one is
    stored."""
    with FakeProvider(rotate=True) as provider:
        grant = _grant(provider.token_url)
        keys = oauth.grant_keys(grant)

        first = oauth.exchange_refresh(grant, "refresh-1")
        assert first[keys["refresh_token"]] == "refresh-2"
        second = oauth.exchange_refresh(grant, first[keys["refresh_token"]])
        assert second[keys["access_token"]] == "access-2"


def test_a_non_rotating_provider_keeps_the_refresh_token(machine):
    """Providers that omit refresh_token on renewal must not have theirs blanked
    — writing an empty string would disconnect a working grant."""
    with FakeProvider(rotate=False) as provider:
        grant = _grant(provider.token_url)
        keys = oauth.grant_keys(grant)
        fresh = oauth.exchange_refresh(grant, "refresh-1")
        assert fresh[keys["refresh_token"]] == "refresh-1"


def test_a_provider_with_no_expiry_still_yields_a_token(machine):
    with FakeProvider(lifetime_field=False) as provider:
        grant = _grant(provider.token_url)
        keys = oauth.grant_keys(grant)
        fresh = oauth.exchange_refresh(grant, "refresh-1")
        assert fresh[keys["access_token"]] == "access-1"
        assert keys["expires_at"] not in fresh


def test_a_revoked_grant_says_so(machine):
    with FakeProvider(fail_with=400) as provider:
        grant = _grant(provider.token_url)
        with pytest.raises(oauth.RefreshFailed, match="revoked"):
            oauth.exchange_refresh(grant, "refresh-1")


def test_an_unreachable_provider_is_a_refresh_failure_not_a_crash(machine):
    grant = _grant("http://127.0.0.1:1/token")
    with pytest.raises(oauth.RefreshFailed, match="could not reach"):
        oauth.exchange_refresh(grant, "refresh-1")


def test_refreshing_without_a_refresh_token_is_refused(machine):
    grant = _grant("https://example.test/token")
    with pytest.raises(oauth.NotConnected):
        oauth.exchange_refresh(grant, "")


def test_completing_a_login_stores_the_tokens(machine):
    with FakeProvider(rotate=True) as provider:
        grant = _grant(provider.token_url)
        keys = oauth.grant_keys(grant)
        oauth.complete_login("custom:work", code="the-code", verifier="v",
                             redirect_uri="http://localhost:1/cb")

        stored = passbook.load()
        assert stored[keys["access_token"]] == "access-1"
        assert stored[keys["refresh_token"]] == "refresh-2"
        assert provider.calls[-1]["code"] == "the-code"
        assert provider.calls[-1]["code_verifier"] == "v"
        assert oauth.find_grant("custom:work")["connected_at"]


# ── knowing when to renew ──────────────────────────────────────────────────


def test_an_expired_token_needs_a_refresh(machine):
    grant = _grant("https://example.test/token")
    keys = _connect(grant, expires_at=time.time() - 1)
    assert oauth.needs_refresh(grant, passbook.load())


def test_a_token_about_to_expire_needs_one_too(machine):
    grant = _grant("https://example.test/token")
    _connect(grant, expires_at=time.time() + 30)
    assert oauth.needs_refresh(grant, passbook.load())


def test_a_healthy_token_is_left_alone(machine):
    grant = _grant("https://example.test/token")
    _connect(grant, expires_at=time.time() + 3600)
    assert not oauth.needs_refresh(grant, passbook.load())


def test_a_provider_that_never_says_when_is_not_refreshed_on_every_read(machine):
    """No recorded expiry must not mean "renew constantly" — that rate-limits an
    honest caller."""
    grant = _grant("https://example.test/token")
    _connect(grant, expires_at=None)
    assert not oauth.needs_refresh(grant, passbook.load())


def test_a_missing_access_token_always_needs_one(machine):
    grant = _grant("https://example.test/token")
    keys = oauth.grant_keys(grant)
    passbook.set_values({keys["refresh_token"]: "refresh-1"}, overwrite=True)
    assert oauth.needs_refresh(grant, passbook.load())


# ── status, without leaking ────────────────────────────────────────────────


@pytest.mark.parametrize("setup,expected", [
    (dict(access="", refresh="", expires_at=None), "disconnected"),
    (dict(access="a", refresh="", expires_at=None), "no-refresh"),
    (dict(access="a", refresh="r", expires_at=lambda: time.time() - 5), "expired"),
    (dict(access="a", refresh="r", expires_at=lambda: time.time() + 30), "expiring"),
    (dict(access="a", refresh="r", expires_at=lambda: time.time() + 3600), "connected"),
])
def test_status_names_the_state(machine, setup, expected):
    grant = _grant("https://example.test/token")
    keys = oauth.grant_keys(grant)
    values = {}
    if setup["access"]:
        values[keys["access_token"]] = setup["access"]
    if setup["refresh"]:
        values[keys["refresh_token"]] = setup["refresh"]
    if setup["expires_at"]:
        values[keys["expires_at"]] = str(int(setup["expires_at"]()))
    if values:
        passbook.set_values(values, overwrite=True)
    assert oauth.status(grant, passbook.load())["state"] == expected


def test_describe_never_carries_a_token(machine):
    grant = _grant("https://example.test/token")
    _connect(grant, access="the-secret-access", refresh="the-secret-refresh",
             expires_at=time.time() + 3600)
    blob = json.dumps(oauth.describe())
    assert "the-secret-access" not in blob and "the-secret-refresh" not in blob
    assert "custom:work" in blob


def test_grants_listing_never_carries_a_token(machine):
    grant = _grant("https://example.test/token")
    _connect(grant, access="the-secret-access")
    assert "the-secret-access" not in json.dumps(oauth.grants())


# ── forgetting ─────────────────────────────────────────────────────────────


def test_removing_a_sign_in_forgets_its_tokens(machine):
    grant = _grant("https://example.test/token")
    keys = _connect(grant)
    oauth.remove_grant("custom:work")

    assert oauth.grants() == []
    remaining = passbook.load()
    assert keys["access_token"] not in remaining
    assert keys["refresh_token"] not in remaining


def test_removing_can_keep_the_keys(machine):
    grant = _grant("https://example.test/token")
    keys = _connect(grant)
    oauth.remove_grant("custom:work", forget_tokens=False)
    assert passbook.load()[keys["access_token"]] == "access-0"
